package main

import (
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/mcuadros/go-version"
)

type Config struct {
	Host               string
	Port               int
	RequestCacheSize   int
	Logfile            string
	RepoLocation       string
	TmpDir             string
	RepoRebuildCommand string
	Token              []Token
}

type Token struct {
	Value string
	Owner string
	Repo  []Repo
}

type Repo struct {
	Name string
}

func main() {
	var config Config
	if _, err := toml.DecodeFile("/etc/deb-drop/deb-drop.toml", &config); err != nil {
		fmt.Println("Failed to parse config file", err.Error())
		os.Exit(1)
	}

	logfile, err := os.OpenFile(config.Logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0660)
	if err != nil {
		fmt.Println("Can not open logfile", config.Logfile, err)
		os.Exit(1)
	}
	lg := log.New(logfile, "", log.Ldate|log.Lmicroseconds|log.Lshortfile)

	// We need to validate config a bit before we run server
	for _, token := range config.Token {
		for _, repo := range token.Repo {
			err = validateRepos(lg, config.RepoLocation, []string{repo.Name})
			if err != nil {
				lg.Println("Found invalid repo. Next time will refuse to run", err)
			}
		}

	}

	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", config.Host, config.Port))
	if err != nil {
		lg.Println("Error:", err)
	}

	h := newHandler(&config, lg)
	http.HandleFunc("/", h.mainHandler)
	err = fcgi.Serve(l, nil)
	// err = http.Serve(l, nil)

	if err != nil {
		lg.Println("Error:", err)
	}
}

type handler struct {
	config      *Config
	lg          *log.Logger
	mu          *sync.Mutex
	t           *time.Ticker            // batch timer
	q           map[string][]chan error // distributions to publish
	adds        int32                   // how many adds still in progress
	lastPublish time.Time
}

func newHandler(config *Config, lg *log.Logger) *handler {
	h := &handler{
		config:      config,
		lg:          lg,
		mu:          new(sync.Mutex),
		t:           time.NewTicker(1000 * time.Millisecond),
		q:           make(map[string][]chan error),
		adds:        0,
		lastPublish: time.Now(),
	}

	go h.publishWorker()

	return h
}

func (h *handler) startAdd() {
	atomic.AddInt32(&h.adds, 1)
}

func (h *handler) finishAdd() {
	atomic.AddInt32(&h.adds, -1)
}

func (h *handler) waitPublished(dist string) error {
	h.mu.Lock()
	h.t.Reset(1000 * time.Millisecond)

	if _, ok := h.q[dist]; !ok {
		h.q[dist] = make([]chan error, 0, 1)
	}

	c := make(chan error, 1)
	defer close(c)

	h.q[dist] = append(h.q[dist], c)
	h.mu.Unlock()
	h.lg.Printf("wait for publish of %s..\n", dist)

	return <-c
}

func (h *handler) publishBatch() {
	// check for new publish requests
	var n int
	var d string
	for dist, waiters := range h.q {
		if len(waiters) > n {
			n = len(waiters)
			d = dist
		}
	}

	if n == 0 {
		return
	}

	// publish distribution
	err := h.publishDist(d)

	// notify waiters that it is done
	for _, waiter := range h.q[d] {
		waiter <- err
	}

	delete(h.q, d)
}

func (h *handler) publishWorker() {
	for {
		h.mu.Lock()
		<-h.t.C
		adds := atomic.LoadInt32(&h.adds)

		// skip if there are still changes in progress, but force a batch after some time..
		if adds > 0 && time.Now().Sub(h.lastPublish) < 15*time.Second {
			h.lastPublish = time.Now()
			h.mu.Unlock()
			continue
		}

		if adds > 0 {
			h.lg.Printf("still %d uploads in progress but no publish in %s. forcing\n", adds, time.Now().Sub(h.lastPublish).String())
		}

		h.publishBatch()
		h.lastPublish = time.Now()
		h.mu.Unlock()
	}
}

func (h *handler) mainHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "HEAD" {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Hello healthcheck")
		return
	}

	repos := strings.Split(r.FormValue("repos"), ",")
	err := validateRepos(h.lg, h.config.RepoLocation, repos)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, err)
		return
	}

	err = validateToken(h.lg, h.config, r.FormValue("token"), repos)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, err)
		return
	}

	// Check if old packages should be removed
	keepVersions, err := strconv.Atoi(r.FormValue("versions"))
	if err != nil || keepVersions < 1 {
		keepVersions = 5
	}

	var content multipart.File
	var packageName string

	// We can get package name from FORM or from parameter. It depends if there is an upload or copy/get
	if r.FormValue("package") != "" {
		packageName = r.FormValue("package")
	} else {
		// This is upload
		header := new(multipart.FileHeader)
		content, header, err = r.FormFile("package")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			h.lg.Println(err)
			fmt.Fprintln(w, err)
			return
		}
		defer content.Close()
		packageName = header.Filename
	}

	if r.Method == "GET" {
		// Package name needs to be validated only when we are making changes
		err := validatePackageName(h.lg, packageName, false)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, err)
			return
		}

		h.list(w, repos, packageName, keepVersions)
		return
	} else if r.Method == "POST" {
		// Allow caching of up to <amount> in memory before buffering to disk. In MB
		err = r.ParseMultipartForm(int64(h.config.RequestCacheSize * 1024))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			h.lg.Println(err)
			fmt.Fprintln(w, err)
			return
		}

		// Remove the multipart-* files in /tmp
		defer r.MultipartForm.RemoveAll()

		// Package name needs to be validated only when we are making changes
		err = validatePackageName(h.lg, packageName, true)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			h.lg.Println(err)
			fmt.Fprintln(w, err)
			return
		}

		repositories := repos

		// This is used when package is passed as name, which means it is copy action
		// Because for UPLOAD it is multipart.FileHeader
		if r.FormValue("package") != "" {
			// We need at least 2 repos to copy package between
			if len(repos) < 2 {
				w.WriteHeader(http.StatusBadRequest)
				h.lg.Println("You should pass at least 2 repo")
				fmt.Fprintln(w, "You should pass at least 2 repo")
				return
			}

			repositories = repos[1:]
			err = h.copyPackage(repos[0], repositories, packageName, h.config.RepoLocation)
			if err != nil {
				if err.Error() == "package version already exists" {
					w.WriteHeader(http.StatusConflict)
				} else {
					w.WriteHeader(http.StatusInternalServerError)
				}
				h.lg.Println(err)
				fmt.Fprintln(w, err)
				return
			}
			h.lg.Printf("done copying %s from %v\n", packageName, repos[0])
		} else {
			err = h.addToRepos(h.lg, h.config, content, repositories, packageName)
			if err != nil {
				if err.Error() == "package version already exists" {
					w.WriteHeader(http.StatusConflict)
				} else {
					w.WriteHeader(http.StatusInternalServerError)
				}
				h.lg.Println(err)
				fmt.Fprintln(w, err)
				return
			}
			h.lg.Printf("done adding %s to %v\n", packageName, repositories)
		}

		// err = removeOldPackages(lg, config, repos, packageName, keepVersions)
		// if err != nil {
		// 	w.WriteHeader(http.StatusInternalServerError)
		// 	fmt.Fprintln(w, err)
		// 	return
		// }
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintln(w, "Unsupported method "+r.Method)
		return
	}

	// err = generateRepos(h.lg, h.config, repos)
	// if err != nil {
	// 	w.WriteHeader(http.StatusInternalServerError)
	// 	fmt.Fprintln(w, err)
	// 	return
	// }
}

func (h *handler) list(w http.ResponseWriter, repos []string, packageName string, n int) error {
	if len(repos) != 1 {
		w.WriteHeader(http.StatusBadRequest)
		err := fmt.Errorf("you should pass exactly 1 repo")
		h.lg.Println(err)
		fmt.Fprintln(w, err)

		return err
	}

	matches := h.listPackages(repos[0], h.config.RepoLocation, packageName)
	if len(matches) == 0 {
		w.WriteHeader(http.StatusNotFound)
		err := fmt.Errorf("package %s not found", packageName)
		h.lg.Println(err)
		fmt.Fprintln(w, err)

		return err
	}

	w.WriteHeader(http.StatusOK)
	for i := 0; i < n; i++ {
		element := len(matches) - 1 - i
		if element < 0 {
			break
		}
		fmt.Fprintln(w, path.Base(matches[element]))
	}

	return nil
}

func validateToken(lg *log.Logger, config *Config, token string, repos []string) error {
	// Going over all tokens in configuration to find requested
	if token == "" {
		lg.Printf("Attempt to access %s without token", repos)
		return fmt.Errorf("%s", "You must specify token")
	}

	var foundToken bool
	for _, configToken := range config.Token {
		if configToken.Value == token {
			foundToken = true
			// Checking all requested repos to be allowed for this token
			for _, requestedRepo := range repos {
				var foundRepo bool
				for _, configRepo := range configToken.Repo {
					if configRepo.Name == requestedRepo {
						foundRepo = true
						break
					}
				}
				if !foundRepo {
					lg.Println("Use of valid token with not listed repo " + requestedRepo)
					return fmt.Errorf("%s", "Token is not allowed to use on one or more of the specified repos")
				}
			}
			return nil
		}
	}

	if !foundToken {
		lg.Printf("Attempt to access %s with invalid token\n", repos)
		return fmt.Errorf("%s", "Token is not allowed to use one or more of the specified repos")
	}

	return nil
}

func validateRepos(lg *log.Logger, repoLocation string, repos []string) error {
	if len(repos) == 0 {
		lg.Println("You should pass at least 1 repo")
		return fmt.Errorf("%s", "You should pass at least 1 repo")
	}

	for _, repo := range repos {
		parts := strings.Split(repo, "-")
		if len(parts) != 3 {
			lg.Println("Repo has invalid format")
			return fmt.Errorf("%s", "Repo has invalid format")
		}

		stat, err := os.Stat(repoLocation + "/" + parts[0] + "/dists/" + parts[0] + "/" + parts[1])
		if err != nil {
			lg.Println("Repository does not exist", err)
			return fmt.Errorf("%s", "Repository does not exist")
		}

		if !stat.IsDir() {
			lg.Println("Specified repository location exists but is not a directory")
			return fmt.Errorf("%s", "Specified repository location exists but is not a directory")
		}
	}
	return nil
}

func validatePackageName(lg *log.Logger, name string, strict bool) error {
	r := new(regexp.Regexp)
	if strict {
		r = regexp.MustCompile("^(?P<package_name>[a-zA-Z0-9.+-]+)_((?P<epoch>[0-9]+):)?(?P<upstream_version>[a-zA-Z0-9.+-:~]+)(-(?P<debian_version>[a-zA-Z0-9.+~]+))?(_(?P<achritecture>amd64|i386|all))\\.(?P<suffix>deb)$")
	} else {
		r = regexp.MustCompile("^([-0-9A-Za-z._]*)$")
	}

	if !r.MatchString(name) {
		lg.Println("Somebody tried to pass invalid package name", name)
		return fmt.Errorf("%s", "Invalid package name")
	}
	return nil
}

func writeStreamToTmpFile(lg *log.Logger, content io.Reader, tmpFilePath string) error {
	tmpDir := filepath.Dir(tmpFilePath)
	stat, err := os.Stat(tmpDir)
	if err != nil {
		lg.Printf("%s does not exist. Creating...\n", tmpDir)
		err = os.Mkdir(tmpDir, os.ModePerm)
		if err != nil {
			lg.Println(err)
			return err
		}
	} else if !stat.IsDir() {
		lg.Printf("%s exists, but it is not a directory\n", tmpDir)
		return fmt.Errorf("%s exists, but it is not a directory", tmpDir)
	}

	tmpFile, err := os.Create(tmpFilePath)
	if err != nil {
		lg.Println(err)
		return err
	}
	defer tmpFile.Close()

	_, err = io.Copy(tmpFile, content)
	if err != nil {
		lg.Printf("Can not save data from POST to %s\n", tmpFilePath)
		return err
	}
	return nil

}

func addToRepos(lg *log.Logger, config *Config, content io.Reader, repos []string, packageName string) error {
	// Place the file in a randomly-named dir to prevent parallel uploads from
	// effecting each other
	tmpDir, tmperr := os.MkdirTemp(config.TmpDir, "deb_drop")
	if tmperr != nil {
		return tmperr
	}
	tmpFilePath := fmt.Sprintf("%s/%s", tmpDir, packageName)
	err := writeStreamToTmpFile(lg, content, tmpFilePath)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	for _, repo := range repos {
		fileInRepo := config.RepoLocation + "/" + repo + "/" + packageName
		err := os.Link(tmpFilePath, fileInRepo)
		if err != nil {
			lg.Printf("Can not link package %s to %s", tmpFilePath, fileInRepo)
			return err
		}
	}
	return nil
}

func getPackagesByPattern(pattern string) []string {
	matches, _ := filepath.Glob(pattern)
	version.Sort(matches)
	return matches
}

func removeOldPackages(lg *log.Logger, config *Config, repos []string, fileName string, keepVersions int) error {
	packageName := strings.Split(fileName, "_")[0]
	for _, repo := range repos {
		matches := getPackagesByPattern(config.RepoLocation + "/" + repo + "/" + packageName + "_*")
		if len(matches) > keepVersions {
			to_remove := len(matches) - keepVersions
			for _, file := range matches[:to_remove] {
				lg.Println("Removing", file)
				err := os.Remove(file)
				if err != nil {
					lg.Println("Could remove package '", file, "' from Repo: '", err, "'")
					return fmt.Errorf("%s", "Cleanup of old packages has failed")
				}
			}
		}

	}
	return nil
}

func generateRepos(lg *log.Logger, config *Config, repos []string) error {
	// Rebuild repositories only once
	names := make(map[string]string)
	for _, repo := range repos {
		parts := strings.Split(repo, "-")
		names[parts[0]] = repo
	}

	for name, repo := range names {
		var cmd *exec.Cmd
		lg.Println("running", config.RepoRebuildCommand, repo)
		parts := strings.Fields(config.RepoRebuildCommand)
		head := parts[0]
		parts = parts[1:]
		parts = append(parts, repo)
		cmd = exec.Command(head, parts...)
		buf, err := cmd.CombinedOutput()
		if err != nil {
			lg.Println("Could not generate metadata for", name, ":", err)
			lg.Println(strings.TrimRight(string(buf), "\n"))
			return fmt.Errorf("Could not generate metadata for %s : %v", name, err)
		}
	}
	return nil
}

func (h *handler) addToRepos(lg *log.Logger, config *Config, content io.Reader, repos []string, packageName string) error {
	tmpFilePath := fmt.Sprintf("%s/%s", config.TmpDir, packageName)
	err := writeStreamToTmpFile(lg, content, tmpFilePath)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFilePath)

	dists := make(map[string]struct{})
	for _, repo := range repos {
		matches := h.listPackages(repo, config.RepoLocation, packageName)
		for _, match := range matches {
			if path.Base(match) == packageName {
				return fmt.Errorf("package version already exists")
			}
		}

		h.startAdd()
		h.mu.Lock()
		h.lg.Printf("add '%s' to '%s'\n", strings.TrimRight(packageName, ".deb"), repo)
		cmd := exec.Command("sudo", "-u", "aptly", "aptly", "repo", "add", repo, tmpFilePath)
		buf, err := cmd.CombinedOutput()
		h.mu.Unlock()
		h.finishAdd()
		if err != nil {
			return fmt.Errorf("could not add package %s to %s: %v\n%s", tmpFilePath, repo, err, string(buf))
		}
		h.lg.Printf("done adding '%s' to '%s'\n", strings.TrimRight(packageName, ".deb"), repo)

		dist := strings.Split(repo, "-")[0]
		dists[dist] = struct{}{}
	}

	for dist := range dists {
		err = h.waitPublished(dist)
		if err != nil {
			return err
		}
	}

	return nil
}

func (h *handler) publishDist(dist string) error {
	h.lg.Printf("publish %s..\n", dist)

	cmd := exec.Command("sudo", "-u", "aptly", "aptly", "publish", "update", "--skip-contents", "--batch", "--passphrase-file", "/etc/aptly/passphrase", "--force-overwrite", dist, dist)
	buf, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("could not publish %s: %v\n%s", dist, err, string(buf))
	}

	return err
}

func (h *handler) listPackages(repo, repoLocation, packageName string) []string {
	parts := strings.Split(repo, "-")
	pattern := repoLocation + "/" + parts[0] + "/" + parts[0] + "/pool/" + parts[1] + "/*/*/" + packageName + "*"

	return getPackagesByPattern(pattern)
}

func (h *handler) copyPackage(srcRepo string, dstRepos []string, packageName, repoLocation string) error {
	matches := h.listPackages(srcRepo, repoLocation, packageName)
	if len(matches) == 0 {
		return fmt.Errorf("could not find package in %s", srcRepo)
	}

	dists := make(map[string]struct{})
	for _, dstRepo := range dstRepos {
		matches := h.listPackages(dstRepo, repoLocation, packageName)
		for _, match := range matches {
			if path.Base(match) == packageName {
				return fmt.Errorf("package version already exists")
			}
		}

		h.startAdd()
		h.mu.Lock()
		h.lg.Printf("copy '%s' from '%s' to '%s'\n", strings.TrimRight(packageName, ".deb"), srcRepo, dstRepo)
		cmd := exec.Command("sudo", "-u", "aptly", "aptly", "repo", "copy", srcRepo, dstRepo, strings.TrimRight(packageName, ".deb"))
		buf, err := cmd.CombinedOutput()
		h.mu.Unlock()
		h.finishAdd()
		if err != nil {
			return fmt.Errorf("could not copy package: %w\n%s", err, string(buf))
		}
		h.lg.Printf("done copying '%s' from '%s' to '%s'\n", strings.TrimRight(packageName, ".deb"), srcRepo, dstRepo)

		dist := strings.Split(dstRepo, "-")[0]
		dists[dist] = struct{}{}
	}

	for dist := range dists {
		err := h.waitPublished(dist)
		if err != nil {
			return err
		}
	}

	return nil
}
