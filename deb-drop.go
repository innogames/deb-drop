package main

import (
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type Config struct {
	Host               string
	Port               int
	RequestCacheSize   int
	Logfile            string
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
	cfg, err := loadConfig()
	if err != nil {
		logrus.WithError(err).Fatal("Could not load config file")
	}
	logrus.Infof("Loaded config from %s", viper.ConfigFileUsed())

	// Collect actual and configured repos
	aptlyRepos, err := listAptlyRepos()
	if err != nil {
		logrus.WithError(err).Fatal()
	}

	aptlyRepoLookup := make(map[string]struct{}, len(aptlyRepos))
	for _, repo := range aptlyRepos {
		aptlyRepoLookup[repo] = struct{}{}
	}

	// Emit warnings for non-existent repositories
	for _, token := range cfg.Token {
		for _, repo := range token.Repo {
			if _, ok := aptlyRepoLookup[repo.Name]; !ok {
				logrus.Warnf("Repository %s does not exist", repo.Name)
			}
		}
	}

	// Start server
	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.Host, cfg.Port))
	if err != nil {
		logrus.WithError(err).Fatal()
	}

	h := newHandler(cfg)
	http.HandleFunc("/", h.mainHandler)

	err = fcgi.Serve(l, nil)
	//err = http.Serve(l, nil)
	if err != nil {
		logrus.WithError(err).Fatal()
	}
}

func loadConfig() (Config, error) {
	viper.SetConfigName("deb-drop")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/deb-drop")

	cfg := Config{}
	err := viper.ReadInConfig()
	if err != nil {
		return cfg, nil
	}

	err = viper.Unmarshal(&cfg)
	return cfg, err
}

func listAptlyRepos() ([]string, error) {
	cmd := exec.Command("aptly", "repo", "list", "--raw")
	buf, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("could not list aptly repos: %w", err)
	}

	return strings.Split(strings.TrimSpace(string(buf)), "\n"), nil
}

type handler struct {
	config      Config
	mu          *sync.Mutex
	t           *time.Ticker            // batch timer
	q           map[string][]chan error // distributions to publish
	adds        int32                   // how many adds still in progress
	lastPublish time.Time
}

func newHandler(config Config) *handler {
	h := &handler{
		config:      config,
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
	logrus.Infof("Wait for publish of %s..", dist)

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
	logrus.Infof("Publish %s..", d)
	err := h.publishDist(d)
	logrus.Infof("Done publishing %s", d)

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
			logrus.Infof("Still %d uploads in progress but no publish in %s. Force publish", adds, time.Now().Sub(h.lastPublish).String())
		}

		h.publishBatch()
		h.lastPublish = time.Now()
		h.mu.Unlock()
	}
}

func (h *handler) mainHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "HEAD" {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "OK")
		return
	}

	if r.FormValue("repos") == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintln(w, "No repos specified")
		return
	}

	// Authorize request
	token := r.FormValue("token")
	repos := strings.Split(r.FormValue("repos"), ",")

	if token == "" {
		logrus.Debugf("Attempt to access %s without token", repos)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintln(w, "No token specified")
		return
	}

	for _, repo := range repos {
		// Check that repos exist
		repoToken, err := h.getRepoToken(repo)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintln(w, err)
			return
		}

		// Check that token matches repo
		if repoToken != token {
			logrus.Debugf("Attempt to access %s with invalid token", repos)
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprintln(w, "Token is not allowed to use one or more of the specified repos")
			return
		}
	}

	// Check if old packages should be removed
	keepVersions, err := strconv.Atoi(r.FormValue("versions"))
	if err != nil || keepVersions < 1 {
		keepVersions = 5
	}

	var content multipart.File
	var packageName string

	// We can get package name from FORM or from parameter. It depends on whether there is an upload or copy/get
	if r.FormValue("package") != "" {
		packageName = r.FormValue("package")
	} else {
		// This is an upload
		header := new(multipart.FileHeader)
		content, header, err = r.FormFile("package")
		if err != nil {
			logrus.WithError(err).Error("Failed to access uploaded file")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer content.Close()
		packageName = header.Filename
	}

	if r.Method == "GET" {
		// Package name needs to be validated only when we are making changes
		err := validatePackageName(packageName, false)
		if err != nil {
			msg := "Package name validation failed"
			logrus.WithError(err).Debugf(msg)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, "%s: %s\n", msg, err.Error())
			return
		}

		h.list(w, repos, packageName, keepVersions)
		return
	} else if r.Method == "POST" {
		// Allow caching of up to <amount> in memory before buffering to disk. In MB
		err = r.ParseMultipartForm(int64(h.config.RequestCacheSize * 1024))
		if err != nil {
			msg := "Parsing multipart form failed"
			logrus.WithError(err).Error(msg)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintln(w, msg)
			return
		}

		// Remove the multipart-* files in /tmp
		defer r.MultipartForm.RemoveAll()

		// Package name needs to be validated only when we are making changes
		err = validatePackageName(packageName, true)
		if err != nil {
			msg := "Package name validation failed"
			logrus.WithError(err).Debug(msg)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, "%s: %s\n", msg, err.Error())
			return
		}

		repositories := repos

		// This is used when package is passed as name, which means it is copy action
		// Because for UPLOAD it is multipart.FileHeader
		if r.FormValue("package") != "" {
			// We need at least 2 repos to copy package between
			if len(repos) < 2 {
				msg := "Copy action requires at least 2 repos"
				logrus.Debug(msg)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = fmt.Fprintln(w, msg)
				return
			}

			repositories = repos[1:]
			err = h.copyPackage(repos[0], repositories, packageName)
			if err != nil {
				msg := "Copying package failed"
				if err.Error() == "package version already exists" {
					logrus.WithError(err).Debug(msg)
					w.WriteHeader(http.StatusConflict)
				} else {
					logrus.WithError(err).Error(msg)
					w.WriteHeader(http.StatusInternalServerError)
				}
				_, _ = fmt.Fprintf(w, "%s: %s\n", msg, err.Error())
				return
			}
		} else {
			err = h.addToRepos(content, repositories, packageName)
			if err != nil {
				msg := "Adding package failed"
				if err.Error() == "package version already exists" {
					logrus.WithError(err).Debug(msg)
					w.WriteHeader(http.StatusConflict)
				} else {
					logrus.WithError(err).Error(msg)
					w.WriteHeader(http.StatusInternalServerError)
				}
				_, _ = fmt.Fprintln(w, msg)
				return
			}
		}

		// err = removeOldPackages(lg, config, repos, packageName, keepVersions)
		// if err != nil {
		// 	w.WriteHeader(http.StatusInternalServerError)
		// 	fmt.Fprintln(w, err)
		// 	return
		// }
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

func (h *handler) list(w http.ResponseWriter, repos []string, packageName string, n int) {
	if len(repos) != 1 {
		msg := "List action was not called with exactly 1 repo"
		logrus.Debug(msg)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintln(w, msg)
		return
	}

	matches, err := h.listPackages(repos[0], packageName, false)
	if err != nil {
		msg := "Repository package listing failed"
		logrus.WithError(err).Error(msg)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintln(w, msg)
		return
	}

	if len(matches) == 0 {
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, "Package %s not found\n", packageName)
		return
	}

	w.WriteHeader(http.StatusOK)
	for i, match := range matches {
		if i >= n {
			break
		}
		_, _ = fmt.Fprintln(w, match)
	}
}

func (h *handler) getRepoToken(repo string) (string, error) {
	for _, tokenCfg := range h.config.Token {
		for _, repoCfg := range tokenCfg.Repo {
			if repoCfg.Name == repo {
				return tokenCfg.Value, nil
			}
		}
	}
	return "", fmt.Errorf("repo %s not found", repo)
}

func validatePackageName(name string, strict bool) error {
	r := new(regexp.Regexp)
	if strict {
		r = regexp.MustCompile("^(?P<package_name>[a-zA-Z0-9.+-]+)_((?P<epoch>[0-9]+):)?(?P<upstream_version>[a-zA-Z0-9.+-:~]+)(-(?P<debian_version>[a-zA-Z0-9.+~]+))?(_(?P<achritecture>amd64|i386|all))\\.(?P<suffix>deb)$")
	} else {
		r = regexp.MustCompile("^([-0-9A-Za-z._]*)$")
	}

	if !r.MatchString(name) {
		return fmt.Errorf("invalid package name: %s", name)
	}
	return nil
}

func writeStreamToTmpFile(content io.Reader, tmpFilePath string) error {
	tmpDir := filepath.Dir(tmpFilePath)
	stat, err := os.Stat(tmpDir)
	if err != nil {
		if os.IsNotExist(err) {
			logrus.Infof("Tmp directory %s does not exist. Creating..", tmpDir)
			err = os.Mkdir(tmpDir, os.ModePerm)
		} else if !stat.IsDir() {
			err = fmt.Errorf("tmp location %s exists, but it is not a directory", tmpDir)
		}
	}
	if err != nil {
		return err
	}

	tmpFile, err := os.Create(tmpFilePath)
	if err != nil {
		return err
	}
	defer tmpFile.Close()

	_, err = io.Copy(tmpFile, content)
	return err
}

//func removeOldPackages(lg *log.Logger, config *Config, repos []string, fileName string, keepVersions int) error {
//	packageName := strings.Split(fileName, "_")[0]
//	for _, repo := range repos {
//		matches := getPackagesByPattern(config.RepoLocation + "/" + repo + "/" + packageName + "_*")
//		if len(matches) > keepVersions {
//			to_remove := len(matches) - keepVersions
//			for _, file := range matches[:to_remove] {
//				lg.Println("Removing", file)
//				err := os.Remove(file)
//				if err != nil {
//					lg.Println("Could remove package '", file, "' from Repo: '", err, "'")
//					return fmt.Errorf("%s", "Cleanup of old packages has failed")
//				}
//			}
//		}
//
//	}
//	return nil
//}

func (h *handler) addToRepos(content io.Reader, repos []string, packageFile string) error {
	tmpFilePath := fmt.Sprintf("%s/%s", h.config.TmpDir, packageFile)
	err := writeStreamToTmpFile(content, tmpFilePath)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFilePath)

	packageName := strings.TrimRight(packageFile, ".deb")
	dists := make(map[string]struct{})
	for _, repo := range repos {
		matches, err := h.listPackages(repo, packageName, true)
		if err != nil {
			msg := "Repository package listing failed"
			logrus.WithError(err).Error(msg)
			return err
		}

		if len(matches) > 0 {
			return fmt.Errorf("package version already exists")
		}

		h.startAdd()
		h.mu.Lock()
		logrus.Infof("Add %s to %s", packageName, repo)
		cmd := exec.Command("aptly", "repo", "add", repo, tmpFilePath)
		buf, err := cmd.CombinedOutput()
		h.mu.Unlock()
		h.finishAdd()
		if err != nil {
			return fmt.Errorf("could not add package %s to %s: %w\n%s", tmpFilePath, repo, err, strings.TrimSpace(string(buf)))
		}
		logrus.Infof("Done adding %s to %s", packageName, repo)

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
	cmd := exec.Command("aptly", "publish", "update", "--skip-contents", "--batch", "--passphrase-file", "/etc/aptly/passphrase", "--force-overwrite", dist, dist)
	//cmd := exec.Command("aptly", "publish", "update", "--skip-contents", "--batch", "--skip-signing", "--force-overwrite", dist, dist)
	buf, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("could not publish %s: %w\n%s", dist, err, strings.TrimSpace(string(buf)))
	}

	return err
}

func (h *handler) listPackages(repo, packageName string, full bool) ([]string, error) {
	var q string
	if full {
		q = packageName
	} else {
		q = fmt.Sprintf("Name (%% %s*)", packageName)
	}

	cmd := exec.Command("aptly", "repo", "search", repo, q)
	buf, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(buf))
	if err != nil {
		if strings.Contains(out, "ERROR: no results") {
			return []string{}, nil
		}
		return nil, fmt.Errorf("could not list packages in %s: %w\n%s", repo, err, out)
	}

	matches := strings.Split(out, "\n")
	for i := range matches {
		matches[i] += ".deb" // TODO: legacy
	}
	return matches, nil
}

func (h *handler) copyPackage(srcRepo string, dstRepos []string, packageFile string) error {
	packageName := strings.TrimRight(packageFile, ".deb")
	matches, err := h.listPackages(srcRepo, packageName, true)
	if err != nil {
		msg := "Repository package listing failed"
		logrus.WithError(err).Error(msg)
		return err
	}

	if len(matches) == 0 {
		return fmt.Errorf("could not find package %s in %s", packageName, srcRepo)
	} else if len(matches) > 1 {
		return fmt.Errorf("found multiple packages for %s in %s", packageName, srcRepo)
	}

	dists := make(map[string]struct{})
	for _, dstRepo := range dstRepos {
		matches, err := h.listPackages(dstRepo, packageName, true)
		if err != nil {
			msg := "Repository package listing failed"
			logrus.WithError(err).Error(msg)
			return err
		}

		if len(matches) > 0 {
			return fmt.Errorf("package version already exists")
		}

		h.startAdd()
		h.mu.Lock()
		logrus.Infof("Copy %s from %s to %s..", strings.TrimRight(packageName, ".deb"), srcRepo, dstRepo)
		cmd := exec.Command("aptly", "repo", "copy", srcRepo, dstRepo, strings.TrimRight(packageName, ".deb"))
		buf, err := cmd.CombinedOutput()
		h.mu.Unlock()
		h.finishAdd()
		if err != nil {
			return fmt.Errorf("could not copy package: %w\n%s", err, strings.TrimSpace(string(buf)))
		}
		logrus.Infof("Done copying %s from %s to %s", strings.TrimRight(packageName, ".deb"), srcRepo, dstRepo)

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
