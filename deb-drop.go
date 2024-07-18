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

const ArgMax = 1024 * 128

type Config struct {
	Host             string
	Port             int
	RequestCacheSize int
	TmpDir           string
	Token            []Token
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

func execAptly(args ...string) ([]string, error) {
	cmd := exec.Command(args[0], args[1:]...)
	buf, err := cmd.CombinedOutput()

	lines := strings.Split(strings.TrimSpace(string(buf)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(lines[i], "Unable to open database, sleeping") {
			lines = append(lines[:i], lines[i+1:]...)
		}
	}

	if err != nil {
		err = fmt.Errorf("aptly returned an error: %w\nOutput: %s", err, string(buf))
	}
	return lines, err
}

func listAptlyRepos() ([]string, error) {
	lines, err := execAptly("aptly", "repo", "list", "--raw")
	if err != nil {
		err = fmt.Errorf("repo list failed: %w", err)
	}
	return lines, err
}

type handler struct {
	config      Config
	mu          *sync.Mutex
	t           *time.Ticker              // batch timer
	publishQ    map[string][]chan error   // distributions to publish
	adds        int32                     // how many adds still in progress
	cleanupQ    map[string]map[string]int // repo packages to clean
	lastPublish time.Time
}

func newHandler(config Config) *handler {
	h := &handler{
		config:      config,
		mu:          new(sync.Mutex),
		t:           time.NewTicker(1000 * time.Millisecond),
		publishQ:    make(map[string][]chan error),
		adds:        0,
		cleanupQ:    make(map[string]map[string]int),
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

	if _, ok := h.publishQ[dist]; !ok {
		h.publishQ[dist] = make([]chan error, 0, 1)
	}

	c := make(chan error, 1)
	defer close(c)

	h.publishQ[dist] = append(h.publishQ[dist], c)
	h.mu.Unlock()
	logrus.Infof("Wait for publish of %s..", dist)

	return <-c
}

func (h *handler) publishBatch() bool {
	// check for new publish requests
	var n int
	var d string
	for dist, waiters := range h.publishQ {
		if len(waiters) > n {
			n = len(waiters)
			d = dist
		}
	}
	if n == 0 {
		return false
	}

	// publish distribution
	logrus.Infof("Publish %s..", d)
	err := h.publishDist(d)
	//var err error = nil
	if err == nil {
		logrus.Infof("Done publishing %s", d)
	}

	// notify waiters that it is done
	for _, waiter := range h.publishQ[d] {
		waiter <- err
	}

	delete(h.publishQ, d)
	return true
}

func (h *handler) popCleanupRepo() (string, string, int, bool) {
	for repo, pkgs := range h.cleanupQ {
		for pkg, keep := range pkgs {
			delete(h.cleanupQ[repo], pkg)
			return repo, pkg, keep, true
		}
	}
	return "", "", 0, false
}

func (h *handler) publishWorker() {
	idleTicks := 0

	for {
		<-h.t.C
		h.mu.Lock()
		adds := atomic.LoadInt32(&h.adds)

		// Skip if there are still changes in progress, but force a batch after some time..
		if adds > 0 && time.Now().Sub(h.lastPublish) < 15*time.Second {
			h.lastPublish = time.Now()
			h.mu.Unlock()
			idleTicks = 0
			continue
		}

		if adds > 0 {
			logrus.Infof("Still %d uploads in progress but no publish in %s. Force publish", adds, time.Now().Sub(h.lastPublish).String())
		}

		// Publish one batch
		published := h.publishBatch()
		h.lastPublish = time.Now()

		// Count idle ticks
		if adds == 0 && !published {
			idleTicks++
		} else {
			idleTicks = 0
		}

		// If nothing is happening we have time for a cleanup
		if idleTicks >= 10 {
			repo, pkg, keep, ok := h.popCleanupRepo()
			h.mu.Unlock()

			if ok {
				err := h.removeOldPackages(repo, pkg, keep)
				if err != nil {
					logrus.WithError(err).Errorf("Repo %s package cleanup of %s failed", repo, pkg)
				}
			}
		} else {
			h.mu.Unlock()
		}
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
		// Check that token matches repo
		if ok := h.validateToken(repo, token); !ok {
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
	packageName = strings.TrimRight(packageName, ".deb")

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

		// Queue cleanup job asynchronously
		defer func() {
			packageBasename := strings.Split(packageName, "_")[0]
			h.mu.Lock()
			for _, repo := range repositories {
				if _, ok := h.cleanupQ[repo]; !ok {
					h.cleanupQ[repo] = make(map[string]int)
				}
				h.cleanupQ[repo][packageBasename] = keepVersions
			}
			h.mu.Unlock()
		}()
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

	// List packages from aptly
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

	// Group by package name
	pkgsByName := make(map[string][]string)
	for _, match := range matches {
		pkgName := strings.Split(match, "_")[0]
		if _, ok := pkgsByName[pkgName]; !ok {
			pkgsByName[pkgName] = make([]string, 0, 1)
		}
		pkgsByName[pkgName] = append(pkgsByName[pkgName], match)
	}

	// Print versions out
	w.WriteHeader(http.StatusOK)
	for _, pkgs := range pkgsByName {
		versions, buckets := groupVersions(pkgs, n)
		for i, version := range versions {
			if i >= n {
				break
			}
			for _, pkg := range buckets[version] {
				_, _ = fmt.Fprintln(w, pkg+".deb") // TODO: remove .deb
			}
		}
	}
}

func (h *handler) validateToken(repo, token string) bool {
	for _, tokenCfg := range h.config.Token {
		for _, repoCfg := range tokenCfg.Repo {
			if repoCfg.Name == repo && tokenCfg.Value == token {
				return true
			}
		}
	}
	return false
}

func validatePackageName(name string, strict bool) error {
	r := new(regexp.Regexp)
	if strict {
		r = regexp.MustCompile("^(?P<package_name>[a-zA-Z0-9.+-]+)_((?P<epoch>[0-9]+):)?(?P<upstream_version>[a-zA-Z0-9.+-:~]+)(-(?P<debian_version>[a-zA-Z0-9.+~]+))?(_(?P<achritecture>amd64|i386|all))$")
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

func (h *handler) removeOldPackages(repo string, packageName string, keepVersions int) error {
	aptly, err := exec.LookPath("aptly")
	if err != nil {
		return fmt.Errorf("could not resolve aptly path: %w", err)
	}

	// Group packages into version buckets
	matches, err := h.listPackages(repo, packageName, true)
	if err != nil {
		return err
	}

	versions, buckets := groupVersions(matches, keepVersions)
	if keepVersions >= len(versions) {
		return nil
	}

	// Collect packages to be deleted
	pkgs := make([]string, 0)
	for _, version := range versions[keepVersions:] {
		pkgs = append(pkgs, buckets[version]...)
	}

	logrus.Infof("Versions: %v", versions)
	logrus.Infof("Keep versions: %v", versions[:keepVersions])

	// Batch all packages into chunks so that we don't exceed ARG_MAX in case of big cleanups
	nPrefix := len(aptly) + 1 + len("repo remove ") + len(repo) + 1 // Take base command into account
	batches := h.batchPkgs(pkgs, nPrefix)

	// Execute batch after batch
	for _, batch := range batches {
		logrus.Infof("Cleaning up %d packages from repo %s: %s", len(batch), repo, batch)
		if _, err := execAptly("aptly", "repo", "remove", repo, strings.Join(batch, "|")); err != nil {
			return fmt.Errorf("could not clean up %d packages from %s: %w", len(batch), repo, err)
		}
	}
	logrus.Infof("Cleaned up %d packages from repo %s", len(pkgs), repo)
	return nil
}

func groupVersions(packages []string, keepVersions int) ([]string, map[string][]string) {
	r := regexp.MustCompile("[0-9]+\\.[0-9]+\\.[0-9]+")
	versions := make([]string, 0)
	buckets := make(map[string][]string)
	for _, pkg := range packages {
		version := strings.Split(pkg, "_")[1]
		mainVersion := r.FindString(version)

		if len(versions) == 0 || versions[len(versions)-1] != mainVersion {
			versions = append(versions, mainVersion)
		}
		buckets[mainVersion] = append(buckets[mainVersion], pkg)
	}

	// Merge together many versions into bigger buckets
	r = regexp.MustCompile("[0-9]+\\.[0-9]+")
	shortVersions := make([]string, 0, len(versions))
	for _, version := range versions {
		for _, bucketPkg := range buckets[version] {
			shortVersion := r.FindString(strings.Split(bucketPkg, "_")[1])
			if len(shortVersions) == 0 || shortVersions[len(shortVersions)-1] != shortVersion {
				shortVersions = append(shortVersions, shortVersion)
			}
			buckets[shortVersion] = append(buckets[shortVersion], bucketPkg)
		}
	}

	// If the short versions don't deviate too much we can do those to keep more packages
	if len(shortVersions) > keepVersions && len(shortVersions)*2 > len(versions) {
		return shortVersions, buckets
	}

	// Split big versions up into smaller buckets
	r = regexp.MustCompile("[0-9]+\\.[0-9]+\\.[0-9]+[^0-9]+")
	longVersions := make([]string, 0, len(versions))
	for _, version := range versions {
		if len(buckets[version]) > keepVersions {
			for _, bucketPkg := range buckets[version] {
				longVersion := r.FindString(strings.Split(bucketPkg, "_")[1])
				if len(longVersions) == 0 || longVersions[len(longVersions)-1] != longVersion {
					longVersions = append(longVersions, longVersion)
				}
				buckets[longVersion] = append(buckets[longVersion], bucketPkg)
			}
		} else {
			longVersions = append(longVersions, version)
		}
	}

	// If we didn't produce too many long versions we can use those to remove some more packages
	if len(versions)*2 > len(longVersions) {
		return longVersions, buckets
	}

	return versions, buckets
}

func (h *handler) batchPkgs(pkgs []string, nPrefix int) [][]string {
	var batches [][]string
	var batchPkgs []string
	c := nPrefix
	for _, pkg := range pkgs {
		if c+len(pkg)+1 > ArgMax {
			batches = append(batches, batchPkgs)
			batchPkgs = []string{}
			c = nPrefix
		}

		c += len(pkg)
		if len(batchPkgs) > 0 {
			c++
		}
		batchPkgs = append(batchPkgs, pkg)
	}
	return append(batches, batchPkgs)
}

func (h *handler) addToRepos(content io.Reader, repos []string, packageName string) error {
	// Place the file in a randomly-named dir to prevent parallel uploads from
	// effecting each other
	tmpDir, tmperr := os.MkdirTemp(h.config.TmpDir, "deb_drop")
	if tmperr != nil {
		return tmperr
	}
	tmpFilePath := fmt.Sprintf("%s/%s.deb", tmpDir, packageName)
	err := writeStreamToTmpFile(content, tmpFilePath)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	// Check for package conflicts in target repos
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
	}

	dists := make(map[string]struct{})
	h.startAdd()
	h.mu.Lock()
	for _, repo := range repos {
		logrus.Infof("Add %s to %s", packageName, repo)
		if _, err := execAptly("aptly", "repo", "add", repo, tmpFilePath); err != nil {
			h.mu.Unlock()
			h.finishAdd()
			return fmt.Errorf("could not add package %s to %s: %w", tmpFilePath, repo, err)
		}
		logrus.Infof("Done adding %s to %s", packageName, repo)

		dist := strings.Split(repo, "-")[0]
		dists[dist] = struct{}{}
	}
	h.mu.Unlock()
	h.finishAdd()

	// Wait for publish of distributions
	for dist := range dists {
		err = h.waitPublished(dist)
		if err != nil {
			return err
		}
	}

	return nil
}

func (h *handler) publishDist(dist string) error {
	_, err := execAptly("aptly", "publish", "update", "--skip-contents", "--batch", "--passphrase-file", "/etc/aptly/passphrase", "--force-overwrite", dist, dist)
	if err != nil {
		err = fmt.Errorf("could not publish %s: %w", dist, err)
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

	lines, err := execAptly("aptly", "repo", "search", repo, q)
	if err != nil {
		if strings.Contains(lines[0], "ERROR: no results") {
			return []string{}, nil
		}
		return nil, fmt.Errorf("could not list packages in %s: %w", repo, err)
	}

	return lines, nil
}

func (h *handler) copyPackage(srcRepo string, dstRepos []string, packageName string) error {
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

	// Check for package conflicts in target repos
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
	}

	// Copy the package
	dists := make(map[string]struct{})
	h.startAdd()
	h.mu.Lock()
	for _, dstRepo := range dstRepos {
		logrus.Infof("Copy %s from %s to %s..", packageName, srcRepo, dstRepo)
		_, err = execAptly("aptly", "repo", "copy", srcRepo, dstRepo, packageName)
		if err != nil {
			h.mu.Unlock()
			h.finishAdd()
			return fmt.Errorf("could not copy package: %w", err)
		}
		logrus.Infof("Done copying %s from %s to %s", packageName, srcRepo, dstRepo)

		dist := strings.Split(dstRepo, "-")[0]
		dists[dist] = struct{}{}
	}
	h.mu.Unlock()
	h.finishAdd()

	// Wait for publish of distributions
	for dist := range dists {
		err := h.waitPublished(dist)
		if err != nil {
			return err
		}
	}

	return nil
}
