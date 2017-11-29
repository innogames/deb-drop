package main

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/mcuadros/go-version"
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

	http.HandleFunc("/", makeHandler(lg, &config, mainHandler))
	err = fcgi.Serve(l, nil)

	if err != nil {
		lg.Println("Error:", err)
	}
}

func makeHandler(lg *log.Logger, config *Config, fn func(http.ResponseWriter, *http.Request, *Config, *log.Logger)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(w, r, config, lg)
	}
}

func mainHandler(w http.ResponseWriter, r *http.Request, config *Config, lg *log.Logger) {

	if r.Method == "HEAD" {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Hello healthcheck")
		return
	}

	repos := strings.Split(r.FormValue("repos"), ",")
	err := validateRepos(lg, config.RepoLocation, repos)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		lg.Println(err)
		fmt.Fprintln(w, err)
		return
	}

	err = validateToken(lg, config, r.FormValue("token"), repos)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		lg.Println(err)
		fmt.Fprintln(w, err)
		return
	}

	//Check if old packages should be removed
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
			lg.Println(err)
			fmt.Fprintln(w, err)
			return
		}
		defer content.Close()
		packageName = header.Filename
	}

	if r.Method == "GET" {
		// Package name needs to be validated only when we are making changes
		err = validatePackageName(lg, packageName, false)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			lg.Println(err)
			fmt.Fprintln(w, err)
			return
		}

		if len(repos) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			lg.Println("You should pass exactly 1 repo")
			fmt.Fprintln(w, "You should pass exactly 1 repo")
			return
		}

		pattern := config.RepoLocation + "/" + repos[0] + "/" + packageName + "*"
		matches := getPackagesByPattern(pattern)
		if len(matches) == 0 {
			w.WriteHeader(http.StatusNotFound)
			lg.Println(pattern + " is not found")
			return
		} else {
			w.WriteHeader(http.StatusOK)
			for i := 0; i < keepVersions; i++ {
				element := len(matches) - 1 - i
				if element < 0 {
					break
				}
				fmt.Fprintln(w, path.Base(matches[element]))
			}
			return
		}
	} else if r.Method == "POST" {
		// Allow caching of up to <amount> in memory before buffering to disk. In MB
		err = r.ParseMultipartForm(int64(config.RequestCacheSize * 1024))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			lg.Println(err)
			fmt.Fprintln(w, err)
			return
		}

		// Package name needs to be validated only when we are making changes
		err = validatePackageName(lg, packageName, true)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			lg.Println(err)
			fmt.Fprintln(w, err)
			return
		}

		repositories := repos

		if r.FormValue("package") != "" {
			/*
				This is used when package is passed as name, which means it is copy action
				Because for UPLOAD it is multipart.FileHeader
			*/

			// Open original file
			content, err = os.Open(config.RepoLocation + "/" + repos[0] + "/" + packageName)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				lg.Println(err)
				fmt.Fprintf(w, "Can not find original package %s in %s", packageName, repos[0])
				return
			}
			defer content.Close()

			// We need at least 2 repos to copy package between
			if len(repos) < 2 {
				w.WriteHeader(http.StatusBadRequest)
				lg.Println("You should pass at least 2 repo")
				fmt.Fprintln(w, "You should pass at least 2 repo")
				return
			}
			repositories = repos[1:]
		}

		err = addToRepos(lg, config, content, repositories, packageName)
		if err != nil && r.FormValue("package") != "" {
			// If COPY was performed and at the destination repo we already have this package - return not modified
			w.WriteHeader(http.StatusNotModified)
			lg.Println(err)
			fmt.Fprintln(w, err)
			return
		} else if err != nil {
			// If this was UPLOAD
			w.WriteHeader(http.StatusConflict)
			lg.Println(err)
			fmt.Fprintln(w, err)
			return
		}

		err = removeOldPackages(lg, config, repos, packageName, keepVersions)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, err)
			return
		}
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintln(w, "Unsupported method "+r.Method)
		return
	}

	err = generateRepos(lg, config, repos)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, err)
		return
	}
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

		stat, err := os.Stat(repoLocation + "/" + repo)
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
		r = regexp.MustCompile("^([-0-9A-Za-z.]+_)+[-0-9A-Za-z]+.deb$")
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
	tmpFilePath := fmt.Sprintf("%s/%s", config.TmpDir, packageName)
	err := writeStreamToTmpFile(lg, content, tmpFilePath)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFilePath)

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
		err := cmd.Run()
		if err != nil {
			lg.Println("Could not generate metadata for", name, ":", err)
			return fmt.Errorf("Could not generate metadata for %s : %v", name, err)
		}
	}
	return nil
}
