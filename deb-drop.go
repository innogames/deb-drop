package main

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/mcuadros/go-version"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"os/exec"
	"path/filepath"
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
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintln(w, "Please use HTTP POST method to send packages")
		return
	}

	/*
		Allow caching of up to <amount> in memory before buffering to disk
		In MB
	*/
	err := r.ParseMultipartForm(int64(config.RequestCacheSize * 1024))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		lg.Println(err)
		fmt.Fprintln(w, err)
		return
	}

	repos := strings.Split(r.FormValue("repos"), ",")
	if len(repos) < 1 {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "repo name not specified or too short")
		return
	}

	token := r.FormValue("token")
	err = validateToken(lg, config, token, repos)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, fmt.Sprint(err))
		return
	}

	// check if they exists after token granted access
	err = validateRepos(lg, config.RepoLocation, repos)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, fmt.Sprint(err))
		return
	}

	//Check if old packages should be removed
	keep_versions, err := strconv.Atoi(r.FormValue(" "))
	if err != nil || keep_versions < 1 {
		keep_versions = 5
	}

	// Check package name and save it locally
	content, header, err := r.FormFile("package")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, err)
		return
	}
	defer content.Close()

	packageName := header.Filename
	err = checkPackageName(lg, packageName)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, err)
		return
	}

	err = addToRepos(lg, config, content, repos, packageName)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, err)
		return
	}

	err = removeOldPackages(lg, config, repos, packageName, keep_versions)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, err)
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
					lg.Println("Attempt to get access to", repos, "with invalid token")
					return fmt.Errorf("%s", "Token is not allowed to use one or more of the specified repos")
				}
			}
			return nil
		}
	}

	if !foundToken {
		lg.Println("Attempt to get access with invalid token")
		return fmt.Errorf("%s", "Token is not allowed to use one or more of the specified repos")
	}

	return nil
}

func validateRepos(lg *log.Logger, repoLocation string, repos []string) error {
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

func checkPackageName(lg *log.Logger, name string) error {
	if !strings.HasSuffix(name, ".deb") {
		lg.Println("Somebody tried to upload invalid package name - missing .deb", name)
		return fmt.Errorf("%s", "Package name must end with .deb")
	}
	if len(strings.Split(name, "_")) != 3 {
		lg.Println("Somebody tried to upload invalid package name - does not contain 3 _", name)
		return fmt.Errorf("%s", "the package name does not look like a valid debian package name")
	}
	return nil
}

func writePostToTmpFile(lg *log.Logger, content io.Reader, tmpFilePath string) error {
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
	err := writePostToTmpFile(lg, content, tmpFilePath)
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

func removeOldPackages(lg *log.Logger, config *Config, repos []string, filename string, keep_versions int) error {
	package_name := strings.Split(filename, "_")[0]
	for _, repo := range repos {
		pattern := config.RepoLocation + "/" + repo + "/" + package_name + "_*"
		matches, _ := filepath.Glob(pattern)
		version.Sort(matches)
		if len(matches) > keep_versions {
			to_remove := len(matches) - keep_versions
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
