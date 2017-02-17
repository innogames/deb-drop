package main

import (
	"log"
	"os"
	"testing"
)

func TestCheckPackageName(t *testing.T) {
	lg := log.New(os.Stdout, "", log.Ldate|log.Lmicroseconds|log.Lshortfile)

	// Valid naming
	name := "test_1.3_amd64.deb"
	if validatePackageName(lg, name) != nil {
		t.Errorf("Check of package name forbid correct name: %s", name)
	}

	// Invalid naming
	name = "test_1.3_amd64.exe"
	if validatePackageName(lg, name) == nil {
		t.Errorf("Check of package name allowed wrong suffix: %s", name)
	}

	// Invalid naming
	name = "test_1.3_2_amd64.exe"
	if validatePackageName(lg, name) == nil {
		t.Errorf("Check of package name allowed wrong name schema: %s", name)
	}

	// Invalid naming
	name = "test_amd64.deb"
	if validatePackageName(lg, name) == nil {
		t.Errorf("Check of package name allowed wrong name schema: %s", name)
	}
}

func TestValidateToken(t *testing.T) {
	lg := log.New(os.Stdout, "", log.Ldate|log.Lmicroseconds|log.Lshortfile)

	token := Token{"validToken", "oleg", []Repo{{"oleg-stable-amd64"}}}
	config := Config{Token: []Token{token}}

	// Valid token, valid repo
	testToken := "validToken"
	testRepo := []string{"oleg-stable-amd64"}
	if validateToken(lg, &config, testToken, testRepo) != nil {
		t.Errorf("Valid token for valid repo was blocked: %s", testToken)
	}

	// Invalid token, valid repo
	testToken = "invalidToken"
	testRepo = []string{"oleg-stable-amd64"}
	if validateToken(lg, &config, testToken, testRepo) == nil {
		t.Errorf("Allowed invalid token: %s", testToken)
	}

	// Valid token, invalid repo
	testToken = "validToken"
	testRepo = []string{"forbidden-repo-amd64"}
	if validateToken(lg, &config, testToken, testRepo) == nil {
		t.Errorf("Allowed token to access forbidden repo: %s", testRepo)
	}

	// Invalid token, invalid repo
	testToken = "invalidToken"
	testRepo = []string{"forbidden-repo-amd64"}
	if validateToken(lg, &config, testToken, testRepo) == nil {
		t.Errorf("Allowed invalid token to access forbidden repo: %s", testRepo)
	}
}

func TestValidateRepos(t *testing.T) {
	lg := log.New(os.Stdout, "", log.Ldate|log.Lmicroseconds|log.Lshortfile)

	repoLocation := "/tmp"
	repo := repoLocation + "/" + "foo-stable-amd64"

	err := os.Mkdir(repo, os.ModePerm)
	if err != nil {
		t.Errorf("Unable to create test directory: %s", err)
	}
	defer os.RemoveAll(repo)

	// Valid format repos
	// One of repos does not exist
	testRepos := []string{"foo-stable-amd64"}
	if validateRepos(lg, repoLocation, testRepos) != nil {
		t.Errorf("Valid repo was not recognised in %s: %s", repoLocation, testRepos)
	}

	testRepos = []string{"foo", "bar"}
	if validateRepos(lg, repoLocation, testRepos) == nil {
		t.Errorf("Invalid repos passed the check in %s: %s", repoLocation, testRepos)
	}

	// Invalid format repos
	testRepos = []string{"foo", "bar"}
	if validateRepos(lg, repoLocation, testRepos) == nil {
		t.Errorf("Invalid repos passed the check in %s: %s", repoLocation, testRepos)
	}

	// One of repos does not exist
	testRepos = []string{"foo-stable-amd64", "bar-testing-amd64"}
	if validateRepos(lg, repoLocation, testRepos) == nil {
		t.Errorf("Invalid repos passed the check in %s: %s", repoLocation, testRepos)
	}
}

func TestAddToRepos(t *testing.T) {
	lg := log.New(os.Stdout, "", log.Ldate|log.Lmicroseconds|log.Lshortfile)

	// We need the file which is on every unix system
	testFile := "/etc/resolv.conf"
	tmpDir := "/tmp"
	config := Config{RepoLocation: tmpDir, TmpDir: tmpDir}
	repo := tmpDir + "/" + "foo-stable-amd64"

	err := os.Mkdir(repo, os.ModePerm)
	if err != nil {
		t.Errorf("Unable to create test directory, %s", err)
	}
	defer os.RemoveAll(repo)

	content, err := os.Open(testFile)
	if err != nil {
		t.Errorf("Unable to read test file %s", err)
	}
	defer content.Close()

	// Valid repos
	testRepo := []string{"foo-stable-amd64"}
	testPackage := "test_1.3_amd64.deb"
	if addToRepos(lg, &config, content, testRepo, testPackage) != nil {
		t.Errorf("Package is not saved in valid repository %s", repo)
	} else {
		// Compare if dst file is the same as origin
		expectedCopyPath := repo + "/" + testPackage
		statOrigin, err := os.Stat(testFile)
		if err != nil {
			t.Errorf("%s", err)
		}
		statCopy, err := os.Stat(expectedCopyPath)
		if err != nil {
			t.Errorf("%s", err)
		}
		if statOrigin.Size() != statCopy.Size() {
			t.Errorf("Original file %s and copy %s have different sizes", testFile, expectedCopyPath)
		}
	}

	// Invalid repo
	testRepo = []string{"bar-stable-amd64"}
	testPackage = "test_1.3_amd64.deb"
	if addToRepos(lg, &config, content, testRepo, testPackage) == nil {
		t.Errorf("Package is saved in invalid repository %s", repo)
	}
}
