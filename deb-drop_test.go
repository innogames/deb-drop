package main

import (
	"testing"
)

func TestCheckPackageName(t *testing.T) {
	// Valid naming
	name := "test_1.3_amd64"
	if validatePackageName(name, true) != nil {
		t.Errorf("Check of package name forbid correct name: %s", name)
	}

	// Valid naming
	name = "test-package_1.2.34-56_all"
	if validatePackageName(name, true) != nil {
		t.Errorf("Check of package name forbid correct name: %s", name)
	}

	// Invalid naming
	name = "test_1.3_2_amd64"
	if validatePackageName(name, true) == nil {
		t.Errorf("Check of package name allowed wrong name schema: %s", name)
	}

	// Invalid naming
	name = "test_amd64"
	if validatePackageName(name, true) == nil {
		t.Errorf("Check of package name allowed wrong name schema: %s", name)
	}
}

func TestValidateToken(t *testing.T) {
	token := Token{"validToken", "oleg", []Repo{{"oleg-stable-amd64"}}}
	config := Config{Token: []Token{token}}
	h := newHandler(config)

	// Valid token, valid repo
	testToken := "validToken"
	testRepo := "oleg-stable-amd64"
	repoToken, err := h.getRepoToken(testRepo)
	if err != nil {
		t.Errorf("Valid token for valid repo has failed: %v", err)
	}
	if repoToken != testToken {
		t.Errorf("Valid token for valid repo did not match")
	}

	// Invalid token, valid repo
	testToken = "invalidToken"
	testRepo = "oleg-stable-amd64"
	repoToken, err = h.getRepoToken(testRepo)
	if err != nil {
		t.Errorf("Invalid token for valid repo has failed: %v", err)
	}
	if repoToken == testToken {
		t.Errorf("Invalid token for valid repo did match")
	}

	// Valid token, invalid repo
	testToken = "validToken"
	testRepo = "forbidden-repo-amd64"
	repoToken, err = h.getRepoToken(testRepo)
	if err == nil && repoToken == testToken {
		t.Errorf("Allowed token to access forbidden repo: %s", testRepo)
	} else if err == nil {
		t.Errorf("Found non-existent repo")
	}
}
