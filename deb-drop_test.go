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
	config := Config{Token: []Token{
		{"validToken1", "oleg", []Repo{{"oleg-stable-amd64"}}},
		{"validToken2", "patrick", []Repo{{"patrick-stable-amd64"}}},
		{"validToken3", "patrick", []Repo{{"patrick-stable-amd64"}}},
	}}
	h := newHandler(config)

	// Valid token, valid repo
	testToken := "validToken1"
	testRepo := "oleg-stable-amd64"
	ok := h.validateToken(testRepo, testToken)
	if !ok {
		t.Errorf("Valid token for valid repo has failed")
	}

	// Invalid token, valid repo
	testToken = "invalidToken"
	testRepo = "oleg-stable-amd64"
	ok = h.validateToken(testRepo, testToken)
	if ok {
		t.Errorf("Invalid token for valid repo has failed")
	}

	// Valid token, invalid repo
	testToken = "validToken1"
	testRepo = "forbidden-repo-amd64"
	ok = h.validateToken(testRepo, testToken)
	if ok {
		t.Errorf("Allowed token to access forbidden repo")
	}

	// Multiple valid tokens for a repo
	testRepo = "patrick-stable-amd64"
	ok = h.validateToken(testRepo, "validToken1")
	if ok {
		t.Errorf("Allowed invalid token to access repo")
	}
	ok = h.validateToken(testRepo, "validToken2")
	if !ok {
		t.Errorf("Valid token for valid repo has failed")
	}
	ok = h.validateToken(testRepo, "validToken3")
	if !ok {
		t.Errorf("Valid token for valid repo has failed")
	}
}
