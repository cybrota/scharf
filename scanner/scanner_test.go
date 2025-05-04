// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"fmt"
	"os"
	"regexp"
	"testing"
)

// --- Dummy implementations for Testing ---

// CheckIfError should be used to naively panics if an error is not nil.
func CheckIfError(err error) {
	if err == nil {
		return
	}

	fmt.Printf("\x1b[31;1m%s\x1b[0m\n", fmt.Sprintf("error: %s", err))
	os.Exit(1)
}

// --- Tests ---

// TestShouldIncludeDir verifies that directories/files meant to be ignored return false.
func TestShouldIncludeDir(t *testing.T) {
	tests := []struct {
		fileName string
		expected bool
	}{
		{".DS_Store", false},
		{".ruff_cache", false},
		{".ropeproject", false},
		{"normalDir", true},
		{"README.md", true},
	}
	for _, tc := range tests {
		got := shouldIncludeDir(tc.fileName)
		if got != tc.expected {
			t.Errorf("shouldIncludeDir(%q) = %v; expected %v", tc.fileName, got, tc.expected)
		}
	}
}

// TestGitHubWorkFlowScanner_ScanContent checks that ScanContent returns the correct matches.
func TestGitHubWorkFlowScanner_ScanContent(t *testing.T) {
	regex := regexp.MustCompile("test")
	content := []byte("this is a test string with test keyword")
	matches, err := ScanContent(content, regex)
	CheckIfError(err)

	expectedCount := 2
	if len(matches) != expectedCount {
		t.Errorf("expected %d matches, got %d", expectedCount, len(matches))
	}
}

// TestScanner_ScanRepos tests the ScanRepos method by wiring in fake VCS and repository implementations.
func TestScanner_ScanRepos(t *testing.T) {
	// TODO
}

// TestScanner_ScanReposDefaultBranch tests the ScanRepos but with passing --head-only flag value to true
func TestScanner_ScanReposDefaultBranch(t *testing.T) {
	// TODO
}
