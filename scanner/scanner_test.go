// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// --- Dummy implementations for Testing ---

// fakeVCS implements the VCS interface for testing.
type fakeVCS struct {
	repos        []Repository
	listReposErr error
}

// CheckIfError should be used to naively panics if an error is not nil.
func CheckIfError(err error) {
	if err == nil {
		return
	}

	fmt.Printf("\x1b[31;1m%s\x1b[0m\n", fmt.Sprintf("error: %s", err))
	os.Exit(1)
}

func (f fakeVCS) ListRepositories(root string) ([]Repository, error) {
	if f.listReposErr != nil {
		return nil, f.listReposErr
	}
	return f.repos, nil
}

// fakeRepository implements the Repository interface.
type fakeRepository struct {
	name            string
	branches        []string
	files           []string          // file names to be returned by ListFiles
	fileContents    map[string][]byte // mapping full file path -> content
	listBranchesErr error
	listFilesErr    error
	readFileErrs    map[string]error
}

func (f fakeRepository) Name() string {
	return f.name
}

func (f fakeRepository) Location() string {
	// For testing, just return a dummy location.
	return filepath.Join("dummy", f.name)
}

func (f fakeRepository) ListBranches() ([]string, error) {
	if f.listBranchesErr != nil {
		return nil, f.listBranchesErr
	}
	return f.branches, nil
}

func (f fakeRepository) ListFiles(loc string) ([]string, error) {
	if f.listFilesErr != nil {
		return nil, f.listFilesErr
	}
	return f.files, nil
}

func (f fakeRepository) ReadFile(filePath string) ([]byte, error) {
	if err, ok := f.readFileErrs[filePath]; ok {
		return nil, err
	}
	if content, ok := f.fileContents[filePath]; ok {
		return content, nil
	}
	return nil, os.ErrNotExist
}

func (f fakeRepository) SwitchBranch(branchName string) error {
	return nil
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
	scanner := GitHubWorkFlowScanner{}
	regex := regexp.MustCompile("test")
	content := []byte("this is a test string with test keyword")
	matches, err := scanner.ScanContent(content, regex)
	CheckIfError(err)

	expectedCount := 2
	if len(matches) != expectedCount {
		t.Errorf("expected %d matches, got %d", expectedCount, len(matches))
	}
}

// TestScanner_ScanRepos tests the ScanRepos method by wiring in fake VCS and repository implementations.
func TestScanner_ScanRepos(t *testing.T) {
	// Use a dummy root; the function will convert it to an absolute path.
	root := "dummyRoot"
	absRoot, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("failed to get absolute path: %v", err)
	}
	dirPath := ".github/workflows"
	// Prepare file names.
	file1 := "file1.txt"
	file2 := "file2.txt"
	// Construct the expected full file paths.
	file1Path := filepath.Join(absRoot, "repo1", dirPath, file1)
	file2Path := filepath.Join(absRoot, "repo1", dirPath, file2)

	// Fake repository "repo1" returns valid branches and files.
	repo1 := fakeRepository{
		name:     "repo1",
		branches: []string{"main", "dev"},
		files:    []string{file1, file2},
		fileContents: map[string][]byte{
			file1Path: []byte("this file contains a match"),
			file2Path: []byte("no relevant content"),
		},
		readFileErrs: make(map[string]error),
	}

	// Fake repository "repoError" simulates an error when listing branches.
	repoError := fakeRepository{
		name:            "repoError",
		listBranchesErr: errors.New("failed to list branches"),
	}

	// The fake VCS returns both repositories.
	fakeVcs := fakeVCS{
		repos: []Repository{repo1, repoError},
	}

	// Use the real GitHubWorkFlowScanner as the FileScanner.
	fileScanner := GitHubWorkFlowScanner{}

	// Construct the Scanner with the fake VCS and FileScanner.
	scanner := Scanner{
		VCS:         fakeVcs,
		FileScanner: fileScanner,
	}

	// Use a regex that matches the word "match".
	regex := regexp.MustCompile("match")

	inventory, err := scanner.ScanRepos(root, regex, false)
	if err != nil {
		t.Fatalf("ScanRepos returned error: %v", err)
	}

	// Expect two records from repo1 (one for each branch) for file1.txt only,
	// because only file1.txt contains the string "match".
	expectedRecords := 2
	if len(inventory.Records) != expectedRecords {
		t.Errorf("expected %d inventory records, got %d", expectedRecords, len(inventory.Records))
	}

	// Verify each record.
	for _, record := range inventory.Records {
		if record.Repository != "repo1" {
			t.Errorf("expected repository name 'repo1', got %q", record.Repository)
		}
		if record.FilePath != file1Path {
			t.Errorf("expected file path %q, got %q", file1Path, record.FilePath)
		}
		if len(record.Matches) == 0 {
			t.Errorf("expected at least one match in record for branch %q", record.Branch)
		}
	}
}

// TestScanner_ScanReposDefaultBranch tests the ScanRepos but with passing --head-only flag value to true
func TestScanner_ScanReposDefaultBranch(t *testing.T) {
	// Use a dummy root; the function will convert it to an absolute path.
	root := "dummyRoot"
	absRoot, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("failed to get absolute path: %v", err)
	}
	dirPath := ".github/workflows"
	// Prepare file names.
	file1 := "file1.txt"
	file2 := "file2.txt"
	// Construct the expected full file paths.
	file1Path := filepath.Join(absRoot, "repo1", dirPath, file1)
	file2Path := filepath.Join(absRoot, "repo1", dirPath, file2)

	// Fake repository "repo1" returns valid branches and files.
	repo1 := fakeRepository{
		name:     "repo1",
		branches: []string{"main", "dev"},
		files:    []string{file1, file2},
		fileContents: map[string][]byte{
			file1Path: []byte("this file contains a match"),
			file2Path: []byte("no relevant content"),
		},
		readFileErrs: make(map[string]error),
	}

	// Fake repository "repoError" simulates an error when listing branches.
	repoError := fakeRepository{
		name:            "repoError",
		listBranchesErr: errors.New("failed to list branches"),
	}

	// The fake VCS returns both repositories.
	fakeVcs := fakeVCS{
		repos: []Repository{repo1, repoError},
	}

	// Use the real GitHubWorkFlowScanner as the FileScanner.
	fileScanner := GitHubWorkFlowScanner{}

	// Construct the Scanner with the fake VCS and FileScanner.
	scanner := Scanner{
		VCS:         fakeVcs,
		FileScanner: fileScanner,
	}

	// Use a regex that matches the word "match".
	regex := regexp.MustCompile("match")

	inventory, err := scanner.ScanRepos(root, regex, true)
	if err != nil {
		t.Fatalf("ScanRepos returned error: %v", err)
	}

	// Expect two records from repo1 (one for each branch) for file1.txt only,
	// because only file1.txt contains the string "match".
	expectedRecords := 1
	if len(inventory.Records) != expectedRecords {
		t.Errorf("expected %d inventory records, got %d", expectedRecords, len(inventory.Records))
	}

	// Verify each record.
	for _, record := range inventory.Records {
		if record.Repository != "repo1" {
			t.Errorf("expected repository name 'repo1', got %q", record.Repository)
		}
		if record.FilePath != file1Path {
			t.Errorf("expected file path %q, got %q", file1Path, record.FilePath)
		}
		if len(record.Matches) == 0 {
			t.Errorf("expected at least one match in record for branch %q", record.Branch)
		}
	}
}
