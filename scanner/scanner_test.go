// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	gitlib "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

var _ func(FilePath) (*[]Workflow, error) = AuditRepository
var _ func(string, GitRepository, *regexp.Regexp, string) *Inventory = ScanBranch
var _ func([]*GitRepository, *regexp.Regexp, bool) (*Inventory, error) = ScanRepos
var _ func(string, bool) (*Inventory, error) = Find
var _ func(Workflow, bool) error = ApplyFixesInFile
var _ = InventoryRecord{"", "", "", nil}
var _ = Inventory{nil}
var _ = PinnedRef{"", "", ""}
var _ = BarePinnedRef{"", ""}

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

func TestV1FindingAndWorkflowContracts(t *testing.T) {
	finding := Finding{1, 2, "description", "sha", "fix", "owner/repo", "v1", "owner/repo@v1"}
	workflow := Workflow{"ci", "ci.yml", []Finding{finding}}
	encoded, err := json.Marshal(workflow)
	if err != nil {
		t.Fatalf("marshal workflow: %v", err)
	}
	text := string(encoded)
	if !strings.Contains(text, `"FilePath":"ci.yml"`) || !strings.Contains(text, `"Line":1`) || strings.Contains(text, `"file":`) {
		t.Fatalf("legacy JSON keys changed: %s", encoded)
	}

	inventory := Inventory{[]*InventoryRecord{{"repo", "main", "ci.yml", []string{"owner/repo@v1"}}}}
	encoded, err = json.Marshal(inventory)
	if err != nil {
		t.Fatalf("marshal inventory: %v", err)
	}
	if got, want := string(encoded), `{"findings":[{"repository_name":"repo","branch_name":"main","actions_file":"ci.yml","matches":["owner/repo@v1"]}]}`; got != want {
		t.Fatalf("legacy inventory JSON = %s, want %s", got, want)
	}
}

func commitWorkflow(t *testing.T, repoPath string, repo *gitlib.Repository, content string, message string) {
	t.Helper()
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatalf("get worktree: %v", err)
	}
	workflowDir := filepath.Join(repoPath, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("create workflow directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
	if _, err := worktree.Add(".github/workflows/ci.yml"); err != nil {
		t.Fatalf("stage workflow: %v", err)
	}
	if _, err := worktree.Commit(message, &gitlib.CommitOptions{Author: &object.Signature{
		Name: "Test", Email: "test@example.com", When: time.Now(),
	}}); err != nil {
		t.Fatalf("commit workflow: %v", err)
	}
}

func TestScanRepositoriesReadsDistinctBranchTreesWithoutCheckout(t *testing.T) {
	repoPath := t.TempDir()
	repository, err := gitlib.PlainInit(repoPath, false)
	if err != nil {
		t.Fatalf("initialize repository: %v", err)
	}
	masterWorkflow := "jobs:\n  test:\n    steps:\n      - uses: owner/master@main\n"
	commitWorkflow(t, repoPath, repository, masterWorkflow, "master workflow")
	worktree, _ := repository.Worktree()

	if err := worktree.Checkout(&gitlib.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("feature"), Create: true}); err != nil {
		t.Fatalf("create feature branch: %v", err)
	}
	commitWorkflow(t, repoPath, repository, "jobs:\n  test:\n    steps:\n      - uses: owner/feature@release/2026\n", "feature workflow")

	if err := worktree.Checkout(&gitlib.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("broken"), Create: true}); err != nil {
		t.Fatalf("create broken branch: %v", err)
	}
	commitWorkflow(t, repoPath, repository, "jobs:\n  broken: [\n", "broken workflow")

	if err := worktree.Checkout(&gitlib.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("master")}); err != nil {
		t.Fatalf("restore master: %v", err)
	}
	beforeHead, err := repository.Head()
	if err != nil {
		t.Fatalf("read HEAD: %v", err)
	}

	scanRepo := &GitRepository{name: "repo", absPath: FilePath(repoPath)}
	result, err := ScanRepositories([]*GitRepository{scanRepo}, false)
	if err == nil || result.Status != ScanStatusIncomplete {
		t.Fatalf("result=%#v err=%v; want incomplete result from broken branch", result, err)
	}
	branchMatches := map[string]string{}
	for _, record := range result.Records {
		if len(record.Matches) == 1 {
			branchMatches[record.Branch] = record.Matches[0]
		}
	}
	if branchMatches["master"] != "owner/master@main" || branchMatches["feature"] != "owner/feature@release/2026" {
		t.Fatalf("branch findings = %#v", branchMatches)
	}
	afterHead, _ := repository.Head()
	if afterHead.Name() != beforeHead.Name() || afterHead.Hash() != beforeHead.Hash() {
		t.Fatalf("scan changed HEAD from %s to %s", beforeHead, afterHead)
	}
	workingContent, _ := os.ReadFile(filepath.Join(repoPath, ".github", "workflows", "ci.yml"))
	if string(workingContent) != masterWorkflow {
		t.Fatalf("scan changed working tree: %q", workingContent)
	}

	headResult, err := ScanRepositories([]*GitRepository{scanRepo}, true)
	if err != nil || headResult.Status != ScanStatusFindings || len(headResult.Records) != 1 || headResult.Records[0].Matches[0] != "owner/master@main" {
		t.Fatalf("head-only result=%#v err=%v", headResult, err)
	}
}

func TestScanRepositoriesIncludesRemoteTrackingBranches(t *testing.T) {
	repoPath := t.TempDir()
	repository, err := gitlib.PlainInit(repoPath, false)
	if err != nil {
		t.Fatalf("initialize repository: %v", err)
	}
	commitWorkflow(t, repoPath, repository, "jobs:\n  test:\n    steps:\n      - uses: owner/local@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", "local workflow")
	worktree, _ := repository.Worktree()

	sourceName := plumbing.NewBranchReferenceName("remote-source")
	if err := worktree.Checkout(&gitlib.CheckoutOptions{Branch: sourceName, Create: true}); err != nil {
		t.Fatalf("create remote source branch: %v", err)
	}
	commitWorkflow(t, repoPath, repository, "jobs:\n  test:\n    steps:\n      - uses: owner/remote@release/2026\n", "remote workflow")
	remoteCommit, err := repository.Head()
	if err != nil {
		t.Fatalf("read remote source commit: %v", err)
	}
	if err := worktree.Checkout(&gitlib.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("master")}); err != nil {
		t.Fatalf("restore master: %v", err)
	}
	if err := repository.Storer.RemoveReference(sourceName); err != nil {
		t.Fatalf("remove local source branch: %v", err)
	}

	remoteName := plumbing.ReferenceName("refs/remotes/origin/release/2026")
	if err := repository.Storer.SetReference(plumbing.NewHashReference(remoteName, remoteCommit.Hash())); err != nil {
		t.Fatalf("create remote-tracking branch: %v", err)
	}
	remoteHead := plumbing.ReferenceName("refs/remotes/origin/HEAD")
	if err := repository.Storer.SetReference(plumbing.NewSymbolicReference(remoteHead, remoteName)); err != nil {
		t.Fatalf("create symbolic remote HEAD: %v", err)
	}

	beforeHead, _ := repository.Head()
	result, err := ScanRepositories([]*GitRepository{{name: "repo", absPath: FilePath(repoPath)}}, false)
	if err != nil || result.Status != ScanStatusFindings {
		t.Fatalf("remote scan result=%#v err=%v", result, err)
	}
	if len(result.Records) != 1 || result.Records[0].Branch != "remote:origin/release/2026" || result.Records[0].Matches[0] != "owner/remote@release/2026" {
		t.Fatalf("remote findings = %#v", result.Records)
	}
	afterHead, _ := repository.Head()
	if afterHead.Name() != beforeHead.Name() || afterHead.Hash() != beforeHead.Hash() {
		t.Fatalf("remote scan changed HEAD from %s to %s", beforeHead, afterHead)
	}
}
