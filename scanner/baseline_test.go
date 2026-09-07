// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	gitlib "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func TestClassifyRepositoryFindingsHandlesRenamesAndModifiedReferences(t *testing.T) {
	repo, worktree := baselineTestRepository(t)
	oldPath := filepath.Join(repo, ".github", "workflows", "old.yml")
	writeBaselineWorkflow(t, oldPath, baselineWorkflow("owner/repo@main"))
	baseHash := baselineCommitAll(t, worktree, "base")

	newPath := filepath.Join(repo, ".github", "workflows", "renamed.yml")
	if err := os.Rename(oldPath, newPath); err != nil {
		t.Fatalf("rename workflow: %v", err)
	}
	baselineCommitAll(t, worktree, "rename")
	findings := scanBaselineTestFile(t, newPath)
	classifications, err := ClassifyRepositoryFindings(repo, baseHash.String(), findings)
	if err != nil {
		t.Fatalf("ClassifyRepositoryFindings returned error: %v", err)
	}
	if len(classifications) != 1 || classifications[0].New || classifications[0].Changed {
		t.Fatalf("pure rename classifications = %#v", classifications)
	}

	writeBaselineWorkflow(t, newPath, "jobs:\n  test:\n    steps:\n      - uses: owner/repo@main\n      - uses: owner/added@release\n")
	baselineCommitAll(t, worktree, "edit renamed workflow")
	findings = scanBaselineTestFile(t, newPath)
	classifications, err = ClassifyRepositoryFindings(repo, baseHash.String(), findings)
	if err != nil {
		t.Fatalf("ClassifyRepositoryFindings returned error: %v", err)
	}
	if len(classifications) != 2 || classifications[0].New || !classifications[1].New || !classifications[1].Changed {
		t.Fatalf("edited rename classifications = %#v", classifications)
	}
}

func TestClassifyRepositoryFindingsTreatsAddedDuplicateAsNew(t *testing.T) {
	repo, worktree := baselineTestRepository(t)
	workflowPath := filepath.Join(repo, ".github", "workflows", "ci.yml")
	writeBaselineWorkflow(t, workflowPath, baselineWorkflow("owner/repo@main"))
	baseHash := baselineCommitAll(t, worktree, "base")

	writeBaselineWorkflow(t, workflowPath, "jobs:\n  test:\n    steps:\n      - uses: owner/repo@main\n      - uses: owner/repo@main\n")
	baselineCommitAll(t, worktree, "duplicate")
	findings := scanBaselineTestFile(t, workflowPath)
	classifications, err := ClassifyRepositoryFindings(repo, baseHash.String(), findings)
	if err != nil {
		t.Fatalf("ClassifyRepositoryFindings returned error: %v", err)
	}
	if len(classifications) != 2 || classifications[0].New || !classifications[1].New || !classifications[1].Changed {
		t.Fatalf("duplicate classifications = %#v", classifications)
	}
}

func TestClassifyRepositoryFindingsMatchesUnchangedDuplicateBeforeAddedDuplicate(t *testing.T) {
	repo, worktree := baselineTestRepository(t)
	workflowPath := filepath.Join(repo, ".github", "workflows", "ci.yml")
	writeBaselineWorkflow(t, workflowPath, "jobs:\n  test:\n    steps:\n      - name: existing\n        uses: owner/repo@main\n")
	baseHash := baselineCommitAll(t, worktree, "base")

	writeBaselineWorkflow(t, workflowPath, "jobs:\n  test:\n    steps:\n      - name: added\n        uses: owner/repo@main\n      - name: existing\n        uses: owner/repo@main\n")
	baselineCommitAll(t, worktree, "prepend duplicate")
	findings := scanBaselineTestFile(t, workflowPath)
	classifications, err := ClassifyRepositoryFindings(repo, baseHash.String(), findings)
	if err != nil {
		t.Fatalf("ClassifyRepositoryFindings returned error: %v", err)
	}
	if len(classifications) != 2 || !classifications[0].New || !classifications[0].Changed || classifications[1].New {
		t.Fatalf("prepended duplicate classifications = %#v", classifications)
	}
}

func TestLoadRepositoryPolicyAtRevisionIgnoresWorkingTreePolicy(t *testing.T) {
	repo, worktree := baselineTestRepository(t)
	policyPath := filepath.Join(repo, defaultPolicyFileName)
	if err := os.WriteFile(policyPath, []byte("version: 1\nallow_cli_ignores: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	trustedHash := baselineCommitAll(t, worktree, "trusted policy")
	if err := os.WriteFile(policyPath, []byte("version: 1\nallow_cli_ignores: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	policy, source, err := LoadRepositoryPolicyAtRevision(repo, trustedHash.String())
	if err != nil {
		t.Fatalf("LoadRepositoryPolicyAtRevision returned error: %v", err)
	}
	if *policy.AllowCLIIgnores || source == "" {
		t.Fatalf("loaded untrusted policy: %#v source=%q", policy, source)
	}
}

func TestClassifyRepositoryFindingsRejectsDirtyAndMalformedBaselines(t *testing.T) {
	t.Run("dirty workflow", func(t *testing.T) {
		repo, worktree := baselineTestRepository(t)
		workflowPath := filepath.Join(repo, ".github", "workflows", "ci.yml")
		writeBaselineWorkflow(t, workflowPath, baselineWorkflow("owner/repo@main"))
		baseHash := baselineCommitAll(t, worktree, "base")
		writeBaselineWorkflow(t, workflowPath, baselineWorkflow("owner/repo@release"))

		_, err := ClassifyRepositoryFindings(repo, baseHash.String(), scanBaselineTestFile(t, workflowPath))
		if err == nil {
			t.Fatal("expected dirty workflow error")
		}
	})

	t.Run("malformed baseline", func(t *testing.T) {
		repo, worktree := baselineTestRepository(t)
		workflowPath := filepath.Join(repo, ".github", "workflows", "ci.yml")
		writeBaselineWorkflow(t, workflowPath, "jobs:\n  broken: [\n")
		baseHash := baselineCommitAll(t, worktree, "broken base")
		writeBaselineWorkflow(t, workflowPath, baselineWorkflow("owner/repo@main"))
		baselineCommitAll(t, worktree, "fix workflow")

		_, err := ClassifyRepositoryFindings(repo, baseHash.String(), scanBaselineTestFile(t, workflowPath))
		if err == nil {
			t.Fatal("expected malformed baseline error")
		}
	})
}

func baselineTestRepository(t *testing.T) (string, *gitlib.Worktree) {
	t.Helper()
	repoPath := t.TempDir()
	repository, err := gitlib.PlainInit(repoPath, false)
	if err != nil {
		t.Fatalf("initialize repository: %v", err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatalf("open worktree: %v", err)
	}
	return repoPath, worktree
}

func baselineWorkflow(reference string) string {
	return "jobs:\n  test:\n    steps:\n      - uses: " + reference + "\n"
}

func writeBaselineWorkflow(t *testing.T, fileName, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(fileName), 0o755); err != nil {
		t.Fatalf("create workflow directory: %v", err)
	}
	if err := os.WriteFile(fileName, []byte(content), 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
}

func baselineCommitAll(t *testing.T, worktree *gitlib.Worktree, message string) plumbing.Hash {
	t.Helper()
	if err := worktree.AddWithOptions(&gitlib.AddOptions{All: true}); err != nil {
		t.Fatalf("stage changes: %v", err)
	}
	signature := object.Signature{Name: "Scharf Test", Email: "test@example.com", When: time.Now()}
	hash, err := worktree.Commit(message, &gitlib.CommitOptions{Author: &signature})
	if err != nil {
		t.Fatalf("commit changes: %v", err)
	}
	return hash
}

func scanBaselineTestFile(t *testing.T, fileName string) []ReferenceFinding {
	t.Helper()
	content, err := os.ReadFile(fileName)
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	findings, err := ScanWorkflowReferences(content, fileName)
	if err != nil {
		t.Fatalf("scan workflow: %v", err)
	}
	return findings
}
