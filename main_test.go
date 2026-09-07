// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sc "github.com/cybrota/scharf/scanner"
	gitlib "github.com/go-git/go-git/v5"
)

func executeRoot(args ...string) (string, string, error) {
	cmd := newRootCmd()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SetArgs(args)

	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestUpgradeSHAWithoutFromVersionShowsUsage(t *testing.T) {
	_, stderr, err := executeRoot("upgrade", "actions/checkout@0123456789012345678901234567890123456789")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if !strings.Contains(stderr, "please provide --from-version") {
		t.Fatalf("stderr = %q; want missing --from-version hint", stderr)
	}

	if !strings.Contains(stderr, "Usage:") {
		t.Fatalf("stderr = %q; want command usage on validation errors", stderr)
	}
}

func TestVersionInfoExposedOnCLI(t *testing.T) {
	var expected string
	for _, args := range [][]string{{"--version"}, {"version"}, {"-V"}} {
		stdout, stderr, err := executeRoot(args...)
		if err != nil {
			t.Fatalf("unexpected error for %v: %v (stderr: %s)", args, err, stderr)
		}

		if !strings.Contains(stdout, "commit") || !strings.Contains(stdout, "built") {
			t.Fatalf("stdout = %q; want version details including commit and build metadata", stdout)
		}
		if !strings.HasPrefix(stdout, "version: ") {
			t.Fatalf("stdout = %q; want direct version output without Cobra prefix", stdout)
		}
		if expected == "" {
			expected = stdout
			continue
		}
		if stdout != expected {
			t.Fatalf("stdout for %v = %q; want %q", args, stdout, expected)
		}
	}
}

func TestAuditCLIReportsCompleteCleanStatus(t *testing.T) {
	repo := t.TempDir()
	if _, err := gitlib.PlainInit(repo, false); err != nil {
		t.Fatalf("initialize repository: %v", err)
	}

	stdout, stderr, err := executeRoot("audit", repo)
	if err != nil {
		t.Fatalf("audit returned error: %v (stderr: %s)", err, stderr)
	}
	if !strings.Contains(stdout, "Scan status: complete-clean") || !strings.Contains(stdout, "No mutable references found") {
		t.Fatalf("stdout = %q; want explicit clean status", stdout)
	}
}

func TestAuditCLIReportsIncompleteAndFails(t *testing.T) {
	repo := t.TempDir()
	if _, err := gitlib.PlainInit(repo, false); err != nil {
		t.Fatalf("initialize repository: %v", err)
	}
	workflowDir := filepath.Join(repo, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("create workflow directory: %v", err)
	}
	broken := filepath.Join(workflowDir, "broken.yml")
	if err := os.WriteFile(broken, []byte("jobs:\n  build: [\n"), 0o644); err != nil {
		t.Fatalf("write malformed workflow: %v", err)
	}

	stdout, stderr, err := executeRoot("audit", repo)
	if err == nil {
		t.Fatal("expected incomplete audit to return an error")
	}
	if !strings.Contains(stdout, "Scan status: incomplete") {
		t.Fatalf("stdout = %q; want explicit incomplete status", stdout)
	}
	if !strings.Contains(stderr, broken) {
		t.Fatalf("stderr = %q; want malformed file context", stderr)
	}
}

func TestAuditCLIFindingsRespectRaiseError(t *testing.T) {
	originalAudit := auditRepository
	auditRepository = func(sc.FilePath) (*sc.AuditResult, error) {
		return &sc.AuditResult{
			Status:   sc.ScanStatusFindings,
			Complete: true,
			Workflows: []sc.Workflow{{
				Name: "ci.yml", FilePath: "ci.yml", Issues: []sc.Finding{{Description: "mutable reference"}},
			}},
		}, nil
	}
	t.Cleanup(func() { auditRepository = originalAudit })

	stdout, stderr, err := executeRoot("audit", ".")
	if err != nil {
		t.Fatalf("audit without --raise-error failed: %v (stderr: %s)", err, stderr)
	}
	if !strings.Contains(stdout, "complete-with-findings") || !strings.Contains(stdout, "mutable reference") {
		t.Fatalf("stdout = %q; want findings report", stdout)
	}

	stdout, _, err = executeRoot("audit", ".", "--raise-error")
	if err == nil {
		t.Fatal("audit with --raise-error succeeded despite findings")
	}
	if !strings.Contains(stdout, "complete-with-findings") || !strings.Contains(stdout, "mutable reference") {
		t.Fatalf("stdout = %q; want report before raised error", stdout)
	}
}

func TestAuditCLIIncompleteRetainsFindingsWithoutCleanMessage(t *testing.T) {
	originalAudit := auditRepository
	scanErrors := []sc.ScanError{{FilePath: "broken.yml", Message: "invalid YAML"}}
	auditRepository = func(sc.FilePath) (*sc.AuditResult, error) {
		return &sc.AuditResult{
			Status:   sc.ScanStatusIncomplete,
			Complete: false,
			Workflows: []sc.Workflow{{
				Name: "valid.yml", FilePath: "valid.yml", Issues: []sc.Finding{{Description: "retained finding"}},
			}},
			Errors: scanErrors,
		}, &sc.IncompleteScanError{Errors: scanErrors}
	}
	t.Cleanup(func() { auditRepository = originalAudit })

	stdout, stderr, err := executeRoot("audit", ".")
	if err == nil {
		t.Fatal("incomplete audit returned success")
	}
	if !strings.Contains(stdout, "retained finding") || !strings.Contains(stdout, "Scan status: incomplete") {
		t.Fatalf("stdout = %q; want retained finding and incomplete state", stdout)
	}
	if strings.Contains(stdout, "No mutable references found") {
		t.Fatalf("incomplete audit printed clean success: %q", stdout)
	}
	if !strings.Contains(stderr, "broken.yml") {
		t.Fatalf("stderr = %q; want file error", stderr)
	}
}

func TestFindCLIWritesPartialJSONBeforeReturningError(t *testing.T) {
	workspace := t.TempDir()
	repo := filepath.Join(workspace, "repo")
	if err := os.Mkdir(repo, 0o755); err != nil {
		t.Fatalf("create repository directory: %v", err)
	}
	if _, err := gitlib.PlainInit(repo, false); err != nil {
		t.Fatalf("initialize repository: %v", err)
	}
	workflowDir := filepath.Join(repo, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("create workflows: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "valid.yml"), []byte("jobs:\n  test:\n    steps:\n      - uses: owner/repo@feature-x\n"), 0o644); err != nil {
		t.Fatalf("write valid workflow: %v", err)
	}
	broken := filepath.Join(workflowDir, "broken.yml")
	if err := os.WriteFile(broken, []byte("jobs:\n  broken: [\n"), 0o644); err != nil {
		t.Fatalf("write broken workflow: %v", err)
	}

	originalDir, _ := os.Getwd()
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("change output directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalDir) })
	stdout, stderr, err := executeRoot("find", "--root", workspace, "--head-only", "--out", "json")
	if err == nil {
		t.Fatal("incomplete find returned success")
	}
	if !strings.Contains(stdout, "Scan status: incomplete") || !strings.Contains(stderr, broken) {
		t.Fatalf("stdout=%q stderr=%q", stdout, stderr)
	}
	output, readErr := os.ReadFile("findings.json")
	if readErr != nil {
		t.Fatalf("read findings JSON: %v", readErr)
	}
	if !strings.Contains(string(output), `"status": "incomplete"`) || !strings.Contains(string(output), `"original": "owner/repo@feature-x"`) {
		t.Fatalf("partial JSON missing status or finding: %s", output)
	}
}

func TestUpgradeAllSHAReturnsMalformedWorkflowError(t *testing.T) {
	repo := t.TempDir()
	if _, err := gitlib.PlainInit(repo, false); err != nil {
		t.Fatalf("initialize repository: %v", err)
	}
	workflowDir := filepath.Join(repo, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("create workflows: %v", err)
	}
	broken := filepath.Join(workflowDir, "broken.yml")
	if err := os.WriteFile(broken, []byte("jobs:\n  broken: [\n"), 0o644); err != nil {
		t.Fatalf("write malformed workflow: %v", err)
	}

	_, stderr, err := executeRoot("upgrade-all-sha", repo)
	if err == nil || !strings.Contains(err.Error(), broken) {
		t.Fatalf("error = %v; want malformed workflow context", err)
	}
	if strings.Contains(stderr, "Usage:") {
		t.Fatalf("runtime error printed usage: %q", stderr)
	}
}

func TestMachineOutputsExposeIncompleteStatus(t *testing.T) {
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalDir) })

	result := &sc.InventoryResult{
		Status:   sc.ScanStatusIncomplete,
		Complete: false,
		Records: []*sc.InventoryResultRecord{{
			Repository: "workspace/repo",
			Branch:     "main",
			FilePath:   "valid.yml",
			Matches:    []string{"owner/repo@main"},
			Findings: []sc.ReferenceFinding{{
				FilePath: "valid.yml", Line: 4, Column: 15, Repository: "owner/repo", Ref: "main", Original: "owner/repo@main", Editable: true,
			}},
		}},
		Errors: []sc.ScanError{{FilePath: "broken.yml", Message: "invalid YAML"}},
	}
	if err := writeToJSON(result); err != nil {
		t.Fatalf("write JSON: %v", err)
	}
	jsonOutput, err := os.ReadFile("findings.json")
	if err != nil {
		t.Fatalf("read JSON: %v", err)
	}
	if !strings.Contains(string(jsonOutput), `"status": "incomplete"`) || !strings.Contains(string(jsonOutput), `"complete": false`) {
		t.Fatalf("JSON output does not expose incomplete state: %s", jsonOutput)
	}

	if err := WriteToCSV(result); err != nil {
		t.Fatalf("write CSV: %v", err)
	}
	csvOutput, err := os.ReadFile("findings.csv")
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}
	rows, err := csv.NewReader(bytes.NewReader(csvOutput)).ReadAll()
	if err != nil {
		t.Fatalf("parse CSV: %v", err)
	}
	if len(rows) != 3 || rows[0][0] != "repository_name" || rows[0][3] != "action" ||
		rows[1][0] != "workspace/repo" || rows[1][3] != "owner/repo@main" || rows[1][4] != "incomplete" || rows[1][5] != "finding" ||
		rows[2][4] != "incomplete" || rows[2][5] != "error" || rows[2][11] != "invalid YAML" {
		t.Fatalf("CSV output does not expose incomplete state: %#v", rows)
	}
}
