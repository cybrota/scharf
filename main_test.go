// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nw "github.com/cybrota/scharf/network"
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
	if len(rows) != 3 || strings.Join(rows[0][:4], ",") != "repository_name,branch_name,actions_file,action" ||
		rows[1][0] != "workspace/repo" || rows[1][3] != "owner/repo@main" || rows[1][4] != "incomplete" || rows[1][5] != "finding" ||
		rows[2][4] != "incomplete" || rows[2][5] != "error" || rows[2][11] != "invalid YAML" {
		t.Fatalf("CSV output does not expose incomplete state: %#v", rows)
	}
}

func TestAuditCLIRepeatableIgnoresDoNotSuppressUnrelatedFindings(t *testing.T) {
	repo := t.TempDir()
	if _, err := gitlib.PlainInit(repo, false); err != nil {
		t.Fatal(err)
	}
	originalAudit := auditRepository
	auditRepository = func(sc.FilePath) (*sc.AuditResult, error) {
		return &sc.AuditResult{
			Status: sc.ScanStatusFindings, Complete: true,
			Details: []sc.ReferenceFinding{
				{FilePath: filepath.Join(repo, ".github/workflows/ci.yml"), Repository: "owner/ignored", Ref: "main", Original: "owner/ignored@main"},
				{FilePath: filepath.Join(repo, ".github/workflows/ci.yml"), Repository: "owner/kept", Ref: "v1", Original: "owner/kept@v1"},
			},
		}, nil
	}
	t.Cleanup(func() { auditRepository = originalAudit })

	_, _, err := executeRoot("audit", repo, "--raise-error", "--ignore", "owner/ignored")
	if err == nil || !strings.Contains(err.Error(), "1 policy violation") {
		t.Fatalf("error = %v; unrelated finding was suppressed", err)
	}
	stdout, stderr, err := executeRoot("audit", repo, "--raise-error", "--ignore", "owner/ignored", "--ignore", `regex:owner/kept@v[0-9]+`)
	if err != nil {
		t.Fatalf("all ignored audit failed: %v (stderr: %s)", err, stderr)
	}
	if !strings.Contains(stdout, "cli-ignore") || !strings.Contains(stdout, "Policy outcome: pass") {
		t.Fatalf("stdout = %q; want explicit ignore dispositions", stdout)
	}
}

func TestAuditCLIPolicyCanDisableTransientIgnores(t *testing.T) {
	repo := t.TempDir()
	if _, err := gitlib.PlainInit(repo, false); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(repo, ".scharf-policy.yml")
	if err := os.WriteFile(policyPath, []byte("version: 1\nallow_cli_ignores: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := executeRoot("audit", repo, "--ignore", "owner/repo")
	if err == nil || !strings.Contains(err.Error(), "CLI ignores are disabled") {
		t.Fatalf("error = %v", err)
	}
}

func TestAuditCLISARIFRetainsIncompleteStateBeforeFailure(t *testing.T) {
	repo := t.TempDir()
	if _, err := gitlib.PlainInit(repo, false); err != nil {
		t.Fatal(err)
	}
	originalAudit := auditRepository
	scanErrors := []sc.ScanError{{FilePath: ".github/workflows/broken.yml", Message: "invalid YAML"}}
	auditRepository = func(sc.FilePath) (*sc.AuditResult, error) {
		return &sc.AuditResult{Status: sc.ScanStatusIncomplete, Complete: false, Errors: scanErrors}, &sc.IncompleteScanError{Errors: scanErrors}
	}
	t.Cleanup(func() { auditRepository = originalAudit })

	stdout, stderr, err := executeRoot("audit", repo, "--out", "sarif")
	if err == nil {
		t.Fatal("incomplete SARIF audit returned success")
	}
	if !strings.Contains(stdout, `"executionSuccessful": false`) || !strings.Contains(stdout, sc.ScanIncompleteRuleID) || !strings.Contains(stderr, "broken.yml") {
		t.Fatalf("stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestAuditCLIChangedLineModeUsesClassifications(t *testing.T) {
	repo := t.TempDir()
	if _, err := gitlib.PlainInit(repo, false); err != nil {
		t.Fatal(err)
	}
	originalAudit := auditRepository
	originalClassify := classifyRepositoryFindings
	auditRepository = func(sc.FilePath) (*sc.AuditResult, error) {
		return &sc.AuditResult{
			Status: sc.ScanStatusFindings, Complete: true,
			Details: []sc.ReferenceFinding{{FilePath: filepath.Join(repo, ".github/workflows/ci.yml"), Repository: "owner/repo", Ref: "main", Original: "owner/repo@main"}},
		}, nil
	}
	classifyRepositoryFindings = func(string, string, []sc.ReferenceFinding) ([]sc.FindingClassification, error) {
		return []sc.FindingClassification{{Classified: true, New: false, Changed: false}}, nil
	}
	t.Cleanup(func() {
		auditRepository = originalAudit
		classifyRepositoryFindings = originalClassify
	})

	stdout, stderr, err := executeRoot("audit", repo, "--baseline-ref", "main", "--changed-lines", "--raise-error")
	if err != nil {
		t.Fatalf("unchanged finding failed audit: %v (stderr: %s)", err, stderr)
	}
	if !strings.Contains(stdout, "unchanged-line") || !strings.Contains(stdout, "Policy outcome: pass") {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestAuditRaiseErrorDoesNotTrustDiscoveredCheckoutPolicy(t *testing.T) {
	repo := t.TempDir()
	if _, err := gitlib.PlainInit(repo, false); err != nil {
		t.Fatal(err)
	}
	policy := "version: 1\nexceptions:\n  - id: BYPASS\n    match:\n      repository: owner/repo\n    owner: attacker\n    rationale: suppress enforcement\n    approved_by: attacker\n    approval: untrusted\n    expires: 2099-01-01\n"
	if err := os.WriteFile(filepath.Join(repo, ".scharf-policy.yml"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	originalAudit := auditRepository
	auditRepository = func(sc.FilePath) (*sc.AuditResult, error) {
		return &sc.AuditResult{Status: sc.ScanStatusFindings, Complete: true, Details: []sc.ReferenceFinding{{
			FilePath: filepath.Join(repo, ".github/workflows/ci.yml"), Repository: "owner/repo", Ref: "main", Original: "owner/repo@main",
		}}}, nil
	}
	t.Cleanup(func() { auditRepository = originalAudit })

	_, _, err := executeRoot("audit", repo, "--raise-error")
	if err == nil || !strings.Contains(err.Error(), "policy violation") {
		t.Fatalf("checkout policy bypassed enforcement: %v", err)
	}
	stdout, stderr, err := executeRoot("audit", repo, "--raise-error", "--policy", filepath.Join(repo, ".scharf-policy.yml"))
	if err != nil {
		t.Fatalf("explicitly trusted policy failed: %v (stderr: %s)", err, stderr)
	}
	if !strings.Contains(stdout, "active-exception") {
		t.Fatalf("trusted policy was not applied: %q", stdout)
	}
}

func TestProvenanceFlagsAreOptIn(t *testing.T) {
	root := newRootCmd()
	for _, name := range []string{"audit", "autofix", "upgrade", "upgrade-all-sha"} {
		command, _, err := root.Find([]string{name})
		if err != nil {
			t.Fatalf("find %s: %v", name, err)
		}
		flag := command.Flags().Lookup("verify-provenance")
		if flag == nil || flag.DefValue != "false" {
			t.Fatalf("%s provenance flag = %#v; want opt-in default false", name, flag)
		}
	}
}

func TestAuditCLIProvenanceDispatchesAndUsesPolicyRenderer(t *testing.T) {
	repo := t.TempDir()
	if _, err := gitlib.PlainInit(repo, false); err != nil {
		t.Fatal(err)
	}
	originalAudit := auditRepository
	originalVerifiedAudit := auditRepositoryWithOptions
	legacyCalls, verifiedCalls := 0, 0
	auditRepository = func(sc.FilePath) (*sc.AuditResult, error) {
		legacyCalls++
		return &sc.AuditResult{Status: sc.ScanStatusClean, Complete: true}, nil
	}
	auditRepositoryWithOptions = func(path sc.FilePath, options sc.VerificationOptions) (*sc.AuditResult, error) {
		verifiedCalls++
		if string(path) != repo || !options.VerifyProvenance {
			t.Fatalf("verified audit arguments: %s, %#v", path, options)
		}
		return &sc.AuditResult{Status: sc.ScanStatusClean, Complete: true}, nil
	}
	t.Cleanup(func() {
		auditRepository = originalAudit
		auditRepositoryWithOptions = originalVerifiedAudit
	})

	stdout, stderr, err := executeRoot("audit", repo)
	if err != nil || legacyCalls != 1 || verifiedCalls != 0 || strings.Contains(stdout, "Policy outcome:") {
		t.Fatalf("legacy audit changed: stdout=%q stderr=%q error=%v calls=%d/%d", stdout, stderr, err, legacyCalls, verifiedCalls)
	}
	stdout, stderr, err = executeRoot("audit", repo, "--verify-provenance=false")
	if err != nil || legacyCalls != 2 || verifiedCalls != 0 || strings.Contains(stdout, "Policy outcome:") {
		t.Fatalf("explicitly disabled provenance changed audit: stdout=%q stderr=%q error=%v calls=%d/%d", stdout, stderr, err, legacyCalls, verifiedCalls)
	}
	stdout, stderr, err = executeRoot("audit", repo, "--verify-provenance")
	if err != nil || legacyCalls != 2 || verifiedCalls != 1 || !strings.Contains(stdout, "Policy outcome:") {
		t.Fatalf("verified audit did not use policy report: stdout=%q stderr=%q error=%v calls=%d/%d", stdout, stderr, err, legacyCalls, verifiedCalls)
	}
}

func TestAuditCLIJSONRetainsIncompleteStateBeforeFailure(t *testing.T) {
	repo := t.TempDir()
	if _, err := gitlib.PlainInit(repo, false); err != nil {
		t.Fatal(err)
	}
	originalAudit := auditRepositoryWithOptions
	scanErrors := []sc.ScanError{{FilePath: "ci.yml", Message: "provenance API unavailable"}}
	auditRepositoryWithOptions = func(sc.FilePath, sc.VerificationOptions) (*sc.AuditResult, error) {
		return &sc.AuditResult{Status: sc.ScanStatusIncomplete, Complete: false, Errors: scanErrors}, &sc.IncompleteScanError{Errors: scanErrors}
	}
	t.Cleanup(func() { auditRepositoryWithOptions = originalAudit })

	stdout, _, err := executeRoot("audit", repo, "--verify-provenance", "--out", "json")
	if err == nil {
		t.Fatal("incomplete verified audit returned success")
	}
	var report sc.PolicyReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("audit output is not standalone JSON: %v; output=%q", err, stdout)
	}
	if report.Complete || report.Status != sc.ScanStatusIncomplete || len(report.Errors) != 1 {
		t.Fatalf("JSON lost incomplete provenance state: %#v", report)
	}

	output := filepath.Join(t.TempDir(), "audit.json")
	stdout, _, err = executeRoot("audit", repo, "--verify-provenance", "--out", "json", "--output", output)
	if err == nil || stdout != "" {
		t.Fatalf("file audit error=%v stdout=%q", err, stdout)
	}
	contents, err := os.ReadFile(output)
	if err != nil || !json.Valid(contents) || !bytes.Contains(contents, []byte("provenance API unavailable")) {
		t.Fatalf("incomplete audit file missing valid report: contents=%s error=%v", contents, err)
	}
}

func TestAuditCLIJSONPreservesPinnedProvenanceEvidence(t *testing.T) {
	repo := t.TempDir()
	if _, err := gitlib.PlainInit(repo, false); err != nil {
		t.Fatal(err)
	}
	originalAudit := auditRepositoryWithOptions
	sha := strings.Repeat("a", 40)
	evidence := verifiedCLIProvenance(sha)
	evidence.Status = "unverified"
	evidence.Reason = "previously observed SHA no longer has current upstream support"
	evidence.SupportingRefs = nil
	auditRepositoryWithOptions = func(sc.FilePath, sc.VerificationOptions) (*sc.AuditResult, error) {
		return &sc.AuditResult{
			Status: sc.ScanStatusFindings, Complete: true,
			Details: []sc.ReferenceFinding{{
				FilePath: filepath.Join(repo, ".github/workflows/ci.yml"), Line: 5, Column: 15,
				Repository: "owner/repo", Ref: sha, Original: "owner/repo@" + sha,
				Pinned: true, Provenance: evidence,
			}},
		}, nil
	}
	t.Cleanup(func() { auditRepositoryWithOptions = originalAudit })

	stdout, _, err := executeRoot("audit", repo, "--verify-provenance", "--out", "json", "--raise-error")
	if err == nil || !strings.Contains(err.Error(), "1 policy violation") {
		t.Fatalf("unverified pin passed enforcement: %v", err)
	}
	var report sc.PolicyReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("invalid audit JSON: %v; output=%q", err, stdout)
	}
	if len(report.Findings) != 1 || report.Findings[0].Reference.Provenance == nil {
		t.Fatalf("JSON lost pinned provenance finding: %#v", report)
	}
	got := report.Findings[0].Reference.Provenance
	if got.Status != evidence.Status || got.SHA != sha || got.Reason != evidence.Reason {
		t.Fatalf("JSON lost provenance details: %#v", got)
	}
}

func TestRepositoryUpdatesDispatchProvenanceOnlyWhenEnabled(t *testing.T) {
	repo := t.TempDir()
	if _, err := gitlib.PlainInit(repo, false); err != nil {
		t.Fatal(err)
	}
	originalAutoFix := autoFixRepository
	originalVerifiedAutoFix := autoFixRepositoryWithOptions
	originalUpgrade := upgradePinnedSHAs
	originalVerifiedUpgrade := upgradePinnedSHAsWithOptions
	t.Cleanup(func() {
		autoFixRepository = originalAutoFix
		autoFixRepositoryWithOptions = originalVerifiedAutoFix
		upgradePinnedSHAs = originalUpgrade
		upgradePinnedSHAsWithOptions = originalVerifiedUpgrade
	})
	legacyCalls, verifiedCalls := 0, 0
	autoFixRepository = func(path sc.FilePath, dryRun bool) error {
		legacyCalls++
		if string(path) != repo || !dryRun {
			t.Fatalf("legacy autofix arguments: %s, %t", path, dryRun)
		}
		return nil
	}
	autoFixRepositoryWithOptions = func(path sc.FilePath, dryRun bool, options sc.VerificationOptions) error {
		verifiedCalls++
		if string(path) != repo || !dryRun || !options.VerifyProvenance {
			t.Fatalf("verified autofix arguments: %s, %t, %#v", path, dryRun, options)
		}
		return nil
	}
	upgradePinnedSHAs = func(path sc.FilePath, cooldown int, dryRun bool) error {
		legacyCalls++
		if string(path) != repo || cooldown != 48 || !dryRun {
			t.Fatalf("legacy upgrade arguments: %s, %d, %t", path, cooldown, dryRun)
		}
		return nil
	}
	upgradePinnedSHAsWithOptions = func(path sc.FilePath, cooldown int, dryRun bool, options sc.VerificationOptions) error {
		verifiedCalls++
		if string(path) != repo || cooldown != 48 || !dryRun || !options.VerifyProvenance {
			t.Fatalf("verified upgrade arguments: %s, %d, %t, %#v", path, cooldown, dryRun, options)
		}
		return nil
	}
	for _, args := range [][]string{
		{"autofix", repo, "--dry-run"},
		{"upgrade-all-sha", repo, "--dry-run", "--cooldown-hours", "48"},
	} {
		if _, stderr, err := executeRoot(args...); err != nil {
			t.Fatalf("legacy %v failed: %v; stderr=%q", args, err, stderr)
		}
		if _, stderr, err := executeRoot(append(args, "--verify-provenance=false")...); err != nil {
			t.Fatalf("explicitly disabled provenance %v failed: %v; stderr=%q", args, err, stderr)
		}
		if _, stderr, err := executeRoot(append(args, "--verify-provenance")...); err != nil {
			t.Fatalf("verified %v failed: %v; stderr=%q", args, err, stderr)
		}
	}
	if legacyCalls != 4 || verifiedCalls != 2 {
		t.Fatalf("dispatch calls=%d/%d; want 4/2", legacyCalls, verifiedCalls)
	}
}

type cliProvenanceResolverStub struct {
	verify      func(string, string, string) *nw.ProvenanceEvidence
	resolveNext func(string, string, int) (*nw.UpgradeResult, error)
}

func (stub *cliProvenanceResolverStub) Verify(repository, ref, sha string) *nw.ProvenanceEvidence {
	return stub.verify(repository, ref, sha)
}

func (stub *cliProvenanceResolverStub) ResolveNext(action, version string, cooldown int) (*nw.UpgradeResult, error) {
	return stub.resolveNext(action, version, cooldown)
}

func verifiedCLIProvenance(sha string) *nw.ProvenanceEvidence {
	return &nw.ProvenanceEvidence{
		Status:         "verified",
		Repository:     "owner/repo",
		RepositoryID:   7,
		SHA:            sha,
		Reason:         "reachable from upstream branch",
		SupportingRefs: []nw.ProvenanceRef{{Ref: "refs/heads/main", SHA: sha}},
	}
}

func TestAllowsVerifiedUpgradeRequiresEvidenceForExactTarget(t *testing.T) {
	sha := strings.Repeat("a", 40)
	for _, test := range []struct {
		name   string
		change func(*nw.ProvenanceEvidence)
		want   bool
	}{
		{name: "verified", want: true},
		{name: "forward movement", change: func(e *nw.ProvenanceEvidence) { e.Status = "moved-reference" }, want: true},
		{name: "canonical rename", change: func(e *nw.ProvenanceEvidence) { e.Repository = "owner/renamed" }, want: true},
		{name: "missing repository", change: func(e *nw.ProvenanceEvidence) { e.Repository = "" }},
		{name: "missing repository identity", change: func(e *nw.ProvenanceEvidence) { e.RepositoryID = 0 }},
		{name: "different SHA", change: func(e *nw.ProvenanceEvidence) { e.SHA = strings.Repeat("b", 40) }},
		{name: "missing supporting refs", change: func(e *nw.ProvenanceEvidence) { e.SupportingRefs = nil }},
		{name: "requires review", change: func(e *nw.ProvenanceEvidence) { e.RequiresReview = true }},
		{name: "unknown status", change: func(e *nw.ProvenanceEvidence) { e.Status = "unknown" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence := verifiedCLIProvenance(sha)
			if test.change != nil {
				test.change(evidence)
			}
			if got := allowsVerifiedUpgrade(evidence, sha); got != test.want {
				t.Fatalf("allowsVerifiedUpgrade(%#v) = %t; want %t", evidence, got, test.want)
			}
		})
	}
	if allowsVerifiedUpgrade(nil, sha) || allowsVerifiedUpgrade(verifiedCLIProvenance("abc"), "abc") {
		t.Fatal("missing evidence or a malformed SHA was accepted")
	}
}

func TestUpgradeVerifiesActualPinBeforeVersionHint(t *testing.T) {
	for _, sha := range []string{strings.Repeat("a", 40), strings.Repeat("A", 40)} {
		t.Run(sha[:1], func(t *testing.T) {
			originalFactory := newProvenanceUpgradeResolver
			verified := false
			newProvenanceUpgradeResolver = func() provenanceUpgradeResolver {
				return &cliProvenanceResolverStub{
					verify: func(repository, ref, actualSHA string) *nw.ProvenanceEvidence {
						if repository != "owner/repo" || ref != sha || actualSHA != sha {
							t.Fatalf("verified version hint instead of actual pin: %s, %s, %s", repository, ref, actualSHA)
						}
						verified = true
						return verifiedCLIProvenance(sha)
					},
					resolveNext: func(action, version string, cooldown int) (*nw.UpgradeResult, error) {
						if !verified || action != "owner/repo" || version != "v1" || cooldown != 48 {
							t.Fatalf("next resolution happened before pin verification or had wrong arguments: %s, %s, %d", action, version, cooldown)
						}
						return &nw.UpgradeResult{NextVersion: "v2", NextSHA: strings.Repeat("b", 40), Provenance: verifiedCLIProvenance(strings.Repeat("b", 40))}, nil
					},
				}
			}
			t.Cleanup(func() { newProvenanceUpgradeResolver = originalFactory })
			stdout, stderr, err := executeRoot("upgrade", "owner/repo@"+sha, "--from-version", "v1", "--verify-provenance", "--dry-run", "--cooldown-hours", "48")
			if err != nil || !verified || !strings.Contains(stdout, "Current pin provenance: verified") ||
				!strings.Contains(stdout, "Proposed upgrade provenance: verified") || !strings.Contains(stdout, "reachable from upstream") ||
				!strings.Contains(stdout, "Dry-run: planned upgrade") || !strings.Contains(stdout, "owner/repo@"+strings.Repeat("b", 40)+" # v2") {
				t.Fatalf("verified upgrade stdout=%q stderr=%q error=%v", stdout, stderr, err)
			}
		})
	}
}

func TestUpgradeRejectsUnsafeCurrentPin(t *testing.T) {
	for _, test := range []struct {
		name     string
		evidence *nw.ProvenanceEvidence
	}{
		{name: "missing"},
		{name: "unverified", evidence: &nw.ProvenanceEvidence{Status: "unverified", Reason: "SHA not reachable from upstream"}},
		{name: "moved", evidence: &nw.ProvenanceEvidence{Status: "verified", RequiresReview: true, Reason: "reference moved"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			originalFactory := newProvenanceUpgradeResolver
			newProvenanceUpgradeResolver = func() provenanceUpgradeResolver {
				return &cliProvenanceResolverStub{
					verify: func(string, string, string) *nw.ProvenanceEvidence { return test.evidence },
					resolveNext: func(string, string, int) (*nw.UpgradeResult, error) {
						t.Fatal("unsafe current SHA reached upgrade resolution")
						return nil, nil
					},
				}
			}
			t.Cleanup(func() { newProvenanceUpgradeResolver = originalFactory })
			stdout, stderr, err := executeRoot("upgrade", "owner/repo@"+strings.Repeat("a", 40), "--from-version", "v1", "--verify-provenance")
			if err == nil || !strings.Contains(err.Error(), "current pin") || strings.Contains(stdout, "# v2") || strings.Contains(stderr, "Usage:") {
				t.Fatalf("unsafe current pin not cleanly blocked: stdout=%q stderr=%q error=%v", stdout, stderr, err)
			}
		})
	}
}

func TestUpgradeRejectsMissingOrUnsafeProposedEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		result *nw.UpgradeResult
		err    error
	}{
		{name: "missing result"},
		{name: "resolver error", err: errors.New("upstream verification unavailable")},
		{name: "missing evidence", result: &nw.UpgradeResult{NextVersion: "v2", NextSHA: strings.Repeat("b", 40)}},
		{name: "unverified", result: &nw.UpgradeResult{NextVersion: "v2", NextSHA: strings.Repeat("b", 40), Provenance: &nw.ProvenanceEvidence{Status: "unverified"}}},
		{name: "moved", result: &nw.UpgradeResult{NextVersion: "v2", NextSHA: strings.Repeat("b", 40), Provenance: &nw.ProvenanceEvidence{Status: "verified", RequiresReview: true}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			originalFactory := newProvenanceUpgradeResolver
			newProvenanceUpgradeResolver = func() provenanceUpgradeResolver {
				return &cliProvenanceResolverStub{
					verify: func(string, string, string) *nw.ProvenanceEvidence {
						t.Fatal("tag input unexpectedly treated as pinned SHA")
						return nil
					},
					resolveNext: func(string, string, int) (*nw.UpgradeResult, error) { return test.result, test.err },
				}
			}
			t.Cleanup(func() { newProvenanceUpgradeResolver = originalFactory })
			stdout, _, err := executeRoot("upgrade", "owner/repo@v1", "--verify-provenance", "--dry-run")
			if err == nil || strings.Contains(stdout, "Dry-run: planned upgrade") || strings.Contains(stdout, "# v2") {
				t.Fatalf("unsafe proposal printed: stdout=%q error=%v", stdout, err)
			}
		})
	}
}

func TestUpgradeWithoutProvenanceUsesLegacyResolver(t *testing.T) {
	originalLegacy := newSHAUpgradeResolver
	originalVerified := newProvenanceUpgradeResolver
	newProvenanceUpgradeResolver = func() provenanceUpgradeResolver {
		t.Fatal("legacy upgrade constructed provenance resolver")
		return nil
	}
	newSHAUpgradeResolver = func() upgradeResolver {
		return &cliProvenanceResolverStub{
			resolveNext: func(action, version string, cooldown int) (*nw.UpgradeResult, error) {
				if action != "owner/repo" || version != "v1" || cooldown != defaultUpgradeCooldownHours {
					t.Fatalf("legacy arguments: %s, %s, %d", action, version, cooldown)
				}
				return &nw.UpgradeResult{NextVersion: "v2", NextSHA: strings.Repeat("b", 40)}, nil
			},
		}
	}
	t.Cleanup(func() {
		newSHAUpgradeResolver = originalLegacy
		newProvenanceUpgradeResolver = originalVerified
	})
	stdout, stderr, err := executeRoot("upgrade", "owner/repo@v1")
	if err != nil || stdout != "owner/repo@"+strings.Repeat("b", 40)+" # v2\n" {
		t.Fatalf("legacy upgrade changed: stdout=%q stderr=%q error=%v", stdout, stderr, err)
	}
	stdout, stderr, err = executeRoot("upgrade", "owner/repo@v1", "--verify-provenance=false")
	if err != nil || stdout != "owner/repo@"+strings.Repeat("b", 40)+" # v2\n" {
		t.Fatalf("explicitly disabled provenance changed upgrade: stdout=%q stderr=%q error=%v", stdout, stderr, err)
	}
}
