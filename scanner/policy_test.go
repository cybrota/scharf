// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadPolicyStrictValidationAndDefaults(t *testing.T) {
	tests := []struct {
		name    string
		policy  string
		wantErr string
	}{
		{name: "unknown field", policy: "version: 1\nunknown: true\n", wantErr: "field unknown not found"},
		{name: "unsupported version", policy: "version: 2\n", wantErr: "version must be 1"},
		{name: "duplicate rule", policy: "version: 1\nrules:\n  - id: SCHARF001\n    requirement: full-commit-sha\n  - id: SCHARF001\n    requirement: full-commit-sha\n", wantErr: "duplicate rule"},
		{name: "invalid mode", policy: "version: 1\nbaseline:\n  mode: new\n", wantErr: "baseline.ref is required"},
		{name: "malformed exception", policy: "version: 1\nexceptions:\n  - id: TEMP\n    match:\n      repository: owner/repo\n    expires: never\n", wantErr: "requires owner"},
		{name: "unknown exception field", policy: "version: 1\nexceptions:\n  - id: TEMP\n    matcher: owner/repo\n", wantErr: "field matcher not found"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "policy.yml")
			if err := os.WriteFile(file, []byte(tc.policy), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := LoadPolicy(file)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v; want containing %q", err, tc.wantErr)
			}
		})
	}

	policyFile := filepath.Join(t.TempDir(), "policy.yml")
	if err := os.WriteFile(policyFile, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	policy, err := LoadPolicy(policyFile)
	if err != nil {
		t.Fatalf("LoadPolicy returned error: %v", err)
	}
	if len(policy.Rules) != 1 || policy.Rules[0].ID != MutableReferenceRuleID || !*policy.AllowCLIIgnores || policy.Baseline.Mode != "all" {
		t.Fatalf("defaults not applied: %#v", policy)
	}
}

func TestLoadRepositoryPolicyDiscovery(t *testing.T) {
	repo := t.TempDir()
	policy, source, err := LoadRepositoryPolicy(repo, "")
	if err != nil || source != "" || len(policy.Rules) != 1 {
		t.Fatalf("default policy = %#v source=%q err=%v", policy, source, err)
	}

	policyPath := filepath.Join(repo, defaultPolicyFileName)
	if err := os.WriteFile(policyPath, []byte("version: 1\nallow_cli_ignores: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	policy, source, err = LoadRepositoryPolicy(repo, "")
	if err != nil || source != policyPath || *policy.AllowCLIIgnores {
		t.Fatalf("discovered policy = %#v source=%q err=%v", policy, source, err)
	}
}

func TestEvaluatePolicyExceptionPrecedenceAndExpiration(t *testing.T) {
	allow := true
	policy := &Policy{
		Version:         1,
		AllowCLIIgnores: &allow,
		Rules:           []PolicyRule{{ID: MutableReferenceRuleID, Requirement: fullCommitSHARequirement, Severity: "error"}},
		Baseline:        PolicyBaseline{Mode: "all"},
		Exceptions: []PolicyException{
			{
				ID: "EXPIRED", Match: ExceptionMatch{Repository: "owner/repo", Ref: "main"}, Owner: "platform", Rationale: "migration", ApprovedBy: "security", Approval: "SEC-1", Expires: "2026-09-06",
			},
		},
	}
	audit := auditResultWithFindings(ReferenceFinding{FilePath: "/repo/.github/workflows/ci.yml", Line: 4, Column: 15, Repository: "owner/repo", Ref: "main", Original: "owner/repo@main", Editable: true, FixSHA: strings.Repeat("a", 40)})

	report, err := EvaluatePolicy("/repo", audit, policy, PolicyEvaluationOptions{
		Now:           time.Date(2026, 9, 7, 1, 0, 0, 0, time.FixedZone("offset", -7*60*60)),
		CLIExceptions: []string{"owner/repo@main"},
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy returned error: %v", err)
	}
	if report.Outcome != PolicyOutcomeFail || report.Findings[0].State != PolicyFindingExpired || !report.Findings[0].Blocking {
		t.Fatalf("expired exception was suppressed by CLI ignore: %#v", report)
	}

	policy.Exceptions[0].Expires = "2026-09-07"
	report, err = EvaluatePolicy("/repo", audit, policy, PolicyEvaluationOptions{Now: time.Date(2026, 9, 7, 23, 59, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("EvaluatePolicy returned error: %v", err)
	}
	if report.Outcome != PolicyOutcomePass || report.Findings[0].State != PolicyFindingExcepted {
		t.Fatalf("inclusive expiration boundary not active: %#v", report)
	}
}

func TestEvaluatePolicyExactAndRegexCLIIgnores(t *testing.T) {
	audit := auditResultWithFindings(
		ReferenceFinding{FilePath: "/repo/.github/workflows/ci.yml", Repository: "owner/repo", Subpath: "deploy", Ref: "feature/x", Original: "owner/repo/deploy@feature/x"},
		ReferenceFinding{FilePath: "/repo/.github/workflows/ci.yml", Repository: "owner/repo", Subpath: "other", Ref: "main", Original: "owner/repo/other@main"},
		ReferenceFinding{FilePath: "/repo/.github/workflows/ci.yml", Repository: "another/action", Ref: "v1", Original: "another/action@v1"},
	)
	report, err := EvaluatePolicy("/repo", audit, DefaultPolicy(), PolicyEvaluationOptions{CLIExceptions: []string{
		"owner/repo/deploy@feature/x",
		`regex:another/action@v[0-9]+`,
	}})
	if err != nil {
		t.Fatalf("EvaluatePolicy returned error: %v", err)
	}
	want := []PolicyFindingState{PolicyFindingIgnored, PolicyFindingViolation, PolicyFindingIgnored}
	for i, state := range want {
		if report.Findings[i].State != state {
			t.Errorf("finding %d state = %q, want %q", i, report.Findings[i].State, state)
		}
	}
	if report.ViolationCount != 1 {
		t.Fatalf("violations = %d, want 1", report.ViolationCount)
	}

	_, err = EvaluatePolicy("/repo", audit, DefaultPolicy(), PolicyEvaluationOptions{CLIExceptions: []string{"regex:["}})
	if err == nil || !strings.Contains(err.Error(), "invalid CLI ignore") {
		t.Fatalf("malformed regex error = %v", err)
	}
}

func TestEvaluatePolicyRuleScopeAndBaseline(t *testing.T) {
	allow := true
	policy := &Policy{
		Version:         1,
		AllowCLIIgnores: &allow,
		Rules: []PolicyRule{{
			ID: MutableReferenceRuleID, Requirement: fullCommitSHARequirement, Severity: "error",
			Repositories: []string{"actions/*"}, Paths: []string{".github/workflows/release.y*ml"},
		}},
		Baseline: PolicyBaseline{Ref: "origin/main", Mode: "new"},
	}
	audit := auditResultWithFindings(
		ReferenceFinding{FilePath: "/repo/.github/workflows/release.yml", Repository: "actions/checkout", Ref: "v4", Original: "actions/checkout@v4"},
		ReferenceFinding{FilePath: "/repo/.github/workflows/release.yml", Repository: "owner/internal", Ref: "main", Original: "owner/internal@main"},
	)
	report, err := EvaluatePolicy("/repo", audit, policy, PolicyEvaluationOptions{Classifications: []FindingClassification{
		{Classified: true, New: false, Changed: false},
		{Classified: true, New: true, Changed: true},
	}})
	if err != nil {
		t.Fatalf("EvaluatePolicy returned error: %v", err)
	}
	if report.Findings[0].State != PolicyFindingBaseline || report.Findings[1].State != PolicyFindingOutsideRule || report.ViolationCount != 0 {
		t.Fatalf("scope/baseline result = %#v", report)
	}
}

func TestEvaluatePolicyChangedLinesAndIncompleteOutcome(t *testing.T) {
	audit := auditResultWithFindings(
		ReferenceFinding{FilePath: "/repo/.github/workflows/ci.yml", Repository: "owner/old", Ref: "main", Original: "owner/old@main"},
		ReferenceFinding{FilePath: "/repo/.github/workflows/ci.yml", Repository: "owner/new", Ref: "main", Original: "owner/new@main"},
	)
	audit.Status = ScanStatusIncomplete
	audit.Complete = false
	audit.Errors = []ScanError{{FilePath: "broken.yml", Message: "invalid YAML"}}
	report, err := EvaluatePolicy("/repo", audit, DefaultPolicy(), PolicyEvaluationOptions{
		ChangedLinesOnly: true,
		Classifications: []FindingClassification{
			{Classified: true, New: false, Changed: false},
			{Classified: true, New: true, Changed: true},
		},
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy returned error: %v", err)
	}
	if report.Outcome != PolicyOutcomeIncomplete || report.Findings[0].State != PolicyFindingUnchanged || report.Findings[1].State != PolicyFindingViolation || report.ViolationCount != 1 {
		t.Fatalf("report = %#v", report)
	}
}

func TestChangedLineEnforcementOverridesBaselineSuppression(t *testing.T) {
	audit := auditResultWithFindings(ReferenceFinding{
		FilePath: "/repo/.github/workflows/ci.yml", Repository: "owner/repo", Ref: "main", Original: "owner/repo@main",
	})
	policy := DefaultPolicy()
	policy.Baseline = PolicyBaseline{Ref: "origin/main", Mode: "new"}
	report, err := EvaluatePolicy("/repo", audit, policy, PolicyEvaluationOptions{
		ChangedLinesOnly: true,
		Classifications:  []FindingClassification{{Classified: true, New: false, Changed: true}},
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy returned error: %v", err)
	}
	if report.Findings[0].State != PolicyFindingViolation || !report.Findings[0].Blocking {
		t.Fatalf("changed baseline finding was suppressed: %#v", report.Findings[0])
	}
}

func TestEvaluatePolicyDisallowsCLIIgnores(t *testing.T) {
	allow := false
	policy := DefaultPolicy()
	policy.AllowCLIIgnores = &allow
	_, err := EvaluatePolicy("/repo", auditResultWithFindings(), policy, PolicyEvaluationOptions{CLIExceptions: []string{"owner/repo"}})
	if err == nil || !strings.Contains(err.Error(), "disabled by policy") {
		t.Fatalf("error = %v", err)
	}
}

func auditResultWithFindings(findings ...ReferenceFinding) *AuditResult {
	return &AuditResult{
		Status:   ScanStatusFindings,
		Complete: true,
		Details:  findings,
	}
}
