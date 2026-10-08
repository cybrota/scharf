// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cybrota/scharf/network"
)

type fakeProvenanceResolver struct {
	evidence map[string]*network.ProvenanceEvidence
	errors   map[string]error
	verified []string
	resolved []string
}

func (f *fakeProvenanceResolver) ResolveWithProvenance(action string) (string, *network.ProvenanceEvidence, error) {
	f.resolved = append(f.resolved, action)
	evidence := f.evidence[action]
	if evidence == nil {
		return "", nil, fmt.Errorf("no fixture for %s", action)
	}
	return evidence.SHA, evidence, f.errors[action]
}

func (f *fakeProvenanceResolver) Verify(repository, ref, sha string) *network.ProvenanceEvidence {
	f.verified = append(f.verified, repository+"@"+ref+":"+sha)
	return f.evidence[repository+"@"+ref]
}

func verifiedEvidence(repository, ref, sha string) *network.ProvenanceEvidence {
	return &network.ProvenanceEvidence{
		Status: "verified", Repository: repository, RepositoryID: 1234,
		OriginalRef: ref, SHA: sha, CheckedAt: "2026-10-08T12:00:00Z",
		SupportingRefs: []network.ProvenanceRef{{Ref: "refs/heads/main", SHA: sha}},
		Reason:         "commit is reachable from an upstream branch",
	}
}

func installAuditProvenanceResolver(t *testing.T, resolver provenanceResolver) {
	t.Helper()
	previous := newAuditProvenanceResolver
	newAuditProvenanceResolver = func() provenanceResolver { return resolver }
	t.Cleanup(func() { newAuditProvenanceResolver = previous })
}

func TestProvenanceAuditIncludesPinnedAndMutableReferences(t *testing.T) {
	sha := strings.Repeat("a", 40)
	unverifiedSHA := strings.Repeat("b", 40)
	resolver := &fakeProvenanceResolver{evidence: map[string]*network.ProvenanceEvidence{
		"owner/pinned@" + sha: verifiedEvidence("owner/pinned", sha, sha),
		"owner/mutable@v1":    verifiedEvidence("owner/mutable", "v1", sha),
		"owner/unverified@" + unverifiedSHA: {
			Status: "unverified", Repository: "owner/unverified", OriginalRef: unverifiedSHA,
			SHA: unverifiedSHA, Reason: "no upstream branch reaches commit",
		},
	}}
	content := []byte("jobs:\n  call:\n    uses: owner/mutable/.github/workflows/reuse.yml@v1\n  test:\n    steps:\n      - uses: owner/pinned/subpath@" + sha + " # v1\n      - uses: owner/unverified@" + unverifiedSHA + "\n      - uses: ./local\n      - uses: docker://alpine:3\n      - run: echo owner/ignored@main\n")
	analysis, err := analyzeWorkflowWithProvenance(resolver, content, "/repo/.github/workflows/ci.yml")
	if err != nil || len(analysis.Findings) != 3 {
		t.Fatalf("analysis = %#v, error = %v", analysis, err)
	}
	if len(resolver.verified) != 2 || len(resolver.resolved) != 1 {
		t.Fatalf("verified = %v, resolved = %v", resolver.verified, resolver.resolved)
	}
	if resolver.verified[0] != "owner/pinned@"+sha+":"+sha {
		t.Fatalf("verification trusted version hint rather than actual pin: %v", resolver.verified)
	}
	if !analysis.Findings[1].Pinned || analysis.Findings[1].FixSHA != "" || analysis.Findings[1].Subpath != "subpath" {
		t.Fatalf("pinned reference offers a rewrite or lost subpath: %#v", analysis.Findings[1])
	}
	audit := &AuditResult{Details: analysis.Findings, Workflows: []Workflow{analysis.Workflow}}
	audit.setStatus()
	report, err := EvaluatePolicy("/repo", audit, DefaultPolicy(), PolicyEvaluationOptions{})
	if err != nil || report.ViolationCount != 2 || len(report.Findings) != 4 {
		t.Fatalf("policy report = %#v, error = %v", report, err)
	}
	for _, finding := range report.Findings {
		if finding.Reference.Pinned && finding.RuleID != ProvenanceRuleID {
			t.Fatalf("pinned reference mislabeled mutable: %#v", finding)
		}
	}
}

func TestVerifiedPinnedAuditIsCleanAndPreservesEvidence(t *testing.T) {
	repo := t.TempDir()
	initGitRepo(t, repo)
	sha := strings.Repeat("a", 40)
	writeWorkflow(t, repo, "jobs:\n  test:\n    steps:\n      - uses: owner/repo@"+sha+"\n")
	resolver := &fakeProvenanceResolver{evidence: map[string]*network.ProvenanceEvidence{"owner/repo@" + sha: verifiedEvidence("owner/repo", sha, sha)}}
	installAuditProvenanceResolver(t, resolver)
	result, err := AuditRepositoryResultWithOptions(FilePath(repo), VerificationOptions{VerifyProvenance: true})
	if err != nil || result.Status != ScanStatusClean || !result.Complete || len(result.Details) != 1 {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	report, err := EvaluatePolicy(repo, result, DefaultPolicy(), PolicyEvaluationOptions{})
	if err != nil || report.Outcome != PolicyOutcomePass || report.ViolationCount != 0 || len(report.Findings) != 1 {
		t.Fatalf("report = %#v, error = %v", report, err)
	}
	if output := FormatGitHubAnnotations(report); !strings.HasPrefix(output, "::notice ") {
		t.Fatalf("verified evidence incorrectly emitted as failure: %s", output)
	}
}

func TestDefaultAuditDoesNotConstructProvenanceResolver(t *testing.T) {
	repo := t.TempDir()
	initGitRepo(t, repo)
	writeWorkflow(t, repo, "jobs:\n  test:\n    steps:\n      - uses: owner/repo@"+strings.Repeat("a", 40)+"\n")
	previous := newAuditProvenanceResolver
	newAuditProvenanceResolver = func() provenanceResolver {
		t.Fatal("default audit constructed provenance resolver")
		return nil
	}
	t.Cleanup(func() { newAuditProvenanceResolver = previous })
	result, err := AuditRepositoryResult(FilePath(repo))
	if err != nil || len(result.Details) != 0 || result.Status != ScanStatusClean {
		t.Fatalf("legacy audit changed: %#v, %v", result, err)
	}
}

func TestProvenanceEvidenceInJSONSARIFAndHumanOutput(t *testing.T) {
	sha := strings.Repeat("b", 40)
	evidence := verifiedEvidence("owner/repo", "v1.2.3", sha)
	evidence.Status = "moved-reference"
	evidence.Moved = true
	evidence.RequiresReview = true
	evidence.Previous = &network.ProvenanceObservation{Repository: "owner/repo", RepositoryID: 1234, SHA: strings.Repeat("a", 40), CheckedAt: "2026-10-07T12:00:00Z"}
	finding := ReferenceFinding{FilePath: "/repo/ci.yml", Line: 4, Column: 15, Repository: "owner/repo", Ref: sha, Original: "owner/repo@" + sha, Pinned: true, Provenance: evidence, Editable: true, FixSHA: sha}
	report := &PolicyReport{Status: ScanStatusFindings, Complete: true, Findings: []EvaluatedFinding{evaluateProvenance("/repo", finding)}}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var sarif bytes.Buffer
	if err := WriteSARIF(&sarif, report); err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{string(encoded), sarif.String()} {
		for _, want := range []string{"provenance", "repository_id", "1234", "checked_at", "supporting_refs", "refs/heads/main", "moved-reference", "requires_review", "previous"} {
			if !strings.Contains(output, want) {
				t.Fatalf("machine output missing %q: %s", want, output)
			}
		}
	}
	if strings.Contains(sarif.String(), `"fixes"`) || strings.Contains(sarif.String(), "Mutable GitHub Actions reference") {
		t.Fatalf("provenance SARIF suggests pin edits or mislabels pins: %s", sarif.String())
	}
	human := FormatPolicyHuman(report)
	for _, want := range []string{"moved-reference", "repository ID 1234", "2026-10-08T12:00:00Z", "refs/heads/main", "Previous observation", "Review required"} {
		if !strings.Contains(human, want) {
			t.Fatalf("human output missing %q: %s", want, human)
		}
	}
}

func TestProvenanceAutofixPreflightsEveryWorkflow(t *testing.T) {
	repo := t.TempDir()
	initGitRepo(t, repo)
	sha := strings.Repeat("a", 40)
	content := "jobs:\n  test:\n    steps:\n      - uses: owner/safe@v1\n"
	first := writeWorkflow(t, repo, content)
	second := filepath.Join(filepath.Dir(first), "later.yml")
	if err := os.WriteFile(second, []byte("jobs:\n  test:\n    steps:\n      - uses: owner/unsafe@"+sha+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resolver := &fakeProvenanceResolver{evidence: map[string]*network.ProvenanceEvidence{
		"owner/safe@v1":       verifiedEvidence("owner/safe", "v1", sha),
		"owner/unsafe@" + sha: {Status: "identity-mismatch", Repository: "owner/unsafe", SHA: sha, Reason: "repository ID changed"},
	}}
	installAuditProvenanceResolver(t, resolver)
	err := AutoFixRepositoryWithOptions(FilePath(repo), false, VerificationOptions{VerifyProvenance: true})
	if err == nil || !strings.Contains(err.Error(), "identity-mismatch") {
		t.Fatalf("unsafe autofix error = %v", err)
	}
	data, err := os.ReadFile(first)
	if err != nil || string(data) != content {
		t.Fatalf("first workflow changed before provenance preflight: %s, %v", data, err)
	}
}

func TestProvenanceAutofixPreservesPinsAndFixesSubpaths(t *testing.T) {
	repo := t.TempDir()
	initGitRepo(t, repo)
	sha := strings.Repeat("a", 40)
	pinned := "      - uses: 'owner/repo/other@" + sha + "' # retained hint\n"
	file := writeWorkflow(t, repo, "jobs:\n  test:\n    steps:\n      - uses: \"owner/repo/subpath@v1\"\n"+pinned)
	resolver := &fakeProvenanceResolver{evidence: map[string]*network.ProvenanceEvidence{
		"owner/repo@v1":     verifiedEvidence("owner/repo", "v1", sha),
		"owner/repo@" + sha: verifiedEvidence("owner/repo", sha, sha),
	}}
	installAuditProvenanceResolver(t, resolver)
	if err := AutoFixRepositoryWithOptions(FilePath(repo), false, VerificationOptions{VerifyProvenance: true}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil || !strings.Contains(string(data), "\"owner/repo/subpath@"+sha+"\" # v1") || !strings.Contains(string(data), pinned) {
		t.Fatalf("unexpected verified autofix: %s, %v", data, err)
	}
}

func TestAuditResolutionFailureCannotRetainVerifiedFix(t *testing.T) {
	sha := strings.Repeat("a", 40)
	resolver := &fakeProvenanceResolver{
		evidence: map[string]*network.ProvenanceEvidence{"owner/repo@v1": verifiedEvidence("owner/repo", "v1", sha)},
		errors:   map[string]error{"owner/repo@v1": errors.New("API timeout")},
	}
	analysis, err := analyzeWorkflowWithProvenance(resolver, []byte("jobs:\n  test:\n    steps:\n      - uses: owner/repo@v1\n"), "ci.yml")
	if err != nil || len(analysis.Findings) != 1 {
		t.Fatalf("analysis = %#v, %v", analysis, err)
	}
	finding := analysis.Findings[0]
	if finding.Provenance.AllowsUpdate() || finding.FixSHA != SHA256NotAvailable || !strings.Contains(finding.Provenance.Reason, "API timeout") {
		t.Fatalf("failed lookup retained safe edit: %#v", finding)
	}
}

func TestAuditRetainsUnsafeProvenanceStatusOnResolutionError(t *testing.T) {
	sha := strings.Repeat("a", 40)
	for _, status := range []string{"identity-mismatch", "moved-reference"} {
		t.Run(status, func(t *testing.T) {
			evidence := verifiedEvidence("owner/repo", "v1", sha)
			evidence.Status = status
			evidence.RequiresReview = true
			resolver := &fakeProvenanceResolver{
				evidence: map[string]*network.ProvenanceEvidence{"owner/repo@v1": evidence},
				errors:   map[string]error{"owner/repo@v1": errors.New("provenance requires review")},
			}
			analysis, err := analyzeWorkflowWithProvenance(resolver, []byte("jobs:\n  test:\n    steps:\n      - uses: owner/repo@v1\n"), "ci.yml")
			if err != nil || len(analysis.Findings) != 1 || analysis.Findings[0].Provenance.Status != status {
				t.Fatalf("unsafe status was lost: %#v, %v", analysis, err)
			}
		})
	}
}

func TestAuditAllowsVerifiedCanonicalRename(t *testing.T) {
	sha := strings.Repeat("a", 40)
	resolver := &fakeProvenanceResolver{evidence: map[string]*network.ProvenanceEvidence{"old-owner/repo@v1": verifiedEvidence("new-owner/repo", "v1", sha)}}
	analysis, err := analyzeWorkflowWithProvenance(resolver, []byte("jobs:\n  test:\n    steps:\n      - uses: old-owner/repo@v1\n"), "ci.yml")
	if err != nil || len(analysis.Findings) != 1 || !analysis.Findings[0].Provenance.AllowsUpdate() || analysis.Findings[0].FixSHA != sha {
		t.Fatalf("verified stable-ID rename rejected: %#v, %v", analysis, err)
	}
}

type fakeVerifiedUpgradeResolver struct {
	fakeUpgradeResolver
	evidence map[string]*network.ProvenanceEvidence
	verified []string
}

func (f *fakeVerifiedUpgradeResolver) Verify(repository, ref, sha string) *network.ProvenanceEvidence {
	f.verified = append(f.verified, repository+"@"+ref+":"+sha)
	return f.evidence[repository+"@"+ref]
}

func TestVerifiedUpgradeRejectsUnsafeEvidence(t *testing.T) {
	current := strings.Repeat("a", 40)
	next := strings.Repeat("b", 40)
	content := []byte("jobs:\n  test:\n    steps:\n      - uses: owner/repo/path@" + current + " # v1\n")
	for _, status := range []string{"unverified", "identity-mismatch", "moved-reference", "missing"} {
		t.Run(status, func(t *testing.T) {
			candidate := verifiedEvidence("owner/repo", "v2", next)
			candidate.Status = status
			candidate.RequiresReview = true
			if status == "missing" {
				candidate = nil
			}
			resolver := &fakeVerifiedUpgradeResolver{
				fakeUpgradeResolver: fakeUpgradeResolver{results: map[string]*network.UpgradeResult{"owner/repo@v1": {NextVersion: "v2", NextSHA: next, Provenance: candidate}}},
				evidence:            map[string]*network.ProvenanceEvidence{"owner/repo@" + current: verifiedEvidence("owner/repo", current, current)},
			}
			updated, changed, err := upgradePinnedSHAsInContentWithOptions(content, "ci.yml", resolver, 24, false, VerificationOptions{VerifyProvenance: true})
			if err == nil || changed || !bytes.Equal(updated, content) {
				t.Fatalf("unsafe upgrade changed content: %s, %v, %v", updated, changed, err)
			}
			if len(resolver.verified) != 1 || resolver.verified[0] != "owner/repo@"+current+":"+current {
				t.Fatalf("upgrade did not verify the literal old pin: %v", resolver.verified)
			}
		})
	}
}

func TestVerifiedUpgradeRejectsUnverifiedExistingPin(t *testing.T) {
	current := strings.Repeat("a", 40)
	next := strings.Repeat("b", 40)
	content := []byte("jobs:\n  test:\n    steps:\n      - uses: owner/repo@" + current + " # v1\n")
	resolver := &fakeVerifiedUpgradeResolver{
		fakeUpgradeResolver: fakeUpgradeResolver{results: map[string]*network.UpgradeResult{"owner/repo@v1": {NextVersion: "v2", NextSHA: next, Provenance: verifiedEvidence("owner/repo", "v2", next)}}},
		evidence:            map[string]*network.ProvenanceEvidence{"owner/repo@" + current: {Status: "unverified", Repository: "owner/repo", SHA: current, Reason: "orphan commit"}},
	}
	updated, changed, err := upgradePinnedSHAsInContentWithOptions(content, "ci.yml", resolver, 24, false, VerificationOptions{VerifyProvenance: true})
	if err == nil || changed || !bytes.Equal(content, updated) || !strings.Contains(err.Error(), "orphan commit") {
		t.Fatalf("unverified current pin accepted: %s, %v, %v", updated, changed, err)
	}
}

func TestVerifiedUpgradeAcceptsSupportedMovementAndDryRun(t *testing.T) {
	current := strings.Repeat("a", 40)
	next := strings.Repeat("b", 40)
	content := []byte("jobs:\n  test:\n    steps:\n      - uses: \"owner/repo/path@" + current + "\" # v1 retained\n")
	candidate := verifiedEvidence("owner/repo", "v2", next)
	candidate.Status = "moved-reference"
	candidate.Moved = true
	resolver := &fakeVerifiedUpgradeResolver{
		fakeUpgradeResolver: fakeUpgradeResolver{results: map[string]*network.UpgradeResult{"owner/repo@v1": {NextVersion: "v2", NextSHA: next, Provenance: candidate}}},
		evidence:            map[string]*network.ProvenanceEvidence{"owner/repo@" + current: verifiedEvidence("owner/repo", current, current)},
	}
	for _, dryRun := range []bool{true, false} {
		updated, changed, err := upgradePinnedSHAsInContentWithOptions(content, "ci.yml", resolver, 24, dryRun, VerificationOptions{VerifyProvenance: true})
		if err != nil {
			t.Fatal(err)
		}
		if dryRun {
			if changed || !bytes.Equal(updated, content) {
				t.Fatalf("dry-run changed content: %s", updated)
			}
		} else if !changed || !strings.Contains(string(updated), "\"owner/repo/path@"+next+"\" # v2 retained") {
			t.Fatalf("verified upgrade lost source formatting: %s", updated)
		}
	}
}

func TestProvenanceExceptionsCannotSuppressUnsafePin(t *testing.T) {
	sha := strings.Repeat("a", 40)
	finding := ReferenceFinding{FilePath: "/repo/ci.yml", Repository: "owner/repo", Ref: sha, Original: "owner/repo@" + sha, Pinned: true, Provenance: &network.ProvenanceEvidence{Status: "unverified", Repository: "owner/repo", SHA: sha}}
	audit := &AuditResult{Status: ScanStatusFindings, Complete: true, Details: []ReferenceFinding{finding}}
	report, err := EvaluatePolicy("/repo", audit, DefaultPolicy(), PolicyEvaluationOptions{CLIExceptions: []string{"owner/repo"}})
	if err != nil || report.ViolationCount != 1 || report.Findings[0].RuleID != ProvenanceRuleID || !report.Findings[0].Blocking {
		t.Fatalf("mutable-reference ignore suppressed provenance review: %#v, %v", report, err)
	}
}

func TestVerifiedUpgradePreflightsAllWorkflowEdits(t *testing.T) {
	repo := t.TempDir()
	initGitRepo(t, repo)
	current := strings.Repeat("a", 40)
	next := strings.Repeat("b", 40)
	firstContent := "jobs:\n  test:\n    steps:\n      - uses: owner/safe@" + current + " # v1\n"
	first := writeWorkflow(t, repo, firstContent)
	second := filepath.Join(filepath.Dir(first), "later.yml")
	secondContent := "jobs:\n  test:\n    steps:\n      - uses: owner/unsafe@" + current + " # v1\n"
	if err := os.WriteFile(second, []byte(secondContent), 0o644); err != nil {
		t.Fatal(err)
	}
	resolver := &fakeVerifiedUpgradeResolver{
		fakeUpgradeResolver: fakeUpgradeResolver{results: map[string]*network.UpgradeResult{"owner/safe@v1": {NextVersion: "v2", NextSHA: next, Provenance: verifiedEvidence("owner/safe", "v2", next)}}},
		evidence: map[string]*network.ProvenanceEvidence{
			"owner/safe@" + current:   verifiedEvidence("owner/safe", current, current),
			"owner/unsafe@" + current: {Status: "unverified", Repository: "owner/unsafe", SHA: current, Reason: "orphan commit"},
		},
	}
	previous := newVerifiedUpgradeResolver
	newVerifiedUpgradeResolver = func() provenanceUpgradeResolver { return resolver }
	t.Cleanup(func() { newVerifiedUpgradeResolver = previous })
	err := UpgradePinnedSHAsWithOptions(FilePath(repo), 24, false, VerificationOptions{VerifyProvenance: true})
	if err == nil || !strings.Contains(err.Error(), "orphan commit") {
		t.Fatalf("unsafe repository upgrade error = %v", err)
	}
	for file, want := range map[string]string{first: firstContent, second: secondContent} {
		data, err := os.ReadFile(file)
		if err != nil || string(data) != want {
			t.Fatalf("workflow changed before verification finished: %s, %v", data, err)
		}
	}
}

func TestDefaultUpgradeDoesNotConstructProvenanceResolver(t *testing.T) {
	repo := t.TempDir()
	initGitRepo(t, repo)
	current := strings.Repeat("a", 40)
	next := strings.Repeat("b", 40)
	file := writeWorkflow(t, repo, "jobs:\n  test:\n    steps:\n      - uses: owner/repo@"+current+" # v1\n")
	previous, previousVerified := newUpgradeResolver, newVerifiedUpgradeResolver
	newUpgradeResolver = func() upgradeResolver {
		return fakeUpgradeResolver{results: map[string]*network.UpgradeResult{"owner/repo@v1": {NextVersion: "v2", NextSHA: next}}}
	}
	newVerifiedUpgradeResolver = func() provenanceUpgradeResolver {
		t.Fatal("default upgrade constructed provenance resolver")
		return nil
	}
	t.Cleanup(func() { newUpgradeResolver, newVerifiedUpgradeResolver = previous, previousVerified })
	if err := UpgradePinnedSHAs(FilePath(repo), 24, false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil || !strings.Contains(string(data), "owner/repo@"+next+" # v2") {
		t.Fatalf("default upgrade behavior changed: %s, %v", data, err)
	}
}

func TestUnverifiedMutableReferenceHasNoSARIFEdit(t *testing.T) {
	sha := strings.Repeat("a", 40)
	finding := ReferenceFinding{
		FilePath: "/repo/ci.yml", Line: 4, Column: 15, Repository: "owner/repo", Ref: "v1", Original: "owner/repo@v1",
		SourceText: "owner/repo@v1", Editable: true, FixSHA: sha,
		Provenance: &network.ProvenanceEvidence{Status: "unverified", Repository: "owner/repo", SHA: sha},
	}
	report, err := EvaluatePolicy("/repo", &AuditResult{Status: ScanStatusFindings, Complete: true, Details: []ReferenceFinding{finding}}, DefaultPolicy(), PolicyEvaluationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := WriteSARIF(&output, report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), `"fixes"`) {
		t.Fatalf("unverified candidate offered automatic edit: %s", output.String())
	}
}
