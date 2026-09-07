// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cybrota/scharf/network"
	gitlib "github.com/go-git/go-git/v5"
)

type fakeUpgradeResolver struct {
	results map[string]*network.UpgradeResult
	errors  map[string]error
	tags    map[string][]network.BranchOrTag
}

type fakeAuditResolver map[string]string

func (f fakeAuditResolver) Resolve(action string) (string, error) {
	sha, ok := f[action]
	if !ok {
		return "", fmt.Errorf("unresolved %s", action)
	}
	return sha, nil
}

func (f fakeUpgradeResolver) ResolveNext(action string, currentVersion string, cooldownHours int) (*network.UpgradeResult, error) {
	key := action + "@" + currentVersion
	if err, ok := f.errors[key]; ok {
		return nil, err
	}
	if r, ok := f.results[key]; ok {
		return r, nil
	}
	return nil, nil
}

func (f fakeUpgradeResolver) ListTags(action string) ([]network.BranchOrTag, error) {
	if tags, ok := f.tags[action]; ok {
		return tags, nil
	}
	return []network.BranchOrTag{}, nil
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating stdout pipe: %v", err)
	}
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = orig
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading captured stdout: %v", err)
	}

	return string(data)
}

func writeWorkflow(t *testing.T, repo string, content string) string {
	t.Helper()
	workflowDir := filepath.Join(repo, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("creating workflow directory: %v", err)
	}
	file := filepath.Join(workflowDir, "ci.yml")
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatalf("writing workflow file: %v", err)
	}
	return file
}

func initGitRepo(t *testing.T, path string) {
	t.Helper()
	if _, err := gitlib.PlainInit(path, false); err != nil {
		t.Fatalf("initializing git repo: %v", err)
	}
}

func TestScanWorkflowUsesNodesOnly(t *testing.T) {
	content := []byte(strings.Join([]string{
		"name: scanner coverage",
		"env:",
		"  MESSAGE: owner/ignored@main",
		"uses: owner/ignored@main",
		"# uses: owner/commented@main",
		"jobs:",
		"  reusable:",
		"    uses: owner/automation/.github/workflows/release.yml@release/2026",
		"  invalid-reusable:",
		"    uses: owner/ignored@main",
		"  build:",
		"    env:",
		"      uses: owner/ignored@feature-x",
		"    steps:",
		"      - uses: actions/checkout@v4",
		"      - uses: \"owner/action/path@feature-x\" # retained",
		"      - uses: 'owner/beta@v1-beta.2'",
		"      - uses: ./local-action",
		"      - uses: docker://alpine:3.20",
		"      - uses: \"owner/dynamic@${{ inputs.ref }}\"",
		"      - run: \"echo 'uses: owner/string@main'\"",
	}, "\n"))

	findings, err := ScanWorkflow(content, "ci.yml")
	if err != nil {
		t.Fatalf("ScanWorkflow returned error: %v", err)
	}
	if len(findings) != 4 {
		t.Fatalf("got %d findings, want 4: %#v", len(findings), findings)
	}

	want := []struct {
		repository string
		subpath    string
		ref        string
	}{
		{"owner/automation", ".github/workflows/release.yml", "release/2026"},
		{"actions/checkout", "", "v4"},
		{"owner/action", "path", "feature-x"},
		{"owner/beta", "", "v1-beta.2"},
	}
	for i, expected := range want {
		finding := findings[i]
		if finding.Repository != expected.repository || finding.Subpath != expected.subpath || finding.Ref != expected.ref {
			t.Errorf("finding %d = %s subpath=%q ref=%q; want %s subpath=%q ref=%q", i, finding.Repository, finding.Subpath, finding.Ref, expected.repository, expected.subpath, expected.ref)
		}
		if finding.FilePath != "ci.yml" {
			t.Errorf("finding %d file = %q, want ci.yml", i, finding.FilePath)
		}
		if got := string(content[finding.StartOffset:finding.EndOffset]); got != finding.Original {
			t.Errorf("finding %d span = %q, want %q", i, got, finding.Original)
		}
	}
	if findings[1].Line != 15 || findings[1].Column != 15 {
		t.Fatalf("unquoted step location = %d:%d, want 15:15", findings[1].Line, findings[1].Column)
	}
}

func TestScanWorkflowPinnedSHAsAreCaseInsensitive(t *testing.T) {
	content := []byte(strings.Join([]string{
		"jobs:",
		"  test:",
		"    steps:",
		"      - uses: owner/lower@abcdef0123456789abcdef0123456789abcdef01",
		"      - uses: owner/upper@ABCDEF0123456789ABCDEF0123456789ABCDEF01",
	}, "\n"))

	findings, err := ScanWorkflow(content, "pins.yaml")
	if err != nil {
		t.Fatalf("ScanWorkflow returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d mutable findings for full SHAs: %#v", len(findings), findings)
	}
}

func TestScanWorkflowIgnoresMalformedExternalReferences(t *testing.T) {
	content := []byte(strings.Join([]string{
		"jobs:",
		"  test:",
		"    steps:",
		"      - uses: missing-repository@v1",
		"      - uses: owner/repo@",
		"      - uses: owner/repo@bad..ref",
		"      - uses: https://github.com/owner/repo@v1",
	}, "\n"))

	findings, err := ScanWorkflow(content, "malformed-refs.yml")
	if err != nil {
		t.Fatalf("ScanWorkflow returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got malformed references as findings: %#v", findings)
	}
}

func TestScanWorkflowReportsExactQuotedLocation(t *testing.T) {
	content := []byte("jobs:\n  build:\n    steps:\n      - name: test\n        uses: \"owner/repo/path@release/2026\" # comment\n")

	findings, err := ScanWorkflow(content, "ci.yml")
	if err != nil {
		t.Fatalf("ScanWorkflow returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Line != 5 || finding.Column != 16 {
		t.Fatalf("location = %d:%d, want 5:16", finding.Line, finding.Column)
	}
	if got := string(content[finding.StartOffset:finding.EndOffset]); got != "owner/repo/path@release/2026" {
		t.Fatalf("span = %q", got)
	}
	if content[finding.ScalarEndOffset-1] != '"' {
		t.Fatalf("scalar end does not preserve closing quote")
	}
}

func TestScanWorkflowMalformedYAMLReturnsContextualError(t *testing.T) {
	_, err := ScanWorkflow([]byte("jobs:\n  build: [\n"), "broken.yml")
	if err == nil {
		t.Fatal("expected malformed YAML error")
	}
	if !strings.Contains(err.Error(), "broken.yml") {
		t.Fatalf("error %q does not contain file context", err)
	}
}

func TestAuditRepositoryDoesNotFalseCleanUnsupportedScalarForms(t *testing.T) {
	tests := []struct {
		name       string
		workflow   string
		incomplete bool
		editable   bool
	}{
		{
			name: "alias",
			workflow: "shared: &shared owner/repo@feature-x\n" +
				"jobs:\n  test:\n    steps:\n      - uses: *shared\n",
			incomplete: true,
		},
		{
			name: "aliased step mapping",
			workflow: "shared: &shared\n  uses: owner/repo@feature-x\n" +
				"jobs:\n  test:\n    steps:\n      - *shared\n",
			incomplete: true,
		},
		{
			name: "aliased steps sequence",
			workflow: "shared: &shared\n  - uses: owner/repo@feature-x\n" +
				"jobs:\n  test:\n    steps: *shared\n",
			incomplete: true,
		},
		{
			name: "aliased jobs mapping",
			workflow: "shared: &shared\n  test:\n    steps:\n      - uses: owner/repo@feature-x\n" +
				"jobs: *shared\n",
			incomplete: true,
		},
		{
			name:       "anchor",
			workflow:   "jobs:\n  test:\n    steps:\n      - uses: &shared owner/repo@feature-x\n",
			incomplete: true,
		},
		{
			name:       "block scalar",
			workflow:   "jobs:\n  test:\n    steps:\n      - uses: |-\n          owner/repo@feature-x\n",
			incomplete: true,
		},
		{
			name:     "escaped double quoted scalar",
			workflow: "jobs:\n  test:\n    steps:\n      - uses: \"owner/repo@feature\\u002dx\"\n",
			editable: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := t.TempDir()
			initGitRepo(t, repo)
			writeWorkflow(t, repo, tc.workflow)
			originalResolver := newAuditResolver
			newAuditResolver = func() network.Resolver {
				return fakeAuditResolver{"owner/repo@feature-x": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
			}
			t.Cleanup(func() { newAuditResolver = originalResolver })

			result, err := AuditRepositoryResult(FilePath(repo))
			if result.Status == ScanStatusClean {
				t.Fatalf("unsupported external uses produced a clean result: %#v", result)
			}
			if len(result.Workflows) != 1 || len(result.Details) != 1 {
				t.Fatalf("semantic finding was not retained: %#v", result)
			}
			if result.Details[0].Editable != tc.editable {
				t.Fatalf("editable = %v, want %v", result.Details[0].Editable, tc.editable)
			}
			if tc.incomplete {
				if err == nil || result.Status != ScanStatusIncomplete || !strings.Contains(err.Error(), "line") {
					t.Fatalf("result=%#v err=%v; want contextual incomplete result", result, err)
				}
			} else if err != nil || result.Status != ScanStatusFindings {
				t.Fatalf("result=%#v err=%v; want complete findings", result, err)
			}
		})
	}
}

func TestEscapedQuotedScalarAutofixUsesExactSourceSpan(t *testing.T) {
	content := "jobs:\n  test:\n    steps:\n      - uses: \"owner/repo@feature\\u002dx\" # keep\n"
	file := filepath.Join(t.TempDir(), "escaped.yml")
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatalf("writing workflow: %v", err)
	}
	analysis, err := AnalyzeWorkflow(
		fakeAuditResolver{"owner/repo@feature-x": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		[]byte(content),
		"escaped.yml",
		file,
	)
	if err != nil {
		t.Fatalf("AnalyzeWorkflow returned error: %v", err)
	}
	if got := analysis.Findings[0].SourceText; got != `owner/repo@feature\u002dx` {
		t.Fatalf("source text = %q", got)
	}
	if err := ApplyReferenceFixesInFile(file, analysis.Findings, false); err != nil {
		t.Fatalf("ApplyReferenceFixesInFile returned error: %v", err)
	}
	updated, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("reading workflow: %v", err)
	}
	want := "uses: \"owner/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" # feature-x # keep"
	if !strings.Contains(string(updated), want) {
		t.Fatalf("updated workflow = %q, want containing %q", updated, want)
	}
}

func TestQuotedTargetAutofixEscapesReplacement(t *testing.T) {
	tests := []struct {
		name     string
		workflow string
		want     string
	}{
		{
			name:     "single quoted apostrophe",
			workflow: "jobs:\n  test:\n    steps:\n      - uses: 'owner/repo/it''s@v1'\n",
			want:     "uses: 'owner/repo/it''s@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' # v1",
		},
		{
			name:     "double quoted quote escape",
			workflow: "jobs:\n  test:\n    steps:\n      - uses: \"owner/repo/path\\u0022name@v1\"\n",
			want:     "uses: \"owner/repo/path\\\"name@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" # v1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "quoted.yml")
			if err := os.WriteFile(file, []byte(tc.workflow), 0o644); err != nil {
				t.Fatalf("writing workflow: %v", err)
			}
			analysis, err := AnalyzeWorkflow(
				fakeAuditResolver{"owner/repo@v1": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
				[]byte(tc.workflow),
				"quoted.yml",
				file,
			)
			if err != nil {
				t.Fatalf("AnalyzeWorkflow returned error: %v", err)
			}
			if err := ApplyReferenceFixesInFile(file, analysis.Findings, false); err != nil {
				t.Fatalf("ApplyReferenceFixesInFile returned error: %v", err)
			}
			updated, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("reading workflow: %v", err)
			}
			if !strings.Contains(string(updated), tc.want) {
				t.Fatalf("updated workflow = %q, want containing %q", updated, tc.want)
			}
			if _, err := ScanWorkflowReferences(updated, file); err != nil {
				t.Fatalf("updated workflow is invalid: %v", err)
			}
		})
	}
}

func TestApplyReferenceFixesDryRunAndStaleSpan(t *testing.T) {
	content := "jobs:\n  test:\n    steps:\n      - uses: owner/repo@feature-x\n"
	resolver := fakeAuditResolver{"owner/repo@feature-x": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}

	t.Run("dry run", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "dry.yml")
		if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
			t.Fatalf("writing workflow: %v", err)
		}
		analysis, err := AnalyzeWorkflow(resolver, []byte(content), "dry.yml", file)
		if err != nil {
			t.Fatalf("AnalyzeWorkflow returned error: %v", err)
		}
		if err := ApplyReferenceFixesInFile(file, analysis.Findings, true); err != nil {
			t.Fatalf("dry-run fix returned error: %v", err)
		}
		got, _ := os.ReadFile(file)
		if string(got) != content {
			t.Fatalf("dry run changed file: %q", got)
		}
	})

	t.Run("stale span", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "stale.yml")
		if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
			t.Fatalf("writing workflow: %v", err)
		}
		analysis, err := AnalyzeWorkflow(resolver, []byte(content), "stale.yml", file)
		if err != nil {
			t.Fatalf("AnalyzeWorkflow returned error: %v", err)
		}
		changed := strings.Replace(content, "feature-x", "feature-y", 1)
		if err := os.WriteFile(file, []byte(changed), 0o644); err != nil {
			t.Fatalf("changing workflow: %v", err)
		}
		if err := ApplyReferenceFixesInFile(file, analysis.Findings, false); err == nil {
			t.Fatal("expected stale span error")
		}
		got, _ := os.ReadFile(file)
		if string(got) != changed {
			t.Fatalf("stale-span failure changed file: %q", got)
		}
	})
}

func TestFlowStyleReferencesRemainBareAndIndependent(t *testing.T) {
	content := "jobs: {build: {steps: [{uses: owner/one@v1}, {uses: owner/two@v2}, {name: \"# later\"}]}} # existing\n"
	file := filepath.Join(t.TempDir(), "flow.yml")
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatalf("writing workflow: %v", err)
	}
	analysis, err := AnalyzeWorkflow(fakeAuditResolver{
		"owner/one@v1": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"owner/two@v2": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}, []byte(content), "flow.yml", file)
	if err != nil {
		t.Fatalf("AnalyzeWorkflow returned error: %v", err)
	}
	if err := ApplyReferenceFixesInFile(file, analysis.Findings, false); err != nil {
		t.Fatalf("ApplyReferenceFixesInFile returned error: %v", err)
	}
	pinnedContent, _ := os.ReadFile(file)
	if strings.Contains(string(pinnedContent), "# v1") || strings.Contains(string(pinnedContent), "# v2") {
		t.Fatalf("flow references received ambiguous hints: %s", pinnedContent)
	}
	if !strings.Contains(string(pinnedContent), `name: "# later"`) {
		t.Fatalf("later quoted hash field changed: %s", pinnedContent)
	}

	resolver := fakeUpgradeResolver{
		tags: map[string][]network.BranchOrTag{
			"owner/one": {{Name: "v1", Commit: network.Commit{Sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}},
			"owner/two": {{Name: "v2", Commit: network.Commit{Sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}},
		},
		results: map[string]*network.UpgradeResult{
			"owner/one@v1": {NextVersion: "v1.1", NextSHA: "cccccccccccccccccccccccccccccccccccccccc"},
			"owner/two@v2": {NextVersion: "v2.1", NextSHA: "dddddddddddddddddddddddddddddddddddddddd"},
		},
	}
	upgraded, changed, err := upgradePinnedSHAsInContent(pinnedContent, file, resolver, 24, false)
	if err != nil || !changed {
		t.Fatalf("upgrade result changed=%v err=%v", changed, err)
	}
	if !strings.Contains(string(upgraded), "owner/one@cccccccccccccccccccccccccccccccccccccccc") ||
		!strings.Contains(string(upgraded), "owner/two@dddddddddddddddddddddddddddddddddddddddd") {
		t.Fatalf("flow references did not upgrade independently: %s", upgraded)
	}
	if strings.Contains(string(upgraded), "# v1.1") || strings.Contains(string(upgraded), "# v2.1") {
		t.Fatalf("flow upgrade added ambiguous hints: %s", upgraded)
	}
}

func TestApplyFixesPreservesYAMLAndEditsOnlyReferences(t *testing.T) {
	content := strings.Join([]string{
		"jobs:",
		"  deploy:",
		"    uses: owner/workflows/.github/workflows/deploy.yml@stable",
		"  build:",
		"    steps:",
		"      - uses: \"owner/repo/path@release/2026\" # keep this comment",
		"      - uses: 'other/action@feature-x'",
		"      - run: echo owner/repo/path@release/2026",
	}, "\n") + "\n"
	file := filepath.Join(t.TempDir(), "ci.yml")
	if err := os.WriteFile(file, []byte(content), 0o640); err != nil {
		t.Fatalf("writing workflow: %v", err)
	}
	resolver := fakeAuditResolver{
		"owner/repo@release/2026": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"other/action@feature-x":  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"owner/workflows@stable":  "cccccccccccccccccccccccccccccccccccccccc",
	}
	analysis, err := AnalyzeWorkflow(resolver, []byte(content), "ci.yml", file)
	if err != nil {
		t.Fatalf("AssembleWorkflow returned error: %v", err)
	}
	if analysis.Workflow.Name != file {
		t.Fatalf("legacy workflow name = %q, want file path %q", analysis.Workflow.Name, file)
	}
	if err := ApplyReferenceFixesInFile(file, analysis.Findings, false); err != nil {
		t.Fatalf("ApplyReferenceFixesInFile returned error: %v", err)
	}

	updated, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("reading updated workflow: %v", err)
	}
	want := strings.Join([]string{
		"jobs:",
		"  deploy:",
		"    uses: owner/workflows/.github/workflows/deploy.yml@cccccccccccccccccccccccccccccccccccccccc # stable",
		"  build:",
		"    steps:",
		"      - uses: \"owner/repo/path@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" # release/2026 # keep this comment",
		"      - uses: 'other/action@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' # feature-x",
		"      - run: echo owner/repo/path@release/2026",
	}, "\n") + "\n"
	if string(updated) != want {
		t.Fatalf("updated workflow:\n%s\nwant:\n%s", updated, want)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatalf("stat updated workflow: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %o, want 640", info.Mode().Perm())
	}
}

func TestApplyFixesPreservesFlowStyleYAML(t *testing.T) {
	content := "jobs: {build: {steps: [{uses: \"owner/repo@feature-x\", name: \"# test\"}]}} # keep\n"
	file := filepath.Join(t.TempDir(), "flow.yml")
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatalf("writing workflow: %v", err)
	}
	analysis, err := AnalyzeWorkflow(
		fakeAuditResolver{"owner/repo@feature-x": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		[]byte(content),
		"flow.yml",
		file,
	)
	if err != nil {
		t.Fatalf("AssembleWorkflow returned error: %v", err)
	}
	if err := ApplyReferenceFixesInFile(file, analysis.Findings, false); err != nil {
		t.Fatalf("ApplyReferenceFixesInFile returned error: %v", err)
	}
	updated, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("reading workflow: %v", err)
	}
	want := "jobs: {build: {steps: [{uses: \"owner/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", name: \"# test\"}]}} # keep\n"
	if string(updated) != want {
		t.Fatalf("updated workflow = %q, want %q", updated, want)
	}
	if _, err := ScanWorkflow(updated, file); err != nil {
		t.Fatalf("updated flow-style workflow is invalid: %v", err)
	}
	if pinned := CollectPinnedRefs(updated); len(pinned) != 0 {
		t.Fatalf("non-terminal flow scalar received an ambiguous version hint: %#v", pinned)
	}
}

func TestAuditRepositoryOutcomes(t *testing.T) {
	t.Run("missing workflow directory is complete clean", func(t *testing.T) {
		repo := t.TempDir()
		initGitRepo(t, repo)

		result, err := AuditRepositoryResult(FilePath(repo))
		if err != nil {
			t.Fatalf("AuditRepository returned error: %v", err)
		}
		if result.Status != ScanStatusClean || !result.Complete {
			t.Fatalf("result = status %q complete=%v", result.Status, result.Complete)
		}
	})

	t.Run("findings are complete", func(t *testing.T) {
		repo := t.TempDir()
		initGitRepo(t, repo)
		writeWorkflow(t, repo, "jobs:\n  test:\n    steps:\n      - uses: owner/repo@feature-x\n")
		originalResolver := newAuditResolver
		newAuditResolver = func() network.Resolver {
			return fakeAuditResolver{"owner/repo@feature-x": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
		}
		t.Cleanup(func() { newAuditResolver = originalResolver })

		result, err := AuditRepositoryResult(FilePath(repo))
		if err != nil {
			t.Fatalf("AuditRepository returned error: %v", err)
		}
		if result.Status != ScanStatusFindings || !result.Complete || len(result.Workflows) != 1 {
			t.Fatalf("result = %#v", result)
		}
	})

	t.Run("mixed files retain findings and return incomplete", func(t *testing.T) {
		repo := t.TempDir()
		initGitRepo(t, repo)
		valid := writeWorkflow(t, repo, "jobs:\n  test:\n    steps:\n      - uses: owner/repo@feature-x\n")
		broken := filepath.Join(filepath.Dir(valid), "broken.yaml")
		if err := os.WriteFile(broken, []byte("jobs:\n  broken: [\n"), 0o644); err != nil {
			t.Fatalf("writing malformed workflow: %v", err)
		}
		originalResolver := newAuditResolver
		newAuditResolver = func() network.Resolver {
			return fakeAuditResolver{"owner/repo@feature-x": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
		}
		t.Cleanup(func() { newAuditResolver = originalResolver })

		result, err := AuditRepositoryResult(FilePath(repo))
		if err == nil {
			t.Fatal("expected incomplete scan error")
		}
		var incomplete *IncompleteScanError
		if !errors.As(err, &incomplete) {
			t.Fatalf("error type = %T, want *IncompleteScanError", err)
		}
		if result.Status != ScanStatusIncomplete || result.Complete || len(result.Workflows) != 1 || len(result.Errors) != 1 {
			t.Fatalf("result = %#v", result)
		}
		if result.Errors[0].FilePath != broken {
			t.Fatalf("error file = %q, want %q", result.Errors[0].FilePath, broken)
		}
		encoded, marshalErr := json.Marshal(result)
		if marshalErr != nil {
			t.Fatalf("marshal result: %v", marshalErr)
		}
		if !strings.Contains(string(encoded), `"status":"incomplete"`) || !strings.Contains(string(encoded), `"complete":false`) {
			t.Fatalf("JSON does not expose incomplete status: %s", encoded)
		}
	})
}

func TestAuditRepositoryIgnoresNonYAMLAndNonRegularEntries(t *testing.T) {
	repo := t.TempDir()
	initGitRepo(t, repo)
	workflowDir := filepath.Join(repo, ".github", "workflows")
	if err := os.MkdirAll(filepath.Join(workflowDir, "nested.yaml"), 0o755); err != nil {
		t.Fatalf("creating workflow directory entry: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "notes.txt"), []byte("jobs: [\nuses: owner/repo@main"), 0o644); err != nil {
		t.Fatalf("writing non-YAML entry: %v", err)
	}

	result, err := AuditRepositoryResult(FilePath(repo))
	if err != nil {
		t.Fatalf("AuditRepository returned error: %v", err)
	}
	if result.Status != ScanStatusClean {
		t.Fatalf("status = %q, want %q", result.Status, ScanStatusClean)
	}
}

func TestAuditRepositoryUnreadableWorkflowIsIncomplete(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission test")
	}
	repo := t.TempDir()
	initGitRepo(t, repo)
	file := writeWorkflow(t, repo, "jobs: {}\n")
	if err := os.Chmod(file, 0); err != nil {
		t.Fatalf("making workflow unreadable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(file, 0o644) })
	if _, readErr := os.ReadFile(file); readErr == nil {
		t.Skip("current user can read mode-000 files")
	}

	result, err := AuditRepositoryResult(FilePath(repo))
	if err == nil || result.Status != ScanStatusIncomplete || len(result.Errors) != 1 {
		t.Fatalf("result=%#v err=%v; want one incomplete file error", result, err)
	}
	if result.Errors[0].FilePath != file {
		t.Fatalf("error file = %q, want %q", result.Errors[0].FilePath, file)
	}
}

func TestParsePinnedRef(t *testing.T) {
	line := "uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v4"
	got, ok := ParsePinnedRef(line)
	if !ok {
		t.Fatalf("expected parse success")
	}
	if got.Action != "actions/checkout" {
		t.Fatalf("action got %q, want %q", got.Action, "actions/checkout")
	}
	if got.Version != "v4" {
		t.Fatalf("version got %q, want %q", got.Version, "v4")
	}
	if got.SHA != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("sha got %q, want 40-char lowercase sha", got.SHA)
	}

	if _, ok := ParsePinnedRef("uses: actions/checkout@v4"); ok {
		t.Fatalf("expected mutable reference to be rejected")
	}

	if _, ok := ParsePinnedRef("uses: actions/checkout@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA # v4"); ok {
		t.Fatal("legacy parser unexpectedly accepted uppercase SHA")
	}

	if got, ok := ParsePinnedRef("actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # release#1"); !ok || got.Version != "release#1" {
		t.Fatalf("hash-containing version was not preserved: %#v, %v", got, ok)
	}
}

func TestCollectPinnedRefs(t *testing.T) {
	content := []byte(strings.Join([]string{
		"jobs:",
		"  test:",
		"    steps:",
		"      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v4",
		"      - uses: actions/setup-go@v5",
	}, "\n"))

	findings := CollectPinnedRefs(content)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Action != "actions/checkout" {
		t.Fatalf("action got %q, want actions/checkout", findings[0].Action)
	}
	if findings[0].Version != "v4" {
		t.Fatalf("version got %q, want v4", findings[0].Version)
	}
}

func TestUpgradePinnedSHAsDryRun(t *testing.T) {
	tmp := t.TempDir()
	initGitRepo(t, tmp)

	workflow := strings.Join([]string{
		"jobs:",
		"  test:",
		"    steps:",
		"      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v4",
		"      - uses: actions/setup-go@v5",
	}, "\n")
	workflowFile := writeWorkflow(t, tmp, workflow)

	originalResolver := newUpgradeResolver
	newUpgradeResolver = func() upgradeResolver {
		return fakeUpgradeResolver{results: map[string]*network.UpgradeResult{
			"actions/checkout@v4": {
				Action:         "actions/checkout",
				CurrentVersion: "v4",
				CurrentSHA:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				NextVersion:    "v4.1.0",
				NextSHA:        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		}}
	}
	t.Cleanup(func() { newUpgradeResolver = originalResolver })

	output := captureStdout(t, func() {
		if err := UpgradePinnedSHAs(FilePath(tmp), 24, true); err != nil {
			t.Fatalf("UpgradePinnedSHAs returned error: %v", err)
		}
	})

	updated, err := os.ReadFile(workflowFile)
	if err != nil {
		t.Fatalf("reading workflow file: %v", err)
	}
	if !strings.Contains(string(updated), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v4") {
		t.Fatalf("expected file to remain unchanged in dry-run mode")
	}
	if strings.Contains(string(updated), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") {
		t.Fatalf("did not expect upgraded SHA to be written during dry-run")
	}
	if !strings.Contains(output, "Dry-run") {
		t.Fatalf("expected dry-run output, got: %s", output)
	}
	if !strings.Contains(output, "skipped 1 non-Scharf references") {
		t.Fatalf("expected summary info for non-Scharf references, got: %s", output)
	}
	if !strings.Contains(output, "owner/repo@<40hexsha> # <version>") {
		t.Fatalf("expected skip reason with expected format in output, got: %s", output)
	}
}

func TestUpgradePinnedSHAsWritesFileWhenNotDryRun(t *testing.T) {
	tmp := t.TempDir()
	initGitRepo(t, tmp)

	workflow := strings.Join([]string{
		"jobs:",
		"  test:",
		"    steps:",
		"      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v4",
	}, "\n")
	workflowFile := writeWorkflow(t, tmp, workflow)

	originalResolver := newUpgradeResolver
	newUpgradeResolver = func() upgradeResolver {
		return fakeUpgradeResolver{results: map[string]*network.UpgradeResult{
			"actions/checkout@v4": {
				Action:         "actions/checkout",
				CurrentVersion: "v4",
				CurrentSHA:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				NextVersion:    "v4.1.0",
				NextSHA:        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		}}
	}
	t.Cleanup(func() { newUpgradeResolver = originalResolver })

	if err := UpgradePinnedSHAs(FilePath(tmp), 24, false); err != nil {
		t.Fatalf("UpgradePinnedSHAs returned error: %v", err)
	}

	updated, err := os.ReadFile(workflowFile)
	if err != nil {
		t.Fatalf("reading workflow file: %v", err)
	}
	if !strings.Contains(string(updated), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb # v4.1.0") {
		t.Fatalf("expected upgraded pinned reference in file, got: %s", string(updated))
	}
}

func TestUpgradePinnedSHAsPreflightPreventsPartialWrites(t *testing.T) {
	repo := t.TempDir()
	initGitRepo(t, repo)
	workflowDir := filepath.Join(repo, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("creating workflow directory: %v", err)
	}
	valid := "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v4\n"
	validPath := filepath.Join(workflowDir, "a-valid.yml")
	if err := os.WriteFile(validPath, []byte(valid), 0o644); err != nil {
		t.Fatalf("writing valid workflow: %v", err)
	}
	brokenPath := filepath.Join(workflowDir, "z-broken.yml")
	if err := os.WriteFile(brokenPath, []byte("jobs:\n  broken: [\n"), 0o644); err != nil {
		t.Fatalf("writing broken workflow: %v", err)
	}
	originalResolver := newUpgradeResolver
	newUpgradeResolver = func() upgradeResolver {
		return fakeUpgradeResolver{results: map[string]*network.UpgradeResult{
			"actions/checkout@v4": {NextVersion: "v5", NextSHA: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		}}
	}
	t.Cleanup(func() { newUpgradeResolver = originalResolver })

	err := UpgradePinnedSHAs(FilePath(repo), 24, false)
	if err == nil || !strings.Contains(err.Error(), brokenPath) {
		t.Fatalf("error = %v; want malformed file context", err)
	}
	after, readErr := os.ReadFile(validPath)
	if readErr != nil {
		t.Fatalf("reading valid workflow: %v", readErr)
	}
	if string(after) != valid {
		t.Fatalf("valid workflow changed before preflight completed: %s", after)
	}
}

func TestUpgradePinnedSHAsPreservesQuotedSubpathAndComment(t *testing.T) {
	tmp := t.TempDir()
	initGitRepo(t, tmp)

	workflow := strings.Join([]string{
		"jobs:",
		"  test:",
		"    steps:",
		"      - uses: \"owner/repo/path\\u0022name@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" # release#1 # keep",
	}, "\n")
	workflowFile := writeWorkflow(t, tmp, workflow)

	originalResolver := newUpgradeResolver
	newUpgradeResolver = func() upgradeResolver {
		return fakeUpgradeResolver{results: map[string]*network.UpgradeResult{
			"owner/repo@release#1": {
				Action:         "owner/repo",
				CurrentVersion: "release#1",
				CurrentSHA:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				NextVersion:    "v5",
				NextSHA:        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		}}
	}
	t.Cleanup(func() { newUpgradeResolver = originalResolver })

	if err := UpgradePinnedSHAs(FilePath(tmp), 24, false); err != nil {
		t.Fatalf("UpgradePinnedSHAs returned error: %v", err)
	}
	updated, err := os.ReadFile(workflowFile)
	if err != nil {
		t.Fatalf("reading workflow file: %v", err)
	}
	want := "uses: \"owner/repo/path\\\"name@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\" # v5 # keep"
	if !strings.Contains(string(updated), want) {
		t.Fatalf("updated workflow = %q; want %q", updated, want)
	}
}

func TestUpgradePinnedSHAsCooldownWarningStillUpgrades(t *testing.T) {
	tmp := t.TempDir()
	initGitRepo(t, tmp)

	workflow := strings.Join([]string{
		"jobs:",
		"  test:",
		"    steps:",
		"      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v4",
		"      - uses: actions/cache@cccccccccccccccccccccccccccccccccccccccc # v4",
	}, "\n")
	workflowFile := writeWorkflow(t, tmp, workflow)

	originalResolver := newUpgradeResolver
	newUpgradeResolver = func() upgradeResolver {
		return fakeUpgradeResolver{results: map[string]*network.UpgradeResult{
			"actions/checkout@v4": {
				Action:         "actions/checkout",
				CurrentVersion: "v4",
				CurrentSHA:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				NextVersion:    "v4.1.0",
				NextSHA:        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				UnderCooldown:  true,
			},
			"actions/cache@v4": {
				Action:         "actions/cache",
				CurrentVersion: "v4",
				CurrentSHA:     "cccccccccccccccccccccccccccccccccccccccc",
				NextVersion:    "v4.1.0",
				NextSHA:        "dddddddddddddddddddddddddddddddddddddddd",
			},
		}}
	}
	t.Cleanup(func() { newUpgradeResolver = originalResolver })

	output := captureStdout(t, func() {
		if err := UpgradePinnedSHAs(FilePath(tmp), 24, false); err != nil {
			t.Fatalf("UpgradePinnedSHAs returned error: %v", err)
		}
	})

	updated, err := os.ReadFile(workflowFile)
	if err != nil {
		t.Fatalf("reading workflow file: %v", err)
	}
	if !strings.Contains(string(updated), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb # v4.1.0") {
		t.Fatalf("expected under-cooldown action to still be upgraded")
	}
	if !strings.Contains(string(updated), "dddddddddddddddddddddddddddddddddddddddd # v4.1.0") {
		t.Fatalf("expected non-cooldown action to upgrade")
	}
	if !strings.Contains(output, "under cooldown") {
		t.Fatalf("expected cooldown warning output, got: %s", output)
	}
}

func TestUpgradePinnedSHAsInfersVersionFromBarePinnedSHA(t *testing.T) {
	tmp := t.TempDir()
	initGitRepo(t, tmp)

	workflow := strings.Join([]string{
		"jobs:",
		"  test:",
		"    steps:",
		"      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}, "\n")
	workflowFile := writeWorkflow(t, tmp, workflow)

	originalResolver := newUpgradeResolver
	newUpgradeResolver = func() upgradeResolver {
		return fakeUpgradeResolver{
			results: map[string]*network.UpgradeResult{
				"actions/checkout@v4": {
					Action:         "actions/checkout",
					CurrentVersion: "v4",
					CurrentSHA:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					NextVersion:    "v4.1.0",
					NextSHA:        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				},
			},
			tags: map[string][]network.BranchOrTag{
				"actions/checkout": {
					{Name: "v4", Commit: network.Commit{Sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
				},
			},
		}
	}
	t.Cleanup(func() { newUpgradeResolver = originalResolver })

	if err := UpgradePinnedSHAs(FilePath(tmp), 24, false); err != nil {
		t.Fatalf("UpgradePinnedSHAs returned error: %v", err)
	}

	updated, err := os.ReadFile(workflowFile)
	if err != nil {
		t.Fatalf("reading workflow file: %v", err)
	}
	if !strings.Contains(string(updated), "actions/checkout@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb # v4.1.0") {
		t.Fatalf("expected inferred-version upgrade in file, got: %s", string(updated))
	}
}

func TestUpgradePinnedSHAsSkipsBarePinnedSHAWhenNoTagMatches(t *testing.T) {
	tmp := t.TempDir()
	initGitRepo(t, tmp)

	workflow := strings.Join([]string{
		"jobs:",
		"  test:",
		"    steps:",
		"      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}, "\n")

	writeWorkflow(t, tmp, workflow)

	originalResolver := newUpgradeResolver
	newUpgradeResolver = func() upgradeResolver {
		return fakeUpgradeResolver{tags: map[string][]network.BranchOrTag{
			"actions/checkout": {
				{Name: "v4", Commit: network.Commit{Sha: "cccccccccccccccccccccccccccccccccccccccc"}},
			},
		}}
	}
	t.Cleanup(func() { newUpgradeResolver = originalResolver })

	output := captureStdout(t, func() {
		if err := UpgradePinnedSHAs(FilePath(tmp), 24, false); err != nil {
			t.Fatalf("UpgradePinnedSHAs returned error: %v", err)
		}
	})

	if !strings.Contains(output, "no tag points to pinned SHA") {
		t.Fatalf("expected no-tag skip reason in output, got: %s", output)
	}
}

func TestUpgradePinnedSHAsSkipsBarePinnedSHAWhenAmbiguous(t *testing.T) {
	tmp := t.TempDir()
	initGitRepo(t, tmp)

	workflow := strings.Join([]string{
		"jobs:",
		"  test:",
		"    steps:",
		"      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}, "\n")

	writeWorkflow(t, tmp, workflow)

	originalResolver := newUpgradeResolver
	newUpgradeResolver = func() upgradeResolver {
		return fakeUpgradeResolver{tags: map[string][]network.BranchOrTag{
			"actions/checkout": {
				{Name: "v4", Commit: network.Commit{Sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
				{Name: "v4.0.1", Commit: network.Commit{Sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
			},
		}}
	}
	t.Cleanup(func() { newUpgradeResolver = originalResolver })

	output := captureStdout(t, func() {
		if err := UpgradePinnedSHAs(FilePath(tmp), 24, false); err != nil {
			t.Fatalf("UpgradePinnedSHAs returned error: %v", err)
		}
	})

	if !strings.Contains(output, "ambiguous: multiple tags point to pinned SHA") {
		t.Fatalf("expected ambiguous-tag skip reason in output, got: %s", output)
	}
}
