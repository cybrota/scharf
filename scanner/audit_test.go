// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"io"
	"os"
	"path/filepath"
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
		t.Fatalf("expected uppercase SHA to be rejected")
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
