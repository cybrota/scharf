// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const depSHA = "1111111111111111111111111111111111111111"
const childSHA = "2222222222222222222222222222222222222222"

type fakeDependencies struct {
	data     map[string]string
	reads    map[string]int
	resolves int
}

func (f *fakeDependencies) Resolve(s string) (string, error) {
	f.resolves++
	if s == "example/child@v1" {
		return childSHA, nil
	}
	return "", errors.New("unavailable")
}
func (f *fakeDependencies) ReadMetadata(repo, sha, name string) ([]byte, error) {
	key := repo + "@" + sha + ":" + name
	f.reads[key]++
	s, ok := f.data[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return []byte(s), nil
}
func dependencyFixture(t *testing.T, uses string) string {
	t.Helper()
	root := t.TempDir()
	name := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(name, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(name, "ci.yml"), []byte("jobs:\n  test:\n    steps:\n      - uses: "+uses+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return root
}
func dependencyFake() *fakeDependencies {
	return &fakeDependencies{data: map[string]string{}, reads: map[string]int{}}
}
func TestDependencyPinnedWrapperMutableChild(t *testing.T) {
	f := dependencyFake()
	f.data["example/wrapper@"+depSHA+":action.yml"] = "runs:\n  using: composite\n  steps:\n    - uses: example/child@v1\n"
	f.data["example/child@"+childSHA+":action.yml"] = "runs:\n  using: node24\n  main: index.js\n"
	r, err := AuditDependencies(dependencyFixture(t, "example/wrapper@"+depSHA), f, DefaultDependencyLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Edges) != 2 || !r.Edges[1].Mutable || len(r.Edges[1].Chain) != 2 || r.Edges[1].Commit != childSHA || r.Status != ScanStatusFindings {
		t.Fatalf("%+v", r)
	}
	for _, format := range []string{"json", "sarif"} {
		var b bytes.Buffer
		if err := WriteDependencyReport(&b, r, format); err != nil {
			t.Fatal(err)
		}
		var v any
		if err := json.Unmarshal(b.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(b.String(), "chain") {
			t.Fatal("provenance lost")
		}
	}
}
func TestDependencyRepeatedCallersAndYAMLFallback(t *testing.T) {
	root := dependencyFixture(t, "example/wrapper@"+depSHA)
	file := filepath.Join(root, ".github/workflows/ci.yml")
	b, _ := os.ReadFile(file)
	b = append(b, []byte("      - uses: example/wrapper@"+depSHA+"\n")...)
	os.WriteFile(file, b, 0600)
	f := dependencyFake()
	f.data["example/wrapper@"+depSHA+":action.yaml"] = "runs: {using: node24, main: index.js}"
	r, err := AuditDependencies(root, f, DefaultDependencyLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Edges) != 2 || r.Edges[0].Chain[0].Line == r.Edges[1].Chain[0].Line || f.reads["example/wrapper@"+depSHA+":action.yaml"] != 1 || r.Status != ScanStatusClean {
		t.Fatalf("%+v %+v", r, f.reads)
	}
}
func TestDependencyIncompleteContexts(t *testing.T) {
	for _, tc := range []struct{ name, uses, metadata string }{
		{"workspace", "example/wrapper@" + depSHA, "runs:\n  using: composite\n  steps:\n    - uses: ./child\n"},
		{"cycle", "example/wrapper@" + depSHA, "runs:\n  using: composite\n  steps:\n    - uses: example/wrapper@" + depSHA + "\n"},
		{"missing", "example/wrapper@" + depSHA, ""},
		{"dynamic", "${{ inputs.action }}", ""},
		{"boundary", "./../outside", ""},
		{"merge", "example/wrapper@" + depSHA, "runs:\n  using: composite\n  steps:\n    - <<: {uses: example/child@v1}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := dependencyFake()
			if tc.metadata != "" {
				f.data["example/wrapper@"+depSHA+":action.yml"] = tc.metadata
			}
			r, err := AuditDependencies(dependencyFixture(t, tc.uses), f, DefaultDependencyLimits())
			if err == nil || r.Complete || r.Status != ScanStatusIncomplete {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
}
func TestDependencySelfRepositoryAndSubpath(t *testing.T) {
	f := dependencyFake()
	f.data["example/wrapper@"+depSHA+":nested/action.yml"] = "runs:\n  using: composite\n  steps:\n    - uses: $/child\n"
	f.data["example/wrapper@"+depSHA+":child/action.yml"] = "runs: {using: node24, main: index.js}"
	r, err := AuditDependencies(dependencyFixture(t, "example/wrapper/nested@"+depSHA), f, DefaultDependencyLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Edges) != 2 || r.Edges[1].Commit != depSHA || r.Edges[1].Mutable {
		t.Fatalf("%+v", r)
	}
}
func TestDependencyBudgets(t *testing.T) {
	for _, limits := range []DependencyLimits{{1, 10, 10000}, {10, 1, 10000}, {10, 10, 10}} {
		f := dependencyFake()
		f.data["example/wrapper@"+depSHA+":action.yml"] = "runs:\n  using: composite\n  steps:\n    - uses: example/child@v1\n"
		f.data["example/child@"+childSHA+":action.yml"] = "runs: {using: node24, main: index.js}"
		r, err := AuditDependencies(dependencyFixture(t, "example/wrapper@"+depSHA), f, limits)
		if err == nil || r.Complete {
			t.Fatalf("limits %+v: %+v", limits, r)
		}
	}
}
func TestDependencyLocalReusableWorkflow(t *testing.T) {
	root := dependencyFixture(t, "./local")
	os.WriteFile(filepath.Join(root, ".github/workflows/ci.yml"), []byte("jobs:\n  call:\n    uses: ./.github/workflows/reuse.yml\n"), 0600)
	os.WriteFile(filepath.Join(root, ".github/workflows/reuse.yml"), []byte("jobs:\n  test:\n    steps:\n      - run: echo safe\n"), 0600)
	r, err := AuditDependencies(root, dependencyFake(), DefaultDependencyLimits())
	if err != nil || !r.Complete || len(r.Edges) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
}
func TestDependencySymlinkEscape(t *testing.T) {
	root := dependencyFixture(t, "./escape")
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "action.yml"), []byte("runs: {using: node24}"), 0600)
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skip(err)
	}
	r, err := AuditDependencies(root, dependencyFake(), DefaultDependencyLimits())
	if err == nil || r.Complete {
		t.Fatal("escaped repository")
	}
}
func TestDependencyAliasRuntimeAndSteps(t *testing.T) {
	f := dependencyFake()
	f.data["example/wrapper@"+depSHA+":action.yml"] = "kind: &kind composite\nchild: &child\n  uses: example/child@v1\nruns:\n  using: *kind\n  steps:\n    - *child\n"
	f.data["example/child@"+childSHA+":action.yml"] = "runs: {using: node24, main: index.js}"
	r, err := AuditDependencies(dependencyFixture(t, "example/wrapper@"+depSHA), f, DefaultDependencyLimits())
	if err != nil || len(r.Edges) != 2 || !r.Edges[1].Mutable {
		t.Fatalf("%+v %v", r, err)
	}
}
func TestDependencyInvalidMetadataNeverClean(t *testing.T) {
	for _, metadata := range []string{"runs: {using: imaginary}", "runs: {using: composite, steps: [], steps: []}", "runs: {using: node24}\n<<: {runs: {using: composite}}", "runs: {using: true}", "runs: {using: node24}\n---\nruns: {using: composite}"} {
		f := dependencyFake()
		f.data["example/wrapper@"+depSHA+":action.yml"] = metadata
		r, err := AuditDependencies(dependencyFixture(t, "example/wrapper@"+depSHA), f, DefaultDependencyLimits())
		if err == nil || r.Complete {
			t.Fatalf("accepted %s: %+v", metadata, r)
		}
	}
}
func TestDependencyCollectionAliasCallerLocations(t *testing.T) {
	for _, doc := range []string{
		"jobs:\n  first: &job\n    steps:\n      - uses: example/child@v1\n  second: *job\n",
		"jobs:\n  first:\n    steps: &steps\n      - uses: example/child@v1\n  second:\n    steps: *steps\n",
		"jobs:\n  first:\n    steps:\n      - &step {uses: example/child@v1}\n      - *step\n",
	} {
		root := dependencyFixture(t, "unused")
		os.WriteFile(filepath.Join(root, ".github/workflows/ci.yml"), []byte(doc), 0600)
		f := dependencyFake()
		f.data["example/child@"+childSHA+":action.yml"] = "runs: {using: node24}"
		r, err := AuditDependencies(root, f, DefaultDependencyLimits())
		if err != nil || len(r.Edges) != 2 {
			t.Fatalf("%+v %v", r, err)
		}
		if r.Edges[0].Chain[0].Line == r.Edges[1].Chain[0].Line {
			t.Fatal("lost alias caller")
		}
	}
}
func TestDependencySelfReferenceCannotOverrideCommit(t *testing.T) {
	root := dependencyFixture(t, "$/action@v1")
	os.Mkdir(filepath.Join(root, "action@v1"), 0700)
	os.WriteFile(filepath.Join(root, "action@v1/action.yml"), []byte("runs: {using: node24}"), 0600)
	r, err := AuditDependencies(root, dependencyFake(), DefaultDependencyLimits())
	if err == nil || r.Complete {
		t.Fatal("accepted invalid self ref")
	}
}
func TestDependencyRemoteReusableWorkflow(t *testing.T) {
	root := dependencyFixture(t, "unused")
	os.WriteFile(filepath.Join(root, ".github/workflows/ci.yml"), []byte("jobs:\n  call:\n    uses: example/reusable/.github/workflows/build.yml@"+depSHA+"\n"), 0600)
	f := dependencyFake()
	f.data["example/reusable@"+depSHA+":.github/workflows/build.yml"] = "jobs:\n  call:\n    uses: ./.github/workflows/child.yml\n"
	f.data["example/reusable@"+depSHA+":.github/workflows/child.yml"] = "jobs:\n  test:\n    steps:\n      - uses: example/child@v1\n"
	f.data["example/child@"+childSHA+":action.yml"] = "runs: {using: node24}"
	r, err := AuditDependencies(root, f, DefaultDependencyLimits())
	if err != nil || len(r.Edges) != 3 || len(r.Edges[2].Chain) != 3 || r.Edges[1].Commit != depSHA {
		t.Fatalf("%+v %v", r, err)
	}
}
func TestDependencyWorkflowSymlinkNeverIgnored(t *testing.T) {
	root := dependencyFixture(t, "unused")
	os.Remove(filepath.Join(root, ".github/workflows/ci.yml"))
	outside := filepath.Join(t.TempDir(), "outside.yml")
	os.WriteFile(outside, []byte("jobs: {}"), 0600)
	if err := os.Symlink(outside, filepath.Join(root, ".github/workflows/ci.yml")); err != nil {
		t.Skip(err)
	}
	r, err := AuditDependencies(root, dependencyFake(), DefaultDependencyLimits())
	if err == nil || r.Complete {
		t.Fatal("silently ignored symlink workflow")
	}
}
func TestDependencyIncompleteMachineReports(t *testing.T) {
	r, err := AuditDependencies(dependencyFixture(t, "example/missing@"+depSHA), dependencyFake(), DefaultDependencyLimits())
	if err == nil {
		t.Fatal("expected incomplete")
	}
	for _, format := range []string{"json", "sarif"} {
		var out bytes.Buffer
		WriteDependencyReport(&out, r, format)
		var data map[string]any
		if err := json.Unmarshal(out.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		if format == "json" && data["complete"] != false {
			t.Fatal(data)
		}
		if format == "sarif" {
			runs := data["runs"].([]any)
			run := runs[0].(map[string]any)
			inv := run["invocations"].([]any)[0].(map[string]any)
			if inv["executionSuccessful"] != false {
				t.Fatal(inv)
			}
		}
	}
}
func TestDependencyMutableResolutionCached(t *testing.T) {
	root := dependencyFixture(t, "example/child@v1")
	file := filepath.Join(root, ".github/workflows/ci.yml")
	b, _ := os.ReadFile(file)
	os.WriteFile(file, append(b, []byte("      - uses: example/child@v1\n")...), 0600)
	f := dependencyFake()
	f.data["example/child@"+childSHA+":action.yml"] = "runs: {using: node24}"
	r, err := AuditDependencies(root, f, DefaultDependencyLimits())
	if err != nil || len(r.Edges) != 2 || f.resolves != 1 {
		t.Fatalf("%+v %d %v", r, f.resolves, err)
	}
}
func TestDependencyNonStringKeysIncomplete(t *testing.T) {
	for _, doc := range []string{"jobs:\n  test:\n    steps:\n      - true: value\n", "key: &key uses\njobs:\n  test:\n    steps:\n      - *key: example/child@v1\n"} {
		root := dependencyFixture(t, "unused")
		os.WriteFile(filepath.Join(root, ".github/workflows/ci.yml"), []byte(doc), 0600)
		r, err := AuditDependencies(root, dependencyFake(), DefaultDependencyLimits())
		if err == nil || r.Complete {
			t.Fatal("unsupported mapping key silently ignored")
		}
	}
}

func TestDependencyHumanEscapesUntrustedControlCharacters(t *testing.T) {
	r := &DependencyReport{Status: ScanStatusIncomplete, Edges: []DependencyEdge{{Chain: []DependencyLocation{{File: "file\n::error::injected", Line: 1, Uses: "action\n::add-mask::injected\x1b[31m"}}, Status: "unresolved-reference"}}, Errors: []ScanError{{Message: "error\n::error::injected\x1b"}}}
	var out bytes.Buffer
	if err := WriteDependencyReport(&out, r, "human"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\n::") || strings.Contains(out.String(), "\x1b") {
		t.Fatalf("unescaped controls: %q", out.String())
	}
}
