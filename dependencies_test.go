// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"bytes"
	"errors"
	sc "github.com/cybrota/scharf/scanner"
	"os"
	"path/filepath"
	"testing"
)

func TestDependencyCommand(t *testing.T) {
	old := dependencyAudit
	defer func() { dependencyAudit = old }()
	dependencyAudit = func(string) (*sc.DependencyReport, error) {
		return &sc.DependencyReport{Status: sc.ScanStatusClean, Complete: true}, nil
	}
	for _, format := range []string{"human", "json", "sarif"} {
		cmd := newRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"audit", t.TempDir(), "--dependencies", "--out", format})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		if out.Len() == 0 {
			t.Fatal("empty report")
		}
	}
	cmd := newRootCmd()
	cmd.SetArgs([]string{"audit", t.TempDir(), "--dependencies", "--ignore", "example/action"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("silently ignored policy flag")
	}
}
func TestDependencyCommandRaiseAndIncomplete(t *testing.T) {
	old := dependencyAudit
	defer func() { dependencyAudit = old }()
	dependencyAudit = func(string) (*sc.DependencyReport, error) {
		return &sc.DependencyReport{Status: sc.ScanStatusFindings, Complete: true, Edges: []sc.DependencyEdge{{Mutable: true, Status: "resolved"}}}, nil
	}
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"audit", t.TempDir(), "--dependencies", "--out", "json", "--raise-error"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("mutable edge did not fail")
	}
}

func TestDependencyCommandIncompleteAndOutput(t *testing.T) {
	old := dependencyAudit
	defer func() { dependencyAudit = old }()
	dependencyAudit = func(string) (*sc.DependencyReport, error) {
		return &sc.DependencyReport{Status: sc.ScanStatusIncomplete, Complete: false}, errors.New("fixture incomplete")
	}
	dest := filepath.Join(t.TempDir(), "report.json")
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"audit", t.TempDir(), "--dependencies", "--out", "json", "--output", dest})
	if err := cmd.Execute(); err == nil {
		t.Fatal("incomplete scan succeeded")
	}
	b, err := os.ReadFile(dest)
	if err != nil || !bytes.Contains(b, []byte(`"complete":false`)) {
		t.Fatalf("%s %v", b, err)
	}
}

func TestDependencyCommandRejectsCombinedProvenance(t *testing.T) {
	cmd := newRootCmd()
	audit, _, err := cmd.Find([]string{"audit"})
	if err != nil {
		t.Fatal(err)
	}
	if audit.Flags().Lookup("verify-provenance") == nil {
		audit.Flags().Bool("verify-provenance", false, "fixture for compatible merge")
	}
	cmd.SetArgs([]string{"audit", t.TempDir(), "--dependencies", "--verify-provenance"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("provenance silently ignored")
	}
}
