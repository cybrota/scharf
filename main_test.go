// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"bytes"
	"strings"
	"testing"
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
