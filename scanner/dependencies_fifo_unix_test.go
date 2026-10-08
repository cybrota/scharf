//go:build unix

// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestDependencyRejectsFIFO(t *testing.T) {
	root := dependencyFixture(t, "./local")
	dir := filepath.Join(root, "local")
	os.Mkdir(dir, 0700)
	if err := syscall.Mkfifo(filepath.Join(dir, "action.yml"), 0600); err != nil {
		t.Skip(err)
	}
	r, err := AuditDependencies(root, dependencyFake(), DefaultDependencyLimits())
	if err == nil || r.Complete {
		t.Fatal("accepted FIFO")
	}
}
