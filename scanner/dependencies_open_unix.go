//go:build unix

// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"os"
	"syscall"
)

// O_NONBLOCK prevents a concurrently replaced FIFO from hanging the scan. os.Root
// additionally prevents symlink replacement from escaping the repository boundary.
func openDependencyFile(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
