//go:build !unix

// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import "os"

func openDependencyFile(root *os.Root, name string) (*os.File, error) { return root.Open(name) }
