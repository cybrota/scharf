// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package logging is to provide a uniform logger to other packages

package logging

import (
	"context"
	"log/slog"
	"testing"
)

// --- Tests for Logging ---

func TestGetLoggerDefaultLevel(t *testing.T) {
	logger := GetLogger(0)
	if logger == nil {
		t.Error("Expected logger object, got nil")
	}

	got := logger.Handler().Enabled(context.Background(), slog.LevelInfo)

	if !got {
		t.Errorf("Expected level to be %v, got %v", 0, got)
	}
}

func TestGetLoggerCustomLevel(t *testing.T) {
	customLevel := slog.LevelDebug
	logger := GetLogger(customLevel)
	if logger == nil {
		t.Error("Expected logger object, got nil")
	}
	got := logger.Handler().Enabled(context.Background(), slog.LevelDebug)

	if !got {
		t.Errorf("Expected level to be %v, got %v", 0, got)
	}
}
