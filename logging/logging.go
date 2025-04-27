// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package logging is to provide a uniform logger to other packages

package logging

import (
	"log/slog"
	"os"
)

// Getlogger makes a new struct log object with given level
func GetLogger(lvl slog.Level) *slog.Logger {
	if lvl == 0 {
		lvl = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(h))
	logger := slog.Default()
	return logger
}
