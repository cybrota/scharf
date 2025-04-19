package main

import (
	"log/slog"
	"os"
)

func getLogger(lvl slog.Level) *slog.Logger {
	// Global logger instance.
	if lvl == 0 {
		lvl = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(h))
	logger := slog.Default()
	return logger
}

var logger = getLogger(0)
