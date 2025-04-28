// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package to store memory between multiple CLI executions

package actcache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// hashEntry is the JSON shape for each action in cache.json.
type hashEntry struct {
	SHA       string `json:"sha"`
	UpdatedAt string `json:"updated_at"`
}

func NewHashEntry() *hashEntry {
	return &hashEntry{}
}

// loadCache loads cache.json into a map[action]hashEntry.
// If the file does not exist, it returns an empty map.
func loadCache(dir string) (map[string]hashEntry, error) {
	file := filepath.Join(dir, "cache.json")
	data, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]hashEntry), nil
		}
		return nil, fmt.Errorf("reading %s: %w", file, err)
	}

	m := make(map[string]hashEntry)
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", file, err)
	}
	return m, nil
}

// saveCache writes the given map[action]hashEntry back to cache.json (with indentation).
func saveCache(dir string, m map[string]hashEntry) error {
	buf, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("ensuring dir %s: %w", dir, err)
	}
	file := filepath.Join(dir, "cache.json")
	if err := os.WriteFile(file, buf, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", file, err)
	}
	return nil
}

// GetCache returns the entire cache as a map[action]hashEntry.
func GetCache(dir string) (map[string]hashEntry, error) {
	return loadCache(dir)
}

// UpdateCacheEntry sets m[action] = { newSHA, now } and persists it.
func UpdateCacheEntry(dir, action, newSHA string) error {
	m, err := loadCache(dir)
	if err != nil {
		return err
	}
	m[action] = hashEntry{
		SHA:       newSHA,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	return saveCache(dir, m)
}

// CacheExists returns true if cache.json exists in dir.
func CacheExists(dir string) bool {
	file := filepath.Join(dir, "cache.json")
	info, err := os.Stat(file)
	if err == nil {
		return !info.IsDir()
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}
