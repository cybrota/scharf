// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package actcache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestNewHashEntry ensures NewHashEntry returns an empty struct pointer.
func TestNewHashEntry(t *testing.T) {
	h := NewHashEntry()
	if h == nil {
		t.Fatalf("NewHashEntry() returned nil")
	}
	if h.SHA != "" || h.UpdatedAt != "" {
		t.Errorf("expected empty hashEntry, got %+v", h)
	}
}

// TestLoadCache_NoFile verifies that an absent cache.json results in an empty map.
func TestLoadCache_NoFile(t *testing.T) {
	dir := t.TempDir()
	m, err := loadCache(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m) != 0 {
		t.Errorf("expected empty map, got %v", m)
	}
}

// TestLoadCache_InvalidJSON ensures invalid JSON surfaces an error.
func TestLoadCache_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "cache.json"), []byte("not-json"), 0o644)
	if _, err := loadCache(dir); err == nil {
		t.Fatal("expected error from invalid json, got nil")
	}
}

// TestLoadCache_Valid verifies a valid cache.json is parsed correctly.
func TestLoadCache_Valid(t *testing.T) {
	dir := t.TempDir()
	data := map[string]hashEntry{"a": {SHA: "1", UpdatedAt: time.Now().Format(time.RFC3339Nano)}}
	b, _ := json.Marshal(data)
	os.WriteFile(filepath.Join(dir, "cache.json"), b, 0o644)

	m, err := loadCache(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m["a"].SHA != "1" {
		t.Errorf("expected SHA '1', got %q", m["a"].SHA)
	}
}

// TestSaveCache writes a map and confirms file contents.
func TestSaveCache(t *testing.T) {
	dir := t.TempDir()
	data := map[string]hashEntry{"a": {SHA: "1", UpdatedAt: "time"}}
	if err := saveCache(dir, data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "cache.json"))
	if err != nil {
		t.Fatalf("failed reading file: %v", err)
	}
	var out map[string]hashEntry
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("invalid json written: %v", err)
	}
	if out["a"].SHA != "1" {
		t.Errorf("expected sha '1', got %q", out["a"].SHA)
	}
}

// TestGetCache simply proxies to loadCache.
func TestGetCache(t *testing.T) {
	dir := t.TempDir()
	data := map[string]hashEntry{"x": {SHA: "abc"}}
	b, _ := json.Marshal(data)
	os.WriteFile(filepath.Join(dir, "cache.json"), b, 0o644)
	m, err := GetCache(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m["x"].SHA != "abc" {
		t.Errorf("expected sha 'abc', got %q", m["x"].SHA)
	}
}

// TestUpdateCacheEntry adds or updates an entry and persists it.
func TestUpdateCacheEntry(t *testing.T) {
	dir := t.TempDir()
	// start with an existing file
	init := map[string]hashEntry{"y": {SHA: "old", UpdatedAt: ""}}
	b, _ := json.Marshal(init)
	os.WriteFile(filepath.Join(dir, "cache.json"), b, 0o644)

	if err := UpdateCacheEntry(dir, "y", "newsha"); err != nil {
		t.Fatalf("update failed: %v", err)
	}

	m, err := loadCache(dir)
	if err != nil {
		t.Fatalf("loadCache failed: %v", err)
	}
	if m["y"].SHA != "newsha" {
		t.Errorf("expected sha 'newsha', got %q", m["y"].SHA)
	}
	if m["y"].UpdatedAt == "" {
		t.Error("expected UpdatedAt to be set")
	}
}

// TestCacheExists checks presence detection of cache.json.
func TestCacheExists(t *testing.T) {
	dir := t.TempDir()
	if CacheExists(dir) {
		t.Error("expected false when file missing")
	}
	os.WriteFile(filepath.Join(dir, "cache.json"), []byte("{}"), 0o644)
	if !CacheExists(dir) {
		t.Error("expected true when file exists")
	}
}
