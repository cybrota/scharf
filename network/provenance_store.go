// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package network

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const provenanceStoreLimit = 8 << 20

type provenanceObservations struct {
	Version int                              `json:"version"`
	Entries map[string]ProvenanceObservation `json:"observations"`
	raw     []byte
}

func loadProvenanceObservations(path string) (*provenanceObservations, error) {
	store := &provenanceObservations{Version: 1, Entries: map[string]ProvenanceObservation{}}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, provenanceStoreLimit+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > provenanceStoreLimit {
		return nil, errors.New("provenance observation file exceeds limit")
	}
	store.Version = 0
	store.Entries = nil
	if err := json.Unmarshal(raw, store); err != nil {
		return nil, err
	}
	if store.Version != 1 || store.Entries == nil {
		return nil, errors.New("unsupported or malformed provenance observation file")
	}
	for key, entry := range store.Entries {
		if (entry.RefKind != "sha" && entry.RefKind != "tags" && entry.RefKind != "heads") || observationTime(entry).IsZero() || key == "" || entry.RepositoryID <= 0 || !validProvenanceRepository(entry.Repository) || !provenanceSHA.MatchString(entry.SHA) || !validProvenanceRef(entry.OriginalRef) {
			return nil, fmt.Errorf("malformed provenance observation %q", key)
		}
	}
	store.raw = raw
	return store, nil
}

func saveProvenanceObservation(path string, original *provenanceObservations, key string, observation ProvenanceObservation) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// An exclusive lock and re-read prevent concurrent invocations from silently
	// replacing an observation they did not verify against. A stale lock fails
	// closed and can be inspected manually; it is never removed speculatively.
	lock := path + ".lock"
	if err := os.Mkdir(lock, 0o700); err != nil {
		return fmt.Errorf("observation store is locked: %w", err)
	}
	defer os.Remove(lock)
	current, err := loadProvenanceObservations(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current.raw, original.raw) {
		return errors.New("observations changed during verification; retry with fresh evidence")
	}
	current.Entries[key] = observation
	data, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > provenanceStoreLimit {
		return errors.New("provenance observation file exceeds limit")
	}
	file, err := os.CreateTemp(dir, ".provenance-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func observationTime(observation ProvenanceObservation) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, observation.CheckedAt)
	return parsed
}
