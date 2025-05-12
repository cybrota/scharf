// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// package network handles all GitHub API related network calls

package network

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/cybrota/scharf/actcache"
)

const apiURL = "https://api.github.com/repos"

var homedir, _ = os.UserHomeDir()
var scharfDir = filepath.Join(homedir, ".scharf")

// Resolver is a converter for action@version to a SHA string
type Resolver interface {
	// Resolve checks if SHA is available for a given version of GitHub action
	Resolve(action string) (string, error)
}

// searchTag probes for a given version tag in list of tags and returns SHA commit
func searchTag(tags []BranchOrTag, version string) (bool, string) {
	for _, t := range tags {
		if t.Name == version {
			if t.Commit.Sha == "" {
				return false, ""
			} else {
				return true, t.Commit.Sha
			}
		}
		continue
	}

	return false, ""
}

// splitRawAction takes a raw action reference and splits it as action & version
func splitRawAction(raw string) [2]string {
	splits := strings.Split(raw, "@")

	if len(splits) == 2 {
		return [2]string{
			splits[0],
			splits[1],
		}
	} else if len(splits) == 1 {
		return [2]string{
			splits[0],
			"",
		}
	}

	return [2]string{}
}

// makeAPIEndpoint checks if  agiven version is a branch or tag and builds endpoint
func makeAPIEndpoint(action string, version string) string {
	var lookupURL string

	if strings.HasPrefix(strings.ToLower(version), "v") {
		lookupURL = fmt.Sprintf("%s/%s/tags", apiURL, action)
	} else {
		lookupURL = fmt.Sprintf("%s/%s/branches", apiURL, action)
	}

	return lookupURL
}

// GetRefList takes an action and returns a list of matching tags
func GetRefList(action string) ([]BranchOrTag, error) {
	lookupURL := fmt.Sprintf("%s/%s/tags", apiURL, action)
	resp, err := http.Get(lookupURL)
	if err != nil {
		return []BranchOrTag{}, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	var b []BranchOrTag
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		return []BranchOrTag{}, fmt.Errorf("json: %w", err)
	}

	return b, nil
}

// SHAResolver resolves a given action to it's safe SHA commit
type SHAResolver struct {
	cache map[string]string
}

func NewSHAResolver() *SHAResolver {
	cache := make(map[string]string)

	// Fill resolver cache from cache file
	c, err := actcache.GetCache(scharfDir)
	if err == nil && len(c) > 0 {
		for k, v := range c {
			cache[k] = v.SHA
		}
	}

	return &SHAResolver{
		cache: cache,
	}
}

type Commit struct {
	Sha string `json:"sha"`
	URL string `json:"url"`
}

type BranchOrTag struct {
	Name   string `json:"name"`
	Commit Commit `json:"commit"`
}

// Resolve fetches list of tags for a given GitHub action and picks SHA commit
func (s *SHAResolver) Resolve(action string) (string, error) {
	// See if SHA can be found in resolver cache
	if s.cache[action] != "" {
		return s.cache[action], nil
	}

	splits := splitRawAction(action)
	actionBase := splits[0]
	version := splits[1]

	if version == "" {
		version = "main"
	}

	url := makeAPIEndpoint(actionBase, version)

	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	var b []BranchOrTag
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		return "", fmt.Errorf("json: %w", err)
	}

	found, sha := searchTag(b, version)
	if !found {
		return "", errors.New(fmt.Sprintf("given version: %s is not found for action: %s", version, actionBase))
	}

	// Add SHA to resolver cache for repeated asks
	s.cache[action] = sha

	// Add SHA to cache file for future calls
	actcache.UpdateCacheEntry(scharfDir, action, sha)

	return sha, nil
}
