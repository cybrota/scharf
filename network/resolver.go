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
	"time"

	"github.com/cybrota/scharf/actcache"
)

const apiURL = "https://api.github.com/repos"
const defaultCooldownHours = 24

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

func githubAPIGet(lookupURL string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, lookupURL, nil)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}

	if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	return http.DefaultClient.Do(req)
}

// GetRefList takes an action and returns a list of matching tags
func GetRefList(action string) ([]BranchOrTag, error) {
	lookupURL := fmt.Sprintf("%s/%s/tags", apiURL, action)
	resp, err := githubAPIGet(lookupURL)
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

// UpgradeResult holds the details needed for pinned SHA upgrade flows.
type UpgradeResult struct {
	Action         string
	CurrentVersion string
	CurrentSHA     string
	NextVersion    string
	NextSHA        string
	CooldownHours  int
	UnderCooldown  bool
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

type commitLookupResponse struct {
	Commit struct {
		Committer struct {
			Date string `json:"date"`
		} `json:"committer"`
	} `json:"commit"`
}

func nextVersion(tags []string, current string) (string, bool) {
	for i := range tags {
		if tags[i] == current && i > 0 {
			return tags[i-1], true
		}
	}

	return "", false
}

func normalizeCooldownHours(cooldownHours int) int {
	if cooldownHours <= 0 {
		return defaultCooldownHours
	}

	return cooldownHours
}

func isUnderCooldown(tagTime time.Time, cooldownHours int) bool {
	safeCooldown := normalizeCooldownHours(cooldownHours)
	return time.Since(tagTime) < time.Duration(safeCooldown)*time.Hour
}

func fetchCommitTimestamp(action string, sha string) (time.Time, error) {
	lookupURL := fmt.Sprintf("%s/%s/commits/%s", apiURL, action, sha)
	resp, err := githubAPIGet(lookupURL)
	if err != nil {
		return time.Time{}, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return time.Time{}, fmt.Errorf("http status: %d", resp.StatusCode)
	}

	var payload commitLookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return time.Time{}, fmt.Errorf("json: %w", err)
	}

	if payload.Commit.Committer.Date == "" {
		return time.Time{}, errors.New("commit date is empty")
	}

	parsed, err := time.Parse(time.RFC3339, payload.Commit.Committer.Date)
	if err != nil {
		return time.Time{}, fmt.Errorf("time parse: %w", err)
	}

	return parsed, nil
}

// ResolveNext resolves the next version and SHA for an action's current version.
func (s *SHAResolver) ResolveNext(action string, currentVersion string, cooldownHours int) (*UpgradeResult, error) {
	refs, err := GetRefList(action)
	if err != nil {
		return nil, err
	}

	tagNames := make([]string, 0, len(refs))
	for _, ref := range refs {
		tagNames = append(tagNames, ref.Name)
	}

	nextVer, found := nextVersion(tagNames, currentVersion)
	if !found {
		return nil, fmt.Errorf("no next version found for action: %s from version: %s", action, currentVersion)
	}

	currentFound, currentSHA := searchTag(refs, currentVersion)
	if !currentFound {
		return nil, fmt.Errorf("given version: %s is not found for action: %s", currentVersion, action)
	}

	nextFound, nextSHA := searchTag(refs, nextVer)
	if !nextFound {
		return nil, fmt.Errorf("given version: %s is not found for action: %s", nextVer, action)
	}

	underCooldown := false
	if ts, err := fetchCommitTimestamp(action, nextSHA); err == nil {
		underCooldown = isUnderCooldown(ts, cooldownHours)
	}

	return &UpgradeResult{
		Action:         action,
		CurrentVersion: currentVersion,
		CurrentSHA:     currentSHA,
		NextVersion:    nextVer,
		NextSHA:        nextSHA,
		CooldownHours:  normalizeCooldownHours(cooldownHours),
		UnderCooldown:  underCooldown,
	}, nil
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

	resp, err := githubAPIGet(url)
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
