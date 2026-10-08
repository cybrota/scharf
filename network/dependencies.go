// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package network

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// DependencyClient never executes remote content and never follows redirects.
// Repository content and API response sizes, request count and duration are bounded.
type DependencyClient struct {
	Client      *http.Client
	BaseURL     string
	Token       string
	MaxRequests int
	requests    int
}

func NewDependencyClient() *DependencyClient {
	return &DependencyClient{Client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, BaseURL: "https://api.github.com", Token: strings.TrimSpace(os.Getenv("GITHUB_TOKEN")), MaxRequests: 500}
}

var dependencySHA = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
var dependencyRepo = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+$`)

func (c *DependencyClient) get(endpoint string, result any) error {
	if c.MaxRequests <= 0 || c.requests >= c.MaxRequests {
		return errors.New("dependency network budget exhausted")
	}
	c.requests++
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(c.BaseURL, "/")+endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if c.Client == nil {
		return errors.New("dependency HTTP client unavailable")
	}
	// Copy the injected client so even test/custom clients cannot follow an
	// attacker-controlled redirect carrying a credential or leave the API host.
	client := *c.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return os.ErrNotExist
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dependency API returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 2<<20 {
		return errors.New("dependency API response exceeds 2 MiB")
	}
	return json.Unmarshal(data, result)
}
func (c *DependencyClient) Resolve(action string) (string, error) {
	parts := strings.SplitN(action, "@", 2)
	if len(parts) != 2 || !dependencyRepo.MatchString(parts[0]) || strings.HasSuffix(parts[0], "/.") || strings.HasSuffix(parts[0], "/..") || parts[1] == "" {
		return "", errors.New("invalid dependency reference")
	}
	var result struct {
		SHA string `json:"sha"`
	}
	if err := c.get("/repos/"+parts[0]+"/commits/"+url.PathEscape(parts[1]), &result); err != nil {
		return "", err
	}
	if !dependencySHA.MatchString(result.SHA) {
		return "", errors.New("dependency API did not return a full commit SHA")
	}
	return result.SHA, nil
}
func (c *DependencyClient) ReadMetadata(repo, sha, name string) ([]byte, error) {
	if !dependencyRepo.MatchString(repo) || strings.HasSuffix(repo, "/.") || strings.HasSuffix(repo, "/..") || !dependencySHA.MatchString(sha) {
		return nil, errors.New("metadata requires repository and full commit SHA")
	}
	parts := strings.Split(name, "/")
	for i, p := range parts {
		if p == "" || p == "." || p == ".." || strings.ContainsAny(p, "\\\x00") {
			return nil, errors.New("invalid metadata path")
		}
		parts[i] = url.PathEscape(p)
	}
	var result struct {
		Type     string `json:"type"`
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
		Size     int    `json:"size"`
	}
	if err := c.get("/repos/"+repo+"/contents/"+strings.Join(parts, "/")+"?ref="+url.QueryEscape(sha), &result); err != nil {
		return nil, err
	}
	if result.Type != "file" || result.Encoding != "base64" || result.Size > 1<<20 {
		return nil, errors.New("unsupported or oversized action metadata")
	}
	b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(result.Content, "\n", ""))
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("metadata exceeds 1 MiB")
	}
	return b, nil
}
