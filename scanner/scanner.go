// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"fmt"
	"os"
	"regexp"

	"github.com/cybrota/scharf/git"
)

// shouldIncludeDir returns false if the file should be ignored.
func shouldIncludeDir(fileName string) bool {
	// List files you want to exclude.
	ignoredFiles := map[string]bool{
		".DS_Store":    true,
		".ruff_cache":  true,
		".ropeproject": true,
	}
	return !ignoredFiles[fileName]
}

// GitHub VCS
type GitHubVCS struct{}

func (g GitHubVCS) ListRepositories(root string) ([]Repository, error) {
	repos, err := os.ReadDir(root)

	if err != nil {
		logger.Error("failed to read root directory", "err", err)
		return nil, fmt.Errorf("os: %w", err)
	}

	var rs []Repository
	for _, repo := range repos {
		if shouldIncludeDir(repo.Name()) {
			rs = append(rs, &GitRepository{
				name:      repo.Name(),
				localPath: fmt.Sprintf("%s/%s", root, repo.Name()),
			})
		}
	}

	return rs, nil
}

// GitRepository implements Repository interface
type GitRepository struct {
	name      string
	localPath string
}

func (g GitRepository) Name() string {
	return g.name
}

func (g GitRepository) Location() string {
	return g.localPath
}

func (g GitRepository) ListBranches() ([]string, error) {
	return git.ListGitBranches(g.localPath)
}

func (g GitRepository) ListFiles(loc string) ([]string, error) {
	entries, err := os.ReadDir(loc)
	if err != nil {
		return nil, fmt.Errorf("os: %w", err)
	}

	var files []string
	for _, entry := range entries {
		logger.Debug("found file at location", "repo", entry.Name(), "loc", loc)
		files = append(files, entry.Name())
	}
	return files, nil
}

func (g GitRepository) ReadFile(filePath string) ([]byte, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("os: %w", err)
	}

	return content, nil
}

func (g GitRepository) SwitchBranch(branchName string) error {
	return git.CheckoutGitBranch(g.localPath, branchName)
}

// GitHubWorkFlowScanner implements Scanner interface
type GitHubWorkFlowScanner struct{}

// ScanContent finds matches in given content
func (gws GitHubWorkFlowScanner) ScanContent(content []byte, regex *regexp.Regexp) ([]string, error) {
	found := regex.FindAll([]byte(content), -1)

	var matches []string
	for _, match := range found {
		matches = append(matches, string(match))
	}

	return matches, nil
}

// InventoryRecord holds details for a regex match in a file.
type InventoryRecord struct {
	Repository string   `json:"repository_name"` // Repository name or path
	Branch     string   `json:"branch_name"`     // Branch name
	FilePath   string   `json:"actions_file"`    // File path where the match was found
	Matches    []string `json:"matches"`         // Regex match results from the file content
}

// Inventory aggregates multiple inventory records.
type Inventory struct {
	Records []*InventoryRecord `json:"findings"`
}
