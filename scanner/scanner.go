// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// package scanner handles find operations

package scanner

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"

	"github.com/cybrota/scharf/git"
)

// Relative or Absolute path of a file
type FilePath string

var findRegex = regexp.MustCompile(
	`([\w-]+)\/([\w-]+)@` +
		`(?:` +
		`v\d+(?:\.\d+)*` + // e.g. v1, v1.2, v10.0.1
		`|` +
		`\d+\.\d+(?:\.\d+)*` + // e.g. 1.2, 2.0.3  (must have at least one dot)
		`|` +
		`main|dev|master` + // branches
		`)`,
)

// GitRepository implements Repository interface
type GitRepository struct {
	name    string
	absPath FilePath
}

func (g GitRepository) Name() string {
	return g.name
}

func (g GitRepository) ListBranches(fp FilePath) ([]string, error) {
	return git.ListGitBranches(string(fp))
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

// ScanBranch scans a given branch for mutable references
func ScanBranch(branch string, repo GitRepository, regex *regexp.Regexp, dirPath string) *Inventory {
	var inventory Inventory
	fileNames, err := ListFiles(FilePath(dirPath))
	if err != nil {
		// The directory might not exist on this branch; skip to next branch.
		logger.Debug("directory might not exist on branch. skipping to next repo")
		return nil
	}

	// Process each file found in the directory.
	for _, fileName := range fileNames {
		loc := filepath.Join(dirPath, string(*fileName))
		content, err := ReadFile(FilePath(loc))
		if err != nil {
			// Log error and skip this file.
			logger.Debug("workflow directory might not exist. skipping to next repo")
			continue
		}

		matches, err := ScanContent(content, regex)
		if err != nil {
			// Log error and skip this file.
			continue
		}

		if len(matches) > 0 {
			ir := &InventoryRecord{
				Repository: repo.Name(),
				Branch:     branch,
				FilePath:   loc,
				Matches:    matches,
			}

			inventory.Records = append(inventory.Records, ir)
		}
	}
	return &inventory
}

// ScanRepos traverses all repositories found under the root directory,
// checks each branch, enumerates over files in the given workflow directory path,
// and scans each file's content for regex matches.
// ho - HEAD only
func ScanRepos(repos []*GitRepository, regex *regexp.Regexp, ho bool) (*Inventory, error) {
	var inventory Inventory

	// Process each repository.
	for _, repo := range repos {
		branches, err := repo.ListBranches(repo.absPath)
		if err != nil {
			// Log error and continue with next repository.
			logger.Debug("couldn't detect branches. skipping to next repo")
			continue
		}

		if ho {
			branches = []string{"HEAD"}
		}

		// For each branch, enumerate files in the specified directory.
		for _, branch := range branches {
			searchPath := filepath.Join(string(repo.absPath), ".github", "workflows")
			logger.Debug("Processing the repo:", "repo", repo.Name(), "branch", branch, "filepath", searchPath)
			inv := ScanBranch(branch, *repo, regex, searchPath)
			if inv != nil {
				inventory.Records = append(inventory.Records, inv.Records...)
			}
		}
	}

	return &inventory, nil
}

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

func ListRepositoriesAtRoot(root FilePath) ([]*GitRepository, error) {
	repos, err := os.ReadDir(string(root))

	if err != nil {
		logger.Error("failed to read root directory", "err", err)
		return nil, fmt.Errorf("os: %w", err)
	}

	var rs []*GitRepository
	for _, repo := range repos {
		abs, err := filepath.Abs(filepath.Join(string(root), repo.Name()))
		if err != nil {
			logger.Error("failed to find absolute path", "err", err)
			return nil, fmt.Errorf("os: %w", err)
		}

		if shouldIncludeDir(repo.Name()) {
			rs = append(rs, &GitRepository{
				name:    repo.Name(),
				absPath: FilePath(abs),
			})
		}
	}

	return rs, nil
}

func ListFiles(loc FilePath) ([]*FilePath, error) {
	entries, err := os.ReadDir(string(loc))
	if err != nil {
		return nil, fmt.Errorf("os: %w", err)
	}

	var files []*FilePath
	for _, entry := range entries {
		logger.Debug("found file at location", "repo", entry.Name(), "loc", loc)
		fp := FilePath(entry.Name())
		files = append(files, &fp)
	}
	return files, nil
}

// ReadFile reads content of file in a given filepath
func ReadFile(loc FilePath) ([]byte, error) {
	content, err := os.ReadFile(string(loc))
	if err != nil {
		return nil, fmt.Errorf("os: %w", err)
	}

	return content, nil
}

// ScanContent finds matches in given content
func ScanContent(content []byte, regex *regexp.Regexp) ([]string, error) {
	found := regex.FindAll([]byte(content), -1)

	var matches []string
	for _, match := range found {
		matches = append(matches, string(match))
	}

	return matches, nil
}

// Match represents a single match plus its position.
type Match struct {
	Text      string
	Line, Col int
}

// ScanContentWithPosition scans the content and returns each match
// along with its 1-based line and column.
func ScanContentWithPosition(content []byte, regex *regexp.Regexp) ([]Match, error) {
	var results []Match

	// Split on \n so we can track line numbers easily.
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		// FindAllIndex returns a slice of [2]int{startByte, endByte} pairs.
		locs := regex.FindAllIndex(line, -1)
		for _, loc := range locs {
			start := loc[0]
			end := loc[1]
			// Convert the byte offsets back to string
			matchedText := string(line[start:end])
			// Column is byte-offset +1. (If you care about rune/character columns,
			// you can convert line[:start] to runes and take len(runes).)
			results = append(results, Match{
				Text: matchedText,
				Line: i + 1,
				Col:  start + 1,
			})
		}
	}

	return results, nil
}

func Find(root string, headOnly bool) (*Inventory, error) {
	repos, err := ListRepositoriesAtRoot(FilePath(root))
	if err != nil {
		log.Fatal(err.Error())
	}

	inv, err := ScanRepos(repos, findRegex, headOnly)
	if err != nil {
		return nil, err
	}

	return inv, nil
}
