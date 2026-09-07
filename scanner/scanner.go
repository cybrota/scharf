// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// package scanner handles find operations

package scanner

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cybrota/scharf/git"
	gitlib "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// Relative or Absolute path of a file
type FilePath string

var findRegex = regexp.MustCompile(
	`([\w-]+)\/([\w-]+)@` +
		`(?:` +
		`v\d+(?:\.\d+)*` +
		`|` +
		`\d+\.\d+(?:\.\d+)*` +
		`|` +
		`main|dev|master` +
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

// InventoryRecord preserves the v1 inventory wire contract.
type InventoryRecord struct {
	Repository string   `json:"repository_name"`
	Branch     string   `json:"branch_name"`
	FilePath   string   `json:"actions_file"`
	Matches    []string `json:"matches"`
}

// Inventory preserves the v1 inventory wire contract.
type Inventory struct {
	Records []*InventoryRecord `json:"findings"`
}

// InventoryResultRecord adds structured details without changing InventoryRecord.
type InventoryResultRecord struct {
	Repository string             `json:"repository_name"`
	Branch     string             `json:"branch_name"`
	FilePath   string             `json:"actions_file"`
	Matches    []string           `json:"matches"`
	Findings   []ReferenceFinding `json:"details"`
}

// InventoryResult distinguishes scan completion from findings.
type InventoryResult struct {
	Status   ScanStatus               `json:"status"`
	Complete bool                     `json:"complete"`
	Records  []*InventoryResultRecord `json:"findings"`
	Errors   []ScanError              `json:"errors,omitempty"`
}

// ScanBranch preserves the v1 regex-scanning signature and behavior.
func ScanBranch(branch string, repo GitRepository, regex *regexp.Regexp, dirPath string) *Inventory {
	var inventory Inventory
	fileNames, err := ListFiles(FilePath(dirPath))
	if err != nil {
		return nil
	}
	for _, fileName := range fileNames {
		loc := filepath.Join(dirPath, string(*fileName))
		content, err := ReadFile(FilePath(loc))
		if err != nil {
			continue
		}
		matches, err := ScanContent(content, regex)
		if err != nil || len(matches) == 0 {
			continue
		}
		inventory.Records = append(inventory.Records, &InventoryRecord{
			Repository: repo.Name(),
			Branch:     branch,
			FilePath:   loc,
			Matches:    matches,
		})
	}
	return &inventory
}

// ScanBranchResult scans the current working tree with structured workflow analysis.
func ScanBranchResult(branch string, repo GitRepository, dirPath string) *InventoryResult {
	result := &InventoryResult{}
	fileNames, err := ListWorkflowFiles(FilePath(dirPath))
	if err != nil {
		result.Errors = append(result.Errors, NewScanError(dirPath, err))
		result.setStatus()
		return result
	}
	for _, fileName := range fileNames {
		filePath := string(fileName)
		content, err := ReadFile(fileName)
		if err != nil {
			result.Errors = append(result.Errors, NewScanError(filePath, err))
			continue
		}
		findings, scanErr := ScanWorkflowReferences(content, filePath)
		if len(findings) > 0 {
			result.Records = append(result.Records, inventoryResultRecord(branch, repo, filePath, findings))
		}
		if scanErr != nil {
			result.Errors = append(result.Errors, NewScanError(filePath, scanErr))
		}
	}
	result.setStatus()
	return result
}

func inventoryResultRecord(branch string, repo GitRepository, filePath string, findings []ReferenceFinding) *InventoryResultRecord {
	matches := make([]string, 0, len(findings))
	for _, finding := range findings {
		matches = append(matches, finding.Original)
	}
	return &InventoryResultRecord{
		Repository: repo.Name(),
		Branch:     branch,
		FilePath:   filePath,
		Matches:    matches,
		Findings:   findings,
	}
}

// ScanRepos preserves the v1 regex-scanning signature and behavior.
func ScanRepos(repos []*GitRepository, regex *regexp.Regexp, headOnly bool) (*Inventory, error) {
	var inventory Inventory
	for _, repo := range repos {
		branches, err := repo.ListBranches(repo.absPath)
		if err != nil {
			continue
		}
		if headOnly {
			branches = []string{"HEAD"}
		}
		for _, branch := range branches {
			searchPath := filepath.Join(string(repo.absPath), ".github", "workflows")
			branchInventory := ScanBranch(branch, *repo, regex, searchPath)
			if branchInventory != nil {
				inventory.Records = append(inventory.Records, branchInventory.Records...)
			}
		}
	}
	return &inventory, nil
}

// ScanRepositories scans the working tree for headOnly and local branch trees otherwise.
func ScanRepositories(repos []*GitRepository, headOnly bool) (*InventoryResult, error) {
	var inventory InventoryResult
	for _, repo := range repos {
		if headOnly {
			searchPath := filepath.Join(string(repo.absPath), ".github", "workflows")
			branchResult := ScanBranchResult("HEAD", *repo, searchPath)
			inventory.Records = append(inventory.Records, branchResult.Records...)
			inventory.Errors = append(inventory.Errors, branchResult.Errors...)
			continue
		}

		gitRepo, err := gitlib.PlainOpen(string(repo.absPath))
		if err != nil {
			inventory.Errors = append(inventory.Errors, NewScanError(string(repo.absPath), fmt.Errorf("open Git repository: %w", err)))
			continue
		}
		branches, err := gitRepo.Branches()
		if err != nil {
			inventory.Errors = append(inventory.Errors, NewScanError(string(repo.absPath), fmt.Errorf("list Git branches: %w", err)))
			continue
		}
		err = branches.ForEach(func(ref *plumbing.Reference) error {
			branchResult := scanGitTree(ref.Name().Short(), *repo, gitRepo, ref.Hash())
			inventory.Records = append(inventory.Records, branchResult.Records...)
			inventory.Errors = append(inventory.Errors, branchResult.Errors...)
			return nil
		})
		if err != nil {
			inventory.Errors = append(inventory.Errors, NewScanError(string(repo.absPath), fmt.Errorf("iterate Git branches: %w", err)))
		}

		refs, err := gitRepo.References()
		if err != nil {
			inventory.Errors = append(inventory.Errors, NewScanError(string(repo.absPath), fmt.Errorf("list remote Git branches: %w", err)))
			continue
		}
		err = refs.ForEach(func(ref *plumbing.Reference) error {
			const remotePrefix = "refs/remotes/"
			name := ref.Name().String()
			if ref.Type() != plumbing.HashReference || !strings.HasPrefix(name, remotePrefix) {
				return nil
			}
			remoteName := strings.TrimPrefix(name, remotePrefix)
			if strings.HasSuffix(remoteName, "/HEAD") {
				return nil
			}
			branchResult := scanGitTree("remote:"+remoteName, *repo, gitRepo, ref.Hash())
			inventory.Records = append(inventory.Records, branchResult.Records...)
			inventory.Errors = append(inventory.Errors, branchResult.Errors...)
			return nil
		})
		if err != nil {
			inventory.Errors = append(inventory.Errors, NewScanError(string(repo.absPath), fmt.Errorf("iterate remote Git branches: %w", err)))
		}
	}
	inventory.setStatus()
	return &inventory, inventory.Err()
}

func scanGitTree(branch string, repo GitRepository, gitRepo *gitlib.Repository, hash plumbing.Hash) *InventoryResult {
	result := &InventoryResult{}
	commit, err := gitRepo.CommitObject(hash)
	if err != nil {
		result.Errors = append(result.Errors, NewScanError(string(repo.absPath), fmt.Errorf("read branch %s commit: %w", branch, err)))
		result.setStatus()
		return result
	}
	tree, err := commit.Tree()
	if err != nil {
		result.Errors = append(result.Errors, NewScanError(string(repo.absPath), fmt.Errorf("read branch %s tree: %w", branch, err)))
		result.setStatus()
		return result
	}
	files := tree.Files()
	err = files.ForEach(func(file *object.File) error {
		if file.Mode != filemode.Regular && file.Mode != filemode.Executable {
			return nil
		}
		if filepath.ToSlash(filepath.Dir(file.Name)) != ".github/workflows" {
			return nil
		}
		ext := filepath.Ext(file.Name)
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		filePath := filepath.Join(string(repo.absPath), filepath.FromSlash(file.Name))
		content, err := file.Contents()
		if err != nil {
			result.Errors = append(result.Errors, NewScanError(filePath, fmt.Errorf("read branch %s blob: %w", branch, err)))
			return nil
		}
		findings, scanErr := ScanWorkflowReferences([]byte(content), filePath)
		if len(findings) > 0 {
			result.Records = append(result.Records, inventoryResultRecord(branch, repo, filePath, findings))
		}
		if scanErr != nil {
			result.Errors = append(result.Errors, NewScanError(filePath, scanErr))
		}
		return nil
	})
	if err != nil {
		result.Errors = append(result.Errors, NewScanError(string(repo.absPath), fmt.Errorf("scan branch %s tree: %w", branch, err)))
	}
	result.setStatus()
	return result
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
		if !repo.IsDir() {
			continue
		}
		abs, err := filepath.Abs(filepath.Join(string(root), repo.Name()))
		if err != nil {
			logger.Error("failed to find absolute path", "err", err)
			return nil, fmt.Errorf("os: %w", err)
		}

		if shouldIncludeDir(repo.Name()) && git.IsGitRepo(abs) {
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
		return nil, err
	}
	return ScanRepos(repos, findRegex, headOnly)
}

// FindStructured returns structure-aware findings and explicit completion state.
func FindStructured(root string, headOnly bool) (*InventoryResult, error) {
	repos, err := ListRepositoriesAtRoot(FilePath(root))
	if err != nil {
		return nil, err
	}
	return ScanRepositories(repos, headOnly)
}
