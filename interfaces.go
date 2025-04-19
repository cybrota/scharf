package main

import (
	"fmt"
	"path/filepath"
	"regexp"
)

// Scanner ties together VCS operations with file scanning logic.
type Scanner struct {
	// VCS system implementation (e.g., GitHub, GitLab)
	VCS         VCS
	FileScanner FileScanner
}

func (s *Scanner) ScanBranch(branch string, repo Repository, regex *regexp.Regexp, dirPath string) *InventoryRecord {
	fileNames, err := repo.ListFiles(dirPath)
	if err != nil {
		// The directory might not exist on this branch; skip to next branch.
		logger.Debug("directory might not exist on branch. skipping to next repo")
		return nil
	}

	// Process each file found in the directory.
	for _, fileName := range fileNames {
		fPath := fmt.Sprintf("%s/%s", dirPath, fileName)
		content, err := repo.ReadFile(fPath)
		if err != nil {
			// Log error and skip this file.
			logger.Debug("workflow directory might not exist. skipping to next repo")
			continue
		}

		matches, err := s.FileScanner.ScanContent(content, regex)
		if err != nil {
			// Log error and skip this file.
			continue
		}

		if len(matches) > 0 {
			return &InventoryRecord{
				Repository: repo.Name(),
				Branch:     branch,
				FilePath:   fPath,
				Matches:    matches,
			}
		}
	}
	return nil
}

// ScanRepos traverses all repositories found under the root directory,
// checks each branch, enumerates over files in the given workflow directory path,
// and scans each file's content for regex matches.
// ho - HEAD only
func (s *Scanner) ScanRepos(root string, regex *regexp.Regexp, ho bool) (*Inventory, error) {
	var inventory Inventory
	absolutePath, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("filepath: %w", err)
	}

	// Retrieve repositories from the VCS.
	repos, err := s.VCS.ListRepositories(absolutePath)
	if err != nil {
		return nil, err
	}

	// Process each repository.
	for _, repo := range repos {
		branches, err := repo.ListBranches()
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
			searchPath := fmt.Sprintf("%s/%s/.github/workflows", absolutePath, repo.Name())
			logger.Debug("Processing the repo:", "repo", repo.Name(), "branch", branch, "filepath", searchPath)
			ir := s.ScanBranch(branch, repo, regex, searchPath)
			if ir != nil {
				inventory.Records = append(inventory.Records, ir)
			}
		}
	}

	return &inventory, nil
}

// Repository abstracts a single repository and its operations.
type Repository interface {
	Name() string

	// Location gets absolute path of repository
	Location() string
	// ListBranches returns all branches available in the repository.
	ListBranches() ([]string, error)
	// ReadFile retrieves the content of a file given a file path.
	ReadFile(filePath string) ([]byte, error)
	// ListFiles returns all file paths under a given directory in a branch.
	ListFiles(loc string) ([]string, error)
	// SwitchBranch checks out the repository to given branch
	SwitchBranch(branchName string) error
}

// Branch abstracts a branch in a repository.
type Branch interface {
	Name() string
}

// FileScanner defines functionality to scan file content using a regex.
type FileScanner interface {
	ScanContent(content []byte, regex *regexp.Regexp) ([]string, error)
}

// VCS defines operations common to all version control systems.
type VCS interface {
	ListRepositories(root string) ([]Repository, error)
}
