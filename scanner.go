package main

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"
)

// Global logger instance.
var logger = slog.Default()

// Scanner ties together VCS operations with file scanning logic.
type Scanner struct {
	// VCS system implementation (e.g., GitHub, GitLab)
	VCS         VCS
	FileScanner FileScanner
}

// ScanRepos traverses all repositories found under the root directory,
// checks each branch, enumerates over files in the given workflow directory path,
// and scans each file's content for regex matches.
func (s *Scanner) ScanRepos(root string, dirPath string, regex *regexp.Regexp) (*Inventory, error) {
	var inventory Inventory

	// Retrieve repositories from the VCS.
	repos, err := s.VCS.ListRepositories(root)
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

		// For each branch, enumerate files in the specified directory.
		for _, branch := range branches {
			fileNames, err := repo.ListFiles(fmt.Sprintf("%s/%s/%s", root, repo.Name(), dirPath))
			if err != nil {
				// The directory might not exist on this branch; skip to next branch.
				logger.Debug("directory might not exist on branch. skipping to next repo")
				continue
			}

			// Process each file found in the directory.
			for _, fileName := range fileNames {
				fPath := fmt.Sprintf("%s/%s/%s/%s", root, repo.Name(), dirPath, fileName)
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
					inventory.Records = append(inventory.Records, InventoryRecord{
						Repository: repo.Name(),
						Branch:     branch,
						FilePath:   fPath,
						Matches:    matches,
					})
				}
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

// VCS defines operations common to all version control systems.
type VCS interface {
	ListRepositories(root string) ([]Repository, error)
}

// GitHub VCS
type GitHubVCS struct{}

func (g GitHubVCS) ListRepositories(root string) ([]Repository, error) {
	repos, err := os.ReadDir(root)

	if err != nil {
		logger.Error("failed to read root directory", "err", err)
		return nil, err
	}

	var rs []Repository
	for _, repo := range repos {
		if shouldIncludeDir(repo.Name()) {
			rs = append(rs, GitRepository{
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
	return ListGitBranches(g.localPath)
}

func (g GitRepository) ListFiles(loc string) ([]string, error) {
	entries, err := os.ReadDir(loc)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	return content, nil
}

func (g GitRepository) SwitchBranch(branchName string) error {
	return CheckoutGitBranch(g.localPath, branchName)
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
	Repository string   // Repository name or path
	Branch     string   // Branch name
	FilePath   string   // File path where the match was found
	Matches    []string // Regex match results from the file content
}

// Inventory aggregates multiple inventory records.
type Inventory struct {
	Records []InventoryRecord
}
