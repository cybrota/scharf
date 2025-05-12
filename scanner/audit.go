// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/cybrota/scharf/git"
	"github.com/cybrota/scharf/logging"
	"github.com/cybrota/scharf/network"
)

var logger = logging.GetLogger(0)

// Color codes
const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	Gray    = "\033[37m"
	White   = "\033[97m"
)

// AuditRepository collects inventory details from current Git repository.
func AuditRepository(path FilePath) (*Inventory, error) {
	abs, err := filepath.Abs(filepath.Join(string(path)))
	if err != nil {
		logger.Error("failed to find absolute path", "err", err)
		return nil, fmt.Errorf("os: %w", err)
	}

	if !git.IsGitRepo(abs) {
		return nil, fmt.Errorf("The directory: %s is not a Git repository", abs)
	}

	paths := strings.Split(abs, "/")
	loc := filepath.Join(abs, ".github", "workflows")

	fileNames, err := ListFiles(FilePath(loc))
	if err != nil {
		return nil, fmt.Errorf("file error: %w", err)
	}

	var inventory Inventory
	// Process each file found in the directory.
	for _, fileName := range fileNames {
		f := filepath.Join(loc, string(*fileName))
		content, err := ReadFile(FilePath(f))
		if err != nil {
			if errors.Is(err, syscall.EISDIR) {
				continue // This is an accidental directory. Move to the next file
			} else {
				return nil, fmt.Errorf("file error: %w", err)
			}
		}

		found := findRegex.FindAll([]byte(content), -1)
		var matches []string
		for _, match := range found {
			matches = append(matches, string(match))
		}

		b, err := git.GetCurrentBranch(abs)
		if err != nil {
			return nil, fmt.Errorf("git error: %w", err)
		}
		if len(matches) > 0 {
			inventory.Records = append(inventory.Records, &InventoryRecord{
				Repository: paths[len(paths)-1],
				Branch:     b,
				FilePath:   f,
				Matches:    matches,
			})
		}
	}

	return &inventory, nil
}

// AutoFixRepository tries to match and replace third-party action references with SHA
// It uses SHA resolution to find accurate SHA
func AutoFixRepository(path FilePath, isDryRun bool) error {
	// Keep a cache for action SHA to avoid many network lookups
	resolver := network.NewSHAResolver()

	abs, err := filepath.Abs(filepath.Join(string(path)))
	if err != nil {
		logger.Error("failed to find absolute path", "err", err)
		return fmt.Errorf("os: %w", err)
	}

	if !git.IsGitRepo(abs) {
		return fmt.Errorf("The directory: %s is not a Git repository", abs)
	}

	workFlowDir := filepath.Join(abs, ".github", "workflows")
	fileNames, err := ListFiles(FilePath(workFlowDir))
	if err != nil {
		return fmt.Errorf("file error: %w", err)
	}

	for _, fileName := range fileNames {
		loc := filepath.Join(workFlowDir, string(*fileName))
		fContent, err := ReadFile(FilePath(loc))
		if err != nil {
			if errors.Is(err, syscall.EISDIR) {
				continue // This is an accidental directory. Move to the next file
			} else {
				return fmt.Errorf("file error: %w", err)
			}
		}

		contentStr := string(fContent)

		// -1: Match all
		fMatches := findRegex.FindAllStringSubmatch(contentStr, -1)
		if len(fMatches) > 0 {
			fmt.Printf("🪄 Fixing %s%s%s: \n", Yellow, string(*fileName), Reset)
			for _, finding := range fMatches {
				// 5 elements created by regex match
				// 0 - Action, 1 - Org, 2- Repo, 4 - Version or Branch
				if len(finding) >= 5 {
					action := finding[0]
					sha, err := resolver.Resolve(action)
					if err != nil {
						fmt.Printf("  '%s' -> %sCouldn't fix the reference: %s. Tag or branch not found on GitHub%s ⚠️\n", action, Magenta, finding[4], Reset)
						continue // Skip to next match
					}

					fixedAction := fmt.Sprintf("%s/%s@%s # %s", finding[1], finding[3], sha, finding[4])
					fmt.Printf("  '%s' -> '%s' ✅\n", action, fixedAction)

					subRegex := regexp.MustCompile(action)
					contentStr = subRegex.ReplaceAllString(contentStr, fixedAction)
				}
			}

			if !isDryRun {
				// Write back to workflow file with replaced SHA
				err = os.WriteFile(loc, []byte(contentStr), os.ModeAppend)
				if err != nil {
					logger.Error("Problem while fixing the action file", "file", fileName, "problem", err.Error())
				}
			}
			// Add padding
			fmt.Println()
		}
	}

	if isDryRun {
		fmt.Println("The displayed fixes are not staged. Re-run 'scharf autofix' and omit the flag '--dry-run' to apply fixes.")
	}
	return nil
}

// BuildRepoPath builds a repo path from arguments
// If repo is a local path, absolute path is returned
// If repo is a cloud URL, repository is cloned into a temporary directory for operation.
func BuildRepoPath(action string, args []string) (*FilePath, error) {
	if len(args) > 0 {
		repo := args[0]

		if strings.HasPrefix(repo, "https://") || strings.HasPrefix(repo, "git@") ||
			strings.HasPrefix(repo, "ssh://") {
			if action == "audit" || action == "autofix" {
				fmt.Printf("Cloning repository: %s%s%s\n", Green, repo, Reset)
				tmp_path, err := git.CloneRepoToTemp(repo)
				if err != nil {
					if strings.HasPrefix(repo, "https://") {
						return nil, fmt.Errorf("%sProblem encountered while cloning: %s.%s Use SSH instead of HTTPS, Ex: git@github.com:psf/requests.git", Red, repo, Reset)
					}
					return nil, fmt.Errorf("Problem encountered while cloning: %s. Maybe the repository is private ?", repo)
				}

				res := FilePath(tmp_path)
				fmt.Printf("Cloned %s%s%s into %s%s%s\n", Green, repo, Reset, Green, tmp_path, Reset)
				return &res, nil
			} else {
				return nil, fmt.Errorf("%sUnsupported action:%s %s", Red, repo, Reset)
			}
		} else {
			return nil, nil
		}
	}

	res := FilePath(".")
	// Default to current directory
	return &res, nil
}
