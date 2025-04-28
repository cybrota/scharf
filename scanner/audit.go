// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/cybrota/scharf/git"
	"github.com/cybrota/scharf/logging"
	"github.com/cybrota/scharf/network"
)

var logger = logging.GetLogger(0)

// AuditRepository collects inventory details from current Git repository.
func AuditRepository(regex *regexp.Regexp) (*Inventory, error) {

	if !git.IsGitRepo(".") {
		return nil, fmt.Errorf("The current directory is not a Git repository")
	}

	var inventory Inventory

	absPath, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("dir error: %w", err)
	}

	paths := strings.Split(absPath, "/")
	repo := &GitRepository{
		localPath: absPath,
		name:      paths[len(paths)-1],
	}
	workflowPath := fmt.Sprintf("%s/.github/workflows", absPath)

	fileNames, err := repo.ListFiles(workflowPath)
	if err != nil {
		return nil, fmt.Errorf("file error: %w", err)
	}

	// Process each file found in the directory.
	for _, fileName := range fileNames {
		fPath := fmt.Sprintf("%s/%s", workflowPath, fileName)
		content, err := repo.ReadFile(fPath)
		if err != nil {
			return nil, fmt.Errorf("file error: %w", err)
		}

		found := regex.FindAll([]byte(content), -1)
		var matches []string
		for _, match := range found {
			matches = append(matches, string(match))
		}

		b, err := git.GetCurrentBranch(absPath)
		if err != nil {
			return nil, fmt.Errorf("git error: %w", err)
		}

		if len(matches) > 0 {
			inventory.Records = append(inventory.Records, &InventoryRecord{
				Repository: repo.Name(),
				Branch:     b,
				FilePath:   fPath,
				Matches:    matches,
			})
		}
	}

	return &inventory, nil
}

// AutoFixRepository tries to match and replace third-party action references with SHA
// It uses SHA resolution to find accurate SHA
func AutoFixRepository(regex *regexp.Regexp, isDryRun bool) error {
	// Keep a cache for action SHA to avoid many network lookups
	resolver := network.NewSHAResolver()

	if isDryRun {
		fmt.Println("Running autofix in dryrun mode.")
	}

	if !git.IsGitRepo(".") {
		return fmt.Errorf("The current directory is not a Git repository")
	}
	absPath, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("dir error: %w", err)
	}

	paths := strings.Split(absPath, "/")
	repo := &GitRepository{
		localPath: absPath,
		name:      paths[len(paths)-1],
	}
	workflowPath := fmt.Sprintf("%s/.github/workflows", absPath)

	fileNames, err := repo.ListFiles(workflowPath)
	if err != nil {
		return fmt.Errorf("file error: %w", err)
	}

	for _, fileName := range fileNames {
		fPath := fmt.Sprintf("%s/%s", workflowPath, fileName)
		fContent, err := repo.ReadFile(fPath)
		if err != nil {
			return fmt.Errorf("file error: %w", err)
		}

		contentStr := string(fContent)
		fMatches := regex.FindAllStringSubmatch(contentStr, 4)

		if len(fMatches) > 0 {
			fmt.Printf("🪄 Fixing %s: \n", fileName)
			for _, finding := range fMatches {
				// 5 elements created by regex match
				// 0 - Action, 1 - Org, 2- Repo, 4 - Version or Branch
				if len(finding) >= 5 {
					action := finding[0]
					sha, err := resolver.Resolve(action)
					if err != nil {
						fmt.Printf(
							"  '%s' -> Couldn't fix as reference: %s is not found on GitHub ⚠️\n", action, finding[4])
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
				err = os.WriteFile(fPath, []byte(contentStr), os.ModeAppend)
				if err != nil {
					logger.Error("Problem while fixing the action file", "file", fileName, "problem", err.Error())
				}
			} else {
				fmt.Println("The displayed fixes are not staged. Re-run the 'scharf autofix' and omit the flag '--dry-run' to apply fixes.")
			}
		}
	}

	return nil
}
