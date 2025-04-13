package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// AuditRepository collects inventory details from current Git repository.
func AuditRepository(regex *regexp.Regexp) (*Inventory, error) {

	if !IsGitRepo(".") {
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

		b, err := GetCurrentBranch(absPath)
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
