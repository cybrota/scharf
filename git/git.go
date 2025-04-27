// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package git is to perform all local Git operations required by application

package git

import (
	"fmt"
	"slices"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// ListTags lists all tags available for a given repository
func ListTags(repo *git.Repository) ([]string, error) {
	var tags []string
	tagIter, err := repo.Tags()

	if err != nil {
		return nil, fmt.Errorf("git error: %w", err)
	}
	tagIter.ForEach(func(ref *plumbing.Reference) error {
		tags = append(tags, ref.Name().Short())
		return nil
	})

	return tags, nil
}

// ListGitBranches opens the Git repository located at repoPath
// and returns a slice of branch names found in the repository.
func ListGitBranches(repoPath string) ([]string, error) {
	// Open the repository at the given path
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	// Get an iterator for the repository's branches
	branches, err := repo.References()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve branches: %w", err)
	}

	var branchNames []string
	tags, err := ListTags(repo)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve tags: %w", err)
	}

	// Iterate over each branch reference and add the short name to our list
	err = branches.ForEach(func(ref *plumbing.Reference) error {
		if !slices.Contains(tags, ref.Name().Short()) {
			branchNames = append(branchNames, ref.Name().Short())
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed during iteration: %w", err)
	}

	return branchNames, nil
}

// CheckoutGitBranch switches the repository at repoPath to the branch specified by branchName.
func CheckoutGitBranch(repoPath, branchName string) error {
	// Open the repository
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return fmt.Errorf("failed to open repository: %w", err)
	}

	// Get the working tree
	worktree, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	// Perform checkout to the specified branch.
	// Note: This assumes the branch already exists.
	err = worktree.Checkout(&git.CheckoutOptions{
		Branch: plumbing.NewBranchReferenceName(branchName),
	})
	if err != nil {
		return fmt.Errorf("failed to checkout branch: %w", err)
	}

	return nil
}

// GetCurrentBranch returns the head ref of a Git Repository
func GetCurrentBranch(path string) (string, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return "", err
	}

	head, err := repo.Head()
	if err != nil {
		return "", err
	}

	return head.Name().String(), nil
}

// IsGitRepo detects if a given repository is Git initialized
func IsGitRepo(path string) bool {
	_, err := git.PlainOpen(path)
	if err != nil {
		return false
	}

	return true
}

// CloneRepo clones a given URL
// func CloneRepo(path string) error {

// }
