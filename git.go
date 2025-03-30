package main

import (
	"fmt"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

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
	// Iterate over each branch reference and add the short name to our list
	err = branches.ForEach(func(ref *plumbing.Reference) error {
		branchNames = append(branchNames, ref.Name().Short())
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
