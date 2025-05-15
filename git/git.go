// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package git is to perform all local Git operations required by application

package git

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
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

// CloneRepoToTemp clones the given GitHub repository URL (https:// or ssh:// or git@...)
// into a newly-created temporary directory under /tmp and returns the local path.
func CloneRepoToTemp(repoURL string) (string, error) {
	tmpDir, err := os.MkdirTemp("/tmp", "scharf-repo-*")
	if err != nil {
		return "", fmt.Errorf("creating temp dir: %w", err)
	}

	// 1) Try native git
	if gitPath, err := exec.LookPath("git"); err == nil {
		cmd := exec.Command(
			gitPath,
			"clone",
			"--depth", "1", // shallow
			repoURL,
			tmpDir,
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err == nil {
			return tmpDir, nil
		}
		// if native clone failed, we'll fall back
		fmt.Fprintf(os.Stderr, "native git clone failed: %v; falling back to go-git\n", err)
	}

	// 2) If native Git is not available, use go-git shallow clone
	opts := &git.CloneOptions{
		URL:          repoURL,
		Progress:     os.Stdout,
		Depth:        1,    // <-- shallow
		SingleBranch: true, // <-- single branch
	}

	if strings.HasPrefix(repoURL, "git@") ||
		strings.HasPrefix(repoURL, "ssh://") {
		// this will look for ~/.ssh/id_rsa (no passphrase)
		auth, sshErr := ssh.NewPublicKeysFromFile(
			"git",
			filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa"),
			"",
		)
		if sshErr != nil {
			return "", fmt.Errorf("setting up SSH auth: %w", sshErr)
		}
		opts.Auth = auth
	}

	// clone the repo and cleanup left overs if op errors
	if _, err = git.PlainClone(tmpDir, false, opts); err != nil {
		os.RemoveAll(tmpDir)
		if err == transport.ErrAuthenticationRequired {
			return "", fmt.Errorf("authentication required for %s", repoURL)
		}
		return "", fmt.Errorf("cloning %s: %w", repoURL, err)
	}

	return tmpDir, nil
}
