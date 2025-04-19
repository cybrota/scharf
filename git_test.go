package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// CheckIfError should be used to naively panics if an error is not nil.
func CheckIfError(err error) {
	if err == nil {
		return
	}

	fmt.Printf("\x1b[31;1m%s\x1b[0m\n", fmt.Sprintf("error: %s", err))
	os.Exit(1)
}

// createTestRepo initializes a brand-new repository in a temporary directory,
// creates one or more branches, and returns the path to the repo and a cleanup function.
//
// "branches" is a list of branch names (excluding "master" which is always there by default).
// This helper also makes a single commit on each new branch (just enough so they exist).
func createTestRepo(t *testing.T, branches, tags []string) (string, func()) {
	t.Helper()

	// Create a temporary directory
	// // - at the end is for a random string to be attached by MkdirTemp
	dir, err := os.MkdirTemp("", "example-git-repo-for-test-")
	CheckIfError(err)

	filename := filepath.Join(dir, "example-git-file")
	err = os.WriteFile(filename, []byte("commit content"), 0644)
	CheckIfError(err)

	cleanup := func() {
		os.RemoveAll(dir)
	}

	// Initialize empty git repository
	repo, err := git.PlainInit(dir, false)
	CheckIfError(err)

	// By default, master will exist right after init, but let's do a trivial commit.
	w, err := repo.Worktree()
	CheckIfError(err)

	_, err = w.Add("example-git-file")
	CheckIfError(err)

	_, err = w.Commit("example go-git commit", &git.CommitOptions{
		AllowEmptyCommits: true,
		Author: &object.Signature{
			Name:  "John Doe",
			Email: "john@doe.org",
			When:  time.Now(),
		},
	})
	CheckIfError(err)

	// Create additional branches
	for _, b := range branches {
		// Create a branch in config
		refName := plumbing.NewBranchReferenceName(b)
		filename := filepath.Join(dir, fmt.Sprintf("example-git-file-%s", b))
		err = os.WriteFile(filename, []byte("commit content"), 0644)
		CheckIfError(err)

		err = repo.CreateBranch(&config.Branch{
			Name:   b,
			Remote: "origin",
		})
		CheckIfError(err)

		// Actually create the reference by checking out the new branch and committing
		err = w.Checkout(&git.CheckoutOptions{Branch: refName, Create: true})
		CheckIfError(err)

		_, err = w.Commit(fmt.Sprintf("commit on %s", b), &git.CommitOptions{
			AllowEmptyCommits: true,
			Author: &object.Signature{
				Name:  "John Doe",
				Email: "john@doe.org",
				When:  time.Now(),
			},
		})
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	}

	// Create tags
	for _, tag := range tags {
		refName := plumbing.NewTagReferenceName(tag)
		tag := plumbing.NewHashReference(refName, plumbing.ZeroHash)
		err = repo.Storer.SetReference(tag)
		if err != nil {
			t.Fatalf("failed to create tag %s: %v", tag, err)
		}
	}

	// Return to master
	masterRef := plumbing.NewBranchReferenceName("master")
	err = w.Checkout(&git.CheckoutOptions{Branch: masterRef})
	CheckIfError(err)

	return dir, cleanup
}

func TestListGitBranches(t *testing.T) {
	tests := []struct {
		name           string
		branchesToMake []string
		expectErr      bool
		expectContains []string
	}{
		{
			name:           "only master branch",
			branchesToMake: []string{}, // no additional branches
			expectErr:      false,
			// We expect to see 'master' only in the results
			expectContains: []string{"master"},
		},
		{
			name:           "multiple branches",
			branchesToMake: []string{"dev", "feature-1", "feature-2"},
			expectErr:      false,
			// We expect to see all the new branches plus master
			expectContains: []string{"master", "dev", "feature-1", "feature-2"},
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			repoPath, cleanup := createTestRepo(t, tt.branchesToMake, []string{})
			defer cleanup()

			got, err := ListGitBranches(repoPath)
			if (err != nil) != tt.expectErr {
				t.Fatalf("ListGitBranches() error = %v, expectErr = %v", err, tt.expectErr)
			}
			for _, branch := range tt.expectContains {
				found := slices.Contains(got, branch)
				if !found {
					t.Errorf("Expected branch %q to be in list, but it was not.\nGot branches: %v", branch, got)
				}
			}
		})
	}
}

func TestListTags(t *testing.T) {
	tests := []struct {
		name         string
		tagsToMake   []string
		expectedTags []string
	}{
		{
			name:         "list tags in repository with multiple tags",
			tagsToMake:   []string{"tag1", "tag2", "tag3"},
			expectedTags: []string{"tag1", "tag2", "tag3"},
		},
		{
			name:         "list tags in repository with no tags",
			tagsToMake:   []string{},
			expectedTags: nil,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			repoPath, cleanup := createTestRepo(t, []string{}, tt.tagsToMake)
			defer cleanup()

			repo, err := git.PlainOpen(repoPath)
			if err != nil {
				t.Fatalf("failed to open repository: %v", err)
			}

			tags, err := ListTags(repo)
			if err != nil {
				t.Fatalf("error listing tags: %v", err)
			}
			// Check if the retrieved tags match the expected tags
			if !reflect.DeepEqual(tags, tt.expectedTags) {
				t.Errorf("got tags %v, want %v", tags, tt.expectedTags)
			}
		})
	}
}

func TestCheckoutGitBranch(t *testing.T) {
	tests := []struct {
		name           string
		branchesToMake []string
		checkoutBranch string
		expectErr      bool
	}{
		{
			name:           "checkout existing branch",
			branchesToMake: []string{"dev"},
			checkoutBranch: "dev",
			expectErr:      false,
		},
		{
			name:           "checkout non-existent branch",
			branchesToMake: []string{"dev"},
			checkoutBranch: "no-such-branch",
			expectErr:      true,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			repoPath, cleanup := createTestRepo(t, tt.branchesToMake, []string{})
			defer cleanup()

			err := CheckoutGitBranch(repoPath, tt.checkoutBranch)
			if tt.expectErr && err == nil {
				t.Fatalf("expected an error but got nil for branch '%s'", tt.checkoutBranch)
			}
			if !tt.expectErr && err != nil {
				t.Fatalf("did not expect an error but got: %v", err)
			}

			// If we expected no error, verify HEAD is on the correct branch
			if !tt.expectErr {
				repo, openErr := git.PlainOpen(repoPath)
				if openErr != nil {
					t.Fatalf("failed to open repo to verify checkout: %v", openErr)
				}
				headRef, headErr := repo.Head()
				if headErr != nil {
					t.Fatalf("failed to get HEAD ref: %v", headErr)
				}

				wantRefName := plumbing.NewBranchReferenceName(tt.checkoutBranch)
				if !reflect.DeepEqual(headRef.Name(), wantRefName) {
					t.Errorf("HEAD ref = %s, want %s", headRef.Name(), wantRefName)
				}
			}
		})
	}
}

// Test for GetCurrentBranch function expecting master.
func TestGetCurrentBranch(t *testing.T) {
	t.Run("valid git repo (master expected)", func(t *testing.T) {
		// createTestRepo will create additional branches but end with HEAD on "master"
		repoPath, cleanup := createTestRepo(t, []string{"dev"}, []string{})
		defer cleanup()

		branch, err := GetCurrentBranch(repoPath)
		if err != nil {
			t.Fatalf("GetCurrentBranch() error = %v", err)
		}

		// We expect the head to be on "master" since the helper returns to master.
		expected := plumbing.NewBranchReferenceName("master").String()
		if branch != expected {
			t.Errorf("GetCurrentBranch() = %s, want %s", branch, expected)
		}
	})

	t.Run("invalid git repo", func(t *testing.T) {
		// Create a temporary non-git directory.
		tmpDir, err := os.MkdirTemp("", "nogitrepo")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		_, err = GetCurrentBranch(tmpDir)
		if err == nil {
			t.Fatalf("expected an error for non-git repo, but got nil")
		}
	})
}

// Test for IsGitRepo function.
func TestIsGitRepo(t *testing.T) {
	t.Run("valid git repo", func(t *testing.T) {
		// createTestRepo initializes a proper Git repository.
		repoPath, cleanup := createTestRepo(t, []string{"dev"}, []string{})
		defer cleanup()

		if !IsGitRepo(repoPath) {
			t.Errorf("IsGitRepo() returned false, want true for a valid git repo")
		}
	})

	t.Run("invalid git repo", func(t *testing.T) {
		// Create a temporary directory that isn't a Git repository.
		tmpDir, err := os.MkdirTemp("", "nogitrepo")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		if IsGitRepo(tmpDir) {
			t.Errorf("IsGitRepo() returned true, want false for a non-git repo")
		}
	})
}
