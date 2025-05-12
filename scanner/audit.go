// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cybrota/scharf/git"
	"github.com/cybrota/scharf/logging"
	"github.com/cybrota/scharf/network"
)

var logger = logging.GetLogger(0)

const SHA256NotAvailable = "N/A"

// AssembleWorkflow builds printable workflows with structure suitable for formatting
func AssembleWorkflow(res network.Resolver, content []byte, fileName string, filePath string) (*Workflow, error) {
	matches, err := ScanContentWithPosition(content, findRegex)
	if err != nil {
		return nil, fmt.Errorf("%sThere is a problem scanning the given file%s%s", Yellow, fileName, Reset)
	}
	// 4) Map matches -> findings
	var issues []Finding
	for _, m := range matches {
		var fm string
		// m.Text is something like "actions/checkout@v1.2"
		parts := strings.SplitN(m.Text, "@", 2)
		action := parts[0]
		version := parts[1]

		original := fmt.Sprintf("%s@%s", action, version)
		msg := fmt.Sprintf("Unpinned GitHub Action: uses `%s`", m.Text)
		resolvedSHA, err := res.Resolve(original)

		if err != nil {
			fm = fmt.Sprintf("Reference '%s' is not found on GitHub. Try 'scharf list %s' to see available versions.", version, action)
			resolvedSHA = SHA256NotAvailable
		} else {
			// Build a human-readable message & a suggested fix
			fm = fmt.Sprintf("Pin `%s` to %s", action, resolvedSHA)
		}

		issues = append(issues, Finding{
			Line:        m.Line,
			Column:      m.Col,
			Description: msg,
			FixMsg:      fm,
			FixSHA:      resolvedSHA,
			Version:     version,
			Action:      action,
			Original:    original,
		})
	}

	// 5) Assemble the Workflow
	return &Workflow{
		Name:     filePath,
		FilePath: filePath,
		Issues:   issues,
	}, nil
}

// AuditRepository collects inventory details from current Git repository.
func AuditRepository(path FilePath) (*[]Workflow, error) {
	abs, err := filepath.Abs(filepath.Join(string(path)))
	if err != nil {
		logger.Error("failed to find absolute path", "err", err)
		return nil, fmt.Errorf("os: %w", err)
	}

	if !git.IsGitRepo(abs) {
		return nil, fmt.Errorf("The directory: %s is not a Git repository", abs)
	}

	// paths := strings.Split(abs, "/")
	loc := filepath.Join(abs, ".github", "workflows")

	fileNames, err := ListFiles(FilePath(loc))
	if err != nil {
		return nil, fmt.Errorf("file error: %w", err)
	}

	fmt.Printf("No of workflows: %s%d%s\n\n", Blue, len(fileNames), Reset)

	var wfs []Workflow
	res := network.NewSHAResolver()
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

		wf, _ := AssembleWorkflow(res, content, string(*fileName), f)
		if len(wf.Issues) > 0 {
			wfs = append(wfs, *wf)
		}
	}

	return &wfs, nil
}

// AutoFixRepository tries to match and replace third-party action references with SHA
// It uses SHA resolution to find accurate SHA
func AutoFixRepository(path FilePath, isDryRun bool) error {
	// Keep a cache for action SHA to avoid many network lookups
	// resolver := network.NewSHAResolver()

	// abs, err := filepath.Abs(filepath.Join(string(path)))
	// if err != nil {
	// 	logger.Error("failed to find absolute path", "err", err)
	// 	return fmt.Errorf("os: %w", err)
	// }

	// if !git.IsGitRepo(abs) {
	// 	return fmt.Errorf("The directory: %s is not a Git repository", abs)
	// }

	// workFlowDir := filepath.Join(abs, ".github", "workflows")
	// fileNames, err := ListFiles(FilePath(workFlowDir))
	// if err != nil {
	// 	return fmt.Errorf("file error: %w", err)
	// }

	// for _, fileName := range fileNames {
	// 	loc := filepath.Join(workFlowDir, string(*fileName))
	// 	fContent, err := ReadFile(FilePath(loc))
	// 	if err != nil {
	// 		if errors.Is(err, syscall.EISDIR) {
	// 			continue // This is an accidental directory. Move to the next file
	// 		} else {
	// 			return fmt.Errorf("file error: %w", err)
	// 		}
	// 	}

	// 	contentStr := string(fContent)

	// 	// -1: Match all
	// 	fMatches := findRegex.FindAllStringSubmatch(contentStr, -1)
	// 	if len(fMatches) > 0 {
	// 		fmt.Printf("🪄 Fixing %s%s%s: \n", Cyan, loc, Reset)
	// 		for _, finding := range fMatches {
	// 			// 3 elements created by regex match
	// 			// 0 - Action, 1 - Org, 2- Repo
	// 			if len(finding) >= 3 {
	// 				action := finding[0]
	// 				version := strings.Split(action, "@")[1]
	// 				sha, err := resolver.Resolve(action)
	// 				if err != nil {
	// 					fmt.Printf("  - %sWarning%s: '%s' -> %sCouldn't fix the reference: %s. Tag or branch not found on GitHub%s ⚠️\n", Yellow, Reset, action, Yellow, version, Reset)
	// 					continue // Skip to next match
	// 				}
	// 				fixedAction := fmt.Sprintf("%s@%s # %s", action, sha, version)
	// 				fmt.Printf("  - %sFixed%s: Pinned '%s' to '%s' \n", Green, Reset, action, fixedAction)

	// 				subRegex := regexp.MustCompile(action)
	// 				contentStr = subRegex.ReplaceAllString(contentStr, fixedAction)
	// 			}
	// 		}

	// 		if !isDryRun {
	// 			// Write back to workflow file with replaced SHA
	// 			err = os.WriteFile(loc, []byte(contentStr), os.ModeAppend)
	// 			if err != nil {
	// 				logger.Error("Problem while fixing the action file", "file", fileName, "problem", err.Error())
	// 			}
	// 		}
	// 		// Add padding
	// 		fmt.Println()
	// 	}
	// }

	// if isDryRun {
	// 	fmt.Println("The displayed fixes are not staged. Re-run 'scharf autofix' and omit the flag '--dry-run' to apply fixes.")
	// }
	// return nil
	//

	// abs, err := filepath.Abs(filepath.Join(string(path)))
	// if err != nil {
	// 	logger.Error("failed to find absolute path", "err", err)
	// 	return fmt.Errorf("os: %w", err)
	// }

	// if !git.IsGitRepo(abs) {
	// 	return fmt.Errorf("The directory: %s is not a Git repository", abs)
	// }

	// fmt.Printf("Autofixing reposotiry at: %s%s%s\n", Blue, abs, Reset)

	// // paths := strings.Split(abs, "/")
	// loc := filepath.Join(abs, ".github", "workflows")

	// fileNames, err := ListFiles(FilePath(loc))
	// if err != nil {
	// 	return fmt.Errorf("file error: %w", err)
	// }

	// fmt.Printf("No of workflows: %s%d%s\n\n", Blue, len(fileNames), Reset)

	// var wfs []Workflow
	// res := network.NewSHAResolver()
	// // Process each file found in the directory.
	// for _, fileName := range fileNames {
	// 	f := filepath.Join(loc, string(*fileName))
	// 	content, err := ReadFile(FilePath(f))
	// 	if err != nil {
	// 		if errors.Is(err, syscall.EISDIR) {
	// 			continue // This is an accidental directory. Move to the next file
	// 		} else {
	// 			return fmt.Errorf("file error: %w", err)
	// 		}
	// 	}

	// 	wf, _ := AssembleWorkflow(res, content, string(*fileName), f)
	// 	if len(wf.Issues) > 0 {
	// 		wfs = append(wfs, *wf)
	// 	}
	// }
	// if err != nil {
	// 	return err
	// }

	wfs, err := AuditRepository(path)
	if err != nil {
		return err
	}

	for _, wf := range *wfs {
		fmt.Printf("🪄 Fixing %s%s%s: \n", Cyan, wf.FilePath, Reset)
		ApplyFixesInFile(wf, isDryRun)
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
				fmt.Printf("Cloning repository: %s%s%s\n", Blue, repo, Reset)
				tmp_path, err := git.CloneRepoToTemp(repo)
				if err != nil {
					if strings.HasPrefix(repo, "https://") {
						return nil, fmt.Errorf("%sProblem encountered while cloning: %s.%s Use SSH instead of HTTPS, Ex: git@github.com:psf/requests.git", Red, repo, Reset)
					}
					return nil, fmt.Errorf("Problem encountered while cloning: %s. Maybe the repository is private ?", repo)
				}

				res := FilePath(tmp_path)
				fmt.Printf("Cloned %s%s%s into %s%s%s\n", Blue, repo, Reset, Blue, tmp_path, Reset)
				return &res, nil
			} else {
				return nil, fmt.Errorf("%sUnsupported action:%s %s", Red, repo, Reset)
			}
		} else {
			res := FilePath(repo)
			return &res, nil
		}
	}

	res := FilePath(".")
	// Default to current directory
	return &res, nil
}
