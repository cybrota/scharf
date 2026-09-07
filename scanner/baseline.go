// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	gitlib "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	fdiff "github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// ClassifyRepositoryFindings compares current findings with the merge base of baseRef and HEAD.
// Workflow changes in the working tree are rejected because classifications must describe the bytes that were scanned.
func ClassifyRepositoryFindings(repoRoot, baseRef string, findings []ReferenceFinding) ([]FindingClassification, error) {
	repository, err := gitlib.PlainOpen(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("open repository for baseline: %w", err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		return nil, fmt.Errorf("open worktree for baseline: %w", err)
	}
	status, err := worktree.Status()
	if err != nil {
		return nil, fmt.Errorf("read worktree status for baseline: %w", err)
	}
	for fileName := range status {
		if isWorkflowPath(fileName) {
			return nil, fmt.Errorf("workflow %s has uncommitted changes; commit or discard them before changed-line analysis", fileName)
		}
	}

	headRef, err := repository.Head()
	if err != nil {
		return nil, fmt.Errorf("resolve HEAD for baseline: %w", err)
	}
	headCommit, err := repository.CommitObject(headRef.Hash())
	if err != nil {
		return nil, fmt.Errorf("read HEAD commit for baseline: %w", err)
	}
	baseHash, err := repository.ResolveRevision(plumbing.Revision(baseRef))
	if err != nil {
		return nil, fmt.Errorf("resolve baseline ref %q: %w", baseRef, err)
	}
	baseCommit, err := repository.CommitObject(*baseHash)
	if err != nil {
		return nil, fmt.Errorf("read baseline ref %q: %w", baseRef, err)
	}
	mergeBases, err := headCommit.MergeBase(baseCommit)
	if err != nil {
		return nil, fmt.Errorf("find merge base for %q: %w", baseRef, err)
	}
	if len(mergeBases) == 0 {
		return nil, fmt.Errorf("no merge base between HEAD and %q", baseRef)
	}
	mergeBase := mergeBases[0]
	baseTree, err := mergeBase.Tree()
	if err != nil {
		return nil, fmt.Errorf("read merge-base tree: %w", err)
	}
	headTree, err := headCommit.Tree()
	if err != nil {
		return nil, fmt.Errorf("read HEAD tree: %w", err)
	}

	baseFindings, err := scanWorkflowTree(baseTree)
	if err != nil {
		return nil, fmt.Errorf("scan baseline %q: %w", baseRef, err)
	}
	renames, changedLines, err := workflowChanges(baseTree, headTree)
	if err != nil {
		return nil, fmt.Errorf("compare baseline %q with HEAD: %w", baseRef, err)
	}

	remaining := make(map[string]map[string]int, len(baseFindings))
	for fileName, previous := range baseFindings {
		remaining[fileName] = make(map[string]int)
		for _, finding := range previous {
			remaining[fileName][canonicalReference(finding)]++
		}
	}

	classifications := make([]FindingClassification, len(findings))
	for i, finding := range findings {
		currentPath := repositoryRelativePath(repoRoot, finding.FilePath)
		classifications[i] = FindingClassification{
			Classified: true,
			New:        true,
			Changed:    changedLines[currentPath][finding.Line],
		}
	}
	// Consume baseline occurrences for unchanged lines first. Otherwise, a newly
	// inserted duplicate before an existing occurrence can steal its baseline slot.
	for i, finding := range findings {
		if classifications[i].Changed {
			continue
		}
		currentPath := repositoryRelativePath(repoRoot, finding.FilePath)
		basePath := currentPath
		if renamedFrom, ok := renames[currentPath]; ok {
			basePath = renamedFrom
		}
		key := canonicalReference(finding)
		if remaining[basePath][key] > 0 {
			remaining[basePath][key]--
			classifications[i].New = false
		}
	}
	for i, finding := range findings {
		if !classifications[i].Changed {
			continue
		}
		currentPath := repositoryRelativePath(repoRoot, finding.FilePath)
		basePath := currentPath
		if renamedFrom, ok := renames[currentPath]; ok {
			basePath = renamedFrom
		}
		key := canonicalReference(finding)
		if remaining[basePath][key] > 0 {
			remaining[basePath][key]--
			classifications[i].New = false
		}
	}
	return classifications, nil
}

// LoadRepositoryPolicyAtRevision loads policy from a trusted committed revision.
// A missing policy at that revision uses the secure default policy.
func LoadRepositoryPolicyAtRevision(repoRoot, revision string) (*Policy, string, error) {
	repository, err := gitlib.PlainOpen(repoRoot)
	if err != nil {
		return nil, "", fmt.Errorf("open repository for policy: %w", err)
	}
	hash, err := repository.ResolveRevision(plumbing.Revision(revision))
	if err != nil {
		return nil, "", fmt.Errorf("resolve policy revision %q: %w", revision, err)
	}
	commit, err := repository.CommitObject(*hash)
	if err != nil {
		return nil, "", fmt.Errorf("read policy revision %q: %w", revision, err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, "", fmt.Errorf("read policy tree %q: %w", revision, err)
	}
	file, err := tree.File(defaultPolicyFileName)
	if errors.Is(err, object.ErrFileNotFound) {
		return DefaultPolicy(), "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("read policy %s at %q: %w", defaultPolicyFileName, revision, err)
	}
	content, err := file.Contents()
	if err != nil {
		return nil, "", fmt.Errorf("read policy content at %q: %w", revision, err)
	}
	source := revision + ":" + defaultPolicyFileName
	policy, err := decodePolicy(strings.NewReader(content), source)
	if err != nil {
		return nil, source, err
	}
	return policy, source, nil
}

func scanWorkflowTree(tree *object.Tree) (map[string][]ReferenceFinding, error) {
	result := make(map[string][]ReferenceFinding)
	var scanErrors []error
	files := tree.Files()
	err := files.ForEach(func(file *object.File) error {
		if !isWorkflowPath(file.Name) {
			return nil
		}
		content, err := file.Contents()
		if err != nil {
			scanErrors = append(scanErrors, fmt.Errorf("read %s: %w", file.Name, err))
			return nil
		}
		findings, scanErr := ScanWorkflowReferences([]byte(content), file.Name)
		if len(findings) > 0 {
			result[file.Name] = findings
		}
		if scanErr != nil {
			scanErrors = append(scanErrors, scanErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, errors.Join(scanErrors...)
}

func workflowChanges(baseTree, headTree *object.Tree) (map[string]string, map[string]map[int]bool, error) {
	changes, err := object.DiffTreeWithOptions(context.Background(), baseTree, headTree, &object.DiffTreeOptions{
		DetectRenames: true,
		RenameScore:   60,
		RenameLimit:   1000,
	})
	if err != nil {
		return nil, nil, err
	}

	renames := make(map[string]string)
	changedLines := make(map[string]map[int]bool)
	for _, change := range changes {
		fromPath := filepath.ToSlash(change.From.Name)
		toPath := filepath.ToSlash(change.To.Name)
		if !isWorkflowPath(fromPath) && !isWorkflowPath(toPath) {
			continue
		}
		if fromPath != "" && toPath != "" && fromPath != toPath {
			renames[toPath] = fromPath
		}
		if toPath == "" {
			continue
		}
		patch, err := change.Patch()
		if err != nil {
			return nil, nil, fmt.Errorf("build patch for %s: %w", toPath, err)
		}
		lines := changedLines[toPath]
		if lines == nil {
			lines = make(map[int]bool)
			changedLines[toPath] = lines
		}
		for _, filePatch := range patch.FilePatches() {
			newLine := 1
			for _, chunk := range filePatch.Chunks() {
				count := diffLineCount(chunk.Content())
				switch chunk.Type() {
				case fdiff.Equal:
					newLine += count
				case fdiff.Add:
					for line := newLine; line < newLine+count; line++ {
						lines[line] = true
					}
					newLine += count
				case fdiff.Delete:
					// Deleted lines do not advance the right-side line counter.
				}
			}
		}
	}
	return renames, changedLines, nil
}

func diffLineCount(content string) int {
	if content == "" {
		return 0
	}
	count := strings.Count(content, "\n")
	if !strings.HasSuffix(content, "\n") {
		count++
	}
	return count
}

func isWorkflowPath(fileName string) bool {
	fileName = filepath.ToSlash(fileName)
	if pathDir(fileName) != ".github/workflows" {
		return false
	}
	extension := filepath.Ext(fileName)
	return extension == ".yml" || extension == ".yaml"
}

func pathDir(fileName string) string {
	index := strings.LastIndexByte(fileName, '/')
	if index < 0 {
		return "."
	}
	return fileName[:index]
}
