// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cybrota/scharf/git"
	"github.com/cybrota/scharf/logging"
	"github.com/cybrota/scharf/network"
)

var logger = logging.GetLogger(0)

const SHA256NotAvailable = "N/A"

var newAuditResolver = func() network.Resolver {
	return network.NewSHAResolver()
}

// AssembleWorkflow builds printable workflows with structure suitable for formatting
func AssembleWorkflow(res network.Resolver, content []byte, fileName string, filePath string) (*Workflow, error) {
	analysis, err := AnalyzeWorkflow(res, content, fileName, filePath)
	return &analysis.Workflow, err
}

// WorkflowAnalysis pairs the v1 report model with structured edit metadata.
type WorkflowAnalysis struct {
	Workflow Workflow           `json:"workflow"`
	Findings []ReferenceFinding `json:"findings"`
}

// AnalyzeWorkflow resolves mutable references while retaining structured source metadata.
func AnalyzeWorkflow(res network.Resolver, content []byte, fileName string, filePath string) (*WorkflowAnalysis, error) {
	findings, scanErr := ScanWorkflowReferences(content, filePath)
	issues := make([]Finding, 0, len(findings))
	for i := range findings {
		var fm string
		finding := &findings[i]
		lookup := fmt.Sprintf("%s@%s", finding.Repository, finding.Ref)
		finding.Description = fmt.Sprintf("Unpinned GitHub Action: uses `%s`", finding.Original)
		resolvedSHA, err := res.Resolve(lookup)

		if err != nil {
			fm = fmt.Sprintf("Reference '%s' is not found on GitHub. Try 'scharf list %s' to see available versions.", finding.Ref, finding.Repository)
			resolvedSHA = SHA256NotAvailable
		} else {
			fm = fmt.Sprintf("Pin `%s` to %s", finding.Original, resolvedSHA)
		}
		finding.FixMessage = fm
		finding.FixSHA = resolvedSHA
		issues = append(issues, finding.legacy())
	}

	return &WorkflowAnalysis{
		Workflow: Workflow{Name: filePath, FilePath: filePath, Issues: issues},
		Findings: findings,
	}, scanErr
}

// AuditResult contains findings and any file errors from one repository scan.
type AuditResult struct {
	Status    ScanStatus         `json:"status"`
	Complete  bool               `json:"complete"`
	Workflows []Workflow         `json:"findings"`
	Details   []ReferenceFinding `json:"details,omitempty"`
	Errors    []ScanError        `json:"errors,omitempty"`
	analyses  []*WorkflowAnalysis
}

func (result *AuditResult) setStatus() {
	findingCount := 0
	for _, workflow := range result.Workflows {
		findingCount += len(workflow.Issues)
	}
	result.Status, result.Complete = scanStatus(findingCount, result.Errors)
}

// Err returns an aggregate error when one or more files were not scanned.
func (result *AuditResult) Err() error {
	if result == nil || len(result.Errors) == 0 {
		return nil
	}
	return &IncompleteScanError{Errors: result.Errors}
}

// AuditRepository preserves the v1 signature while returning partial workflows with incomplete errors.
func AuditRepository(path FilePath) (*[]Workflow, error) {
	result, err := AuditRepositoryResult(path)
	if result == nil {
		return nil, err
	}
	return &result.Workflows, err
}

// AuditRepositoryResult returns findings, edit metadata, and explicit completion state.
func AuditRepositoryResult(path FilePath) (*AuditResult, error) {
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

	fileNames, err := ListWorkflowFiles(FilePath(loc))
	if err != nil {
		result := &AuditResult{Errors: []ScanError{NewScanError(loc, err)}}
		result.setStatus()
		return result, result.Err()
	}

	result := &AuditResult{}
	res := newAuditResolver()
	// Process each file found in the directory.
	for _, fileName := range fileNames {
		f := string(fileName)
		content, err := ReadFile(fileName)
		if err != nil {
			result.Errors = append(result.Errors, NewScanError(f, err))
			continue
		}

		analysis, scanErr := AnalyzeWorkflow(res, content, filepath.Base(f), f)
		if analysis != nil && len(analysis.Workflow.Issues) > 0 {
			result.Workflows = append(result.Workflows, analysis.Workflow)
			result.Details = append(result.Details, analysis.Findings...)
			result.analyses = append(result.analyses, analysis)
		}
		if scanErr != nil {
			result.Errors = append(result.Errors, NewScanError(f, scanErr))
		}
	}

	result.setStatus()
	return result, result.Err()
}

// AutoFixRepository tries to match and replace third-party action references with SHA
// It uses SHA resolution to find accurate SHA
func AutoFixRepository(path FilePath, isDryRun bool) error {
	result, err := AuditRepositoryResult(path)
	if err != nil {
		return err
	}

	for _, analysis := range result.analyses {
		fmt.Printf("🪄 Fixing %s%s%s: \n", Cyan, analysis.Workflow.FilePath, Reset)
		if err := ApplyReferenceFixesInFile(analysis.Workflow.FilePath, analysis.Findings, isDryRun); err != nil {
			return err
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
	return BuildRepoPathWithWriter(action, args, os.Stderr)
}

// BuildRepoPathWithWriter routes clone diagnostics separately from machine-readable output.
func BuildRepoPathWithWriter(action string, args []string, diagnostic io.Writer) (*FilePath, error) {
	if len(args) > 0 {
		repo := args[0]

		if strings.HasPrefix(repo, "https://") || strings.HasPrefix(repo, "git@") ||
			strings.HasPrefix(repo, "ssh://") {
			if action == "audit" || action == "autofix" || action == "upgrade-all-sha" {
				fmt.Fprintf(diagnostic, "Cloning repository: %s%s%s\n", Blue, repo, Reset)
				tmp_path, err := git.CloneRepoToTempWithWriter(repo, diagnostic)
				if err != nil {
					if strings.HasPrefix(repo, "https://") {
						return nil, fmt.Errorf("%sProblem encountered while cloning: %s.%s Use SSH instead of HTTPS, Ex: git@github.com:psf/requests.git", Red, repo, Reset)
					}
					return nil, fmt.Errorf("Problem encountered while cloning: %s. Maybe the repository is private ?", repo)
				}

				res := FilePath(tmp_path)
				fmt.Fprintf(diagnostic, "Cloned %s%s%s into %s%s%s\n", Blue, repo, Reset, Blue, tmp_path, Reset)
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
