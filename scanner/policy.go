// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	PolicyVersion            = 1
	MutableReferenceRuleID   = "SCHARF001"
	ScanIncompleteRuleID     = "SCHARF_SCAN_INCOMPLETE"
	fullCommitSHARequirement = "full-commit-sha"
	defaultPolicyFileName    = ".scharf-policy.yml"
)

// Policy describes repository policy for mutable GitHub Actions references.
type Policy struct {
	Version         int               `yaml:"version" json:"version"`
	AllowCLIIgnores *bool             `yaml:"allow_cli_ignores,omitempty" json:"allow_cli_ignores,omitempty"`
	Rules           []PolicyRule      `yaml:"rules,omitempty" json:"rules"`
	Baseline        PolicyBaseline    `yaml:"baseline,omitempty" json:"baseline,omitempty"`
	Exceptions      []PolicyException `yaml:"exceptions,omitempty" json:"exceptions,omitempty"`
}

// PolicyRule applies an immutable-reference requirement to matching repositories and workflow paths.
type PolicyRule struct {
	ID           string   `yaml:"id" json:"id"`
	Requirement  string   `yaml:"requirement" json:"requirement"`
	Severity     string   `yaml:"severity,omitempty" json:"severity"`
	Repositories []string `yaml:"repositories,omitempty" json:"repositories,omitempty"`
	Paths        []string `yaml:"paths,omitempty" json:"paths,omitempty"`
}

// PolicyBaseline controls gradual rollout against an existing Git revision.
type PolicyBaseline struct {
	Ref  string `yaml:"ref,omitempty" json:"ref,omitempty"`
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`
}

// PolicyException is an accountable, time-bound exception.
type PolicyException struct {
	ID         string         `yaml:"id" json:"id"`
	Match      ExceptionMatch `yaml:"match" json:"match"`
	Owner      string         `yaml:"owner" json:"owner"`
	Rationale  string         `yaml:"rationale" json:"rationale"`
	ApprovedBy string         `yaml:"approved_by" json:"approved_by"`
	Approval   string         `yaml:"approval" json:"approval"`
	Expires    string         `yaml:"expires" json:"expires"`
	expiresAt  time.Time
}

// ExceptionMatch identifies only the intended action references. All populated fields are ANDed.
type ExceptionMatch struct {
	Repository string   `yaml:"repository" json:"repository"`
	Subpath    string   `yaml:"subpath,omitempty" json:"subpath,omitempty"`
	Ref        string   `yaml:"ref,omitempty" json:"ref,omitempty"`
	Paths      []string `yaml:"paths,omitempty" json:"paths,omitempty"`
}

// FindingClassification records baseline and changed-line state for one current finding.
type FindingClassification struct {
	Classified bool `json:"classified"`
	New        bool `json:"new"`
	Changed    bool `json:"changed_line"`
}

// PolicyFindingState explains how policy treated a mutable reference.
type PolicyFindingState string

const (
	PolicyFindingViolation   PolicyFindingState = "violation"
	PolicyFindingExcepted    PolicyFindingState = "active-exception"
	PolicyFindingExpired     PolicyFindingState = "expired-exception"
	PolicyFindingIgnored     PolicyFindingState = "cli-ignore"
	PolicyFindingBaseline    PolicyFindingState = "baseline"
	PolicyFindingUnchanged   PolicyFindingState = "unchanged-line"
	PolicyFindingOutsideRule PolicyFindingState = "outside-policy"
	PolicyOutcomePass                           = "pass"
	PolicyOutcomeFail                           = "violations"
	PolicyOutcomeIncomplete                     = "incomplete"
)

// EvaluatedFinding combines scanner details with policy and rollout decisions.
type EvaluatedFinding struct {
	RuleID         string                `json:"rule_id"`
	Severity       string                `json:"severity"`
	FilePath       string                `json:"file"`
	Reference      ReferenceFinding      `json:"reference"`
	Classification FindingClassification `json:"classification"`
	State          PolicyFindingState    `json:"exception_status"`
	ExceptionID    string                `json:"exception_id,omitempty"`
	Blocking       bool                  `json:"blocking"`
	Message        string                `json:"message"`
	Remediation    string                `json:"remediation"`
}

// PolicyReport preserves scan completeness while reporting the separate policy outcome.
type PolicyReport struct {
	Status         ScanStatus         `json:"status"`
	Complete       bool               `json:"complete"`
	Outcome        string             `json:"outcome"`
	BaselineRef    string             `json:"baseline_ref,omitempty"`
	Findings       []EvaluatedFinding `json:"findings"`
	Errors         []ScanError        `json:"errors,omitempty"`
	ViolationCount int                `json:"violation_count"`
}

// PolicyEvaluationOptions supplies transient exceptions and revision classifications.
type PolicyEvaluationOptions struct {
	CLIExceptions    []string
	Now              time.Time
	Classifications  []FindingClassification
	ChangedLinesOnly bool
}

type compiledCLIException struct {
	source     string
	repository string
	subpath    string
	ref        string
	regex      *regexp.Regexp
}

// DefaultPolicy enforces full commit SHAs for every parsed external action reference.
func DefaultPolicy() *Policy {
	allow := true
	return &Policy{
		Version:         PolicyVersion,
		AllowCLIIgnores: &allow,
		Rules: []PolicyRule{{
			ID:          MutableReferenceRuleID,
			Requirement: fullCommitSHARequirement,
			Severity:    "error",
		}},
	}
}

// LoadRepositoryPolicy loads an explicit policy or discovers .scharf-policy.yml at the repository root.
// It returns a default policy when no discovered policy exists.
func LoadRepositoryPolicy(repoRoot, explicitPath string) (*Policy, string, error) {
	policyPath := explicitPath
	if policyPath == "" {
		policyPath = filepath.Join(repoRoot, defaultPolicyFileName)
		if _, err := os.Stat(policyPath); errors.Is(err, os.ErrNotExist) {
			return DefaultPolicy(), "", nil
		} else if err != nil {
			return nil, policyPath, fmt.Errorf("stat policy %s: %w", policyPath, err)
		}
	}

	policy, err := LoadPolicy(policyPath)
	if err != nil {
		return nil, policyPath, err
	}
	return policy, policyPath, nil
}

// LoadPolicy strictly parses and validates one versioned policy file.
func LoadPolicy(filePath string) (*Policy, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open policy %s: %w", filePath, err)
	}
	defer func() { _ = file.Close() }()
	return decodePolicy(file, filePath)
}

func decodePolicy(reader io.Reader, source string) (*Policy, error) {
	decoder := yaml.NewDecoder(reader)
	decoder.KnownFields(true)
	var policy Policy
	if err := decoder.Decode(&policy); err != nil {
		return nil, fmt.Errorf("parse policy %s: %w", source, err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return nil, fmt.Errorf("parse policy %s: multiple YAML documents are not supported", source)
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse policy %s: %w", source, err)
	}
	if err := policy.validate(); err != nil {
		return nil, fmt.Errorf("invalid policy %s: %w", source, err)
	}
	return &policy, nil
}

func (policy *Policy) validate() error {
	if policy.Version != PolicyVersion {
		return fmt.Errorf("version must be %d", PolicyVersion)
	}
	if policy.AllowCLIIgnores == nil {
		allow := true
		policy.AllowCLIIgnores = &allow
	}
	if len(policy.Rules) == 0 {
		policy.Rules = DefaultPolicy().Rules
	}

	seenRules := make(map[string]struct{}, len(policy.Rules))
	for i := range policy.Rules {
		rule := &policy.Rules[i]
		if !validRuleID(rule.ID) {
			return fmt.Errorf("rules[%d].id %q must match [A-Z][A-Z0-9_.-]{2,63}", i, rule.ID)
		}
		if _, exists := seenRules[rule.ID]; exists {
			return fmt.Errorf("duplicate rule id %q", rule.ID)
		}
		seenRules[rule.ID] = struct{}{}
		if rule.Requirement != fullCommitSHARequirement {
			return fmt.Errorf("rules[%d].requirement %q is unsupported", i, rule.Requirement)
		}
		if rule.Severity == "" {
			rule.Severity = "error"
		}
		if rule.Severity != "error" && rule.Severity != "warning" && rule.Severity != "note" {
			return fmt.Errorf("rules[%d].severity %q must be error, warning, or note", i, rule.Severity)
		}
		if err := validatePatterns(fmt.Sprintf("rules[%d].repositories", i), rule.Repositories); err != nil {
			return err
		}
		if err := validatePatterns(fmt.Sprintf("rules[%d].paths", i), rule.Paths); err != nil {
			return err
		}
	}

	if policy.Baseline.Mode == "" {
		if policy.Baseline.Ref != "" {
			policy.Baseline.Mode = "new"
		} else {
			policy.Baseline.Mode = "all"
		}
	}
	if policy.Baseline.Mode != "all" && policy.Baseline.Mode != "new" {
		return fmt.Errorf("baseline.mode %q must be all or new", policy.Baseline.Mode)
	}
	if policy.Baseline.Mode == "new" && policy.Baseline.Ref == "" {
		return errors.New("baseline.ref is required when baseline.mode is new")
	}

	seenExceptions := make(map[string]struct{}, len(policy.Exceptions))
	for i := range policy.Exceptions {
		exception := &policy.Exceptions[i]
		if strings.TrimSpace(exception.ID) == "" {
			return fmt.Errorf("exceptions[%d].id is required", i)
		}
		if _, exists := seenExceptions[exception.ID]; exists {
			return fmt.Errorf("duplicate exception id %q", exception.ID)
		}
		seenExceptions[exception.ID] = struct{}{}
		if strings.TrimSpace(exception.Match.Repository) == "" {
			return fmt.Errorf("exceptions[%d].match.repository is required", i)
		}
		if !validExactTarget(exception.Match.Repository, exception.Match.Subpath) {
			return fmt.Errorf("exceptions[%d].match has invalid repository or subpath", i)
		}
		if exception.Match.Ref != "" && !validGitRef(exception.Match.Ref) {
			return fmt.Errorf("exceptions[%d].match.ref %q is invalid", i, exception.Match.Ref)
		}
		if err := validatePatterns(fmt.Sprintf("exceptions[%d].match.paths", i), exception.Match.Paths); err != nil {
			return err
		}
		if strings.TrimSpace(exception.Owner) == "" || strings.TrimSpace(exception.Rationale) == "" ||
			strings.TrimSpace(exception.ApprovedBy) == "" || strings.TrimSpace(exception.Approval) == "" {
			return fmt.Errorf("exceptions[%d] requires owner, rationale, approved_by, and approval", i)
		}
		expiresAt, err := time.Parse(time.DateOnly, exception.Expires)
		if err != nil {
			return fmt.Errorf("exceptions[%d].expires must use YYYY-MM-DD: %w", i, err)
		}
		exception.expiresAt = expiresAt
	}
	return nil
}

func validRuleID(id string) bool {
	if len(id) < 3 || len(id) > 64 || id[0] < 'A' || id[0] > 'Z' {
		return false
	}
	for _, r := range id[1:] {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func validatePatterns(field string, patterns []string) error {
	for _, pattern := range patterns {
		if pattern == "" {
			return fmt.Errorf("%s contains an empty pattern", field)
		}
		if _, err := path.Match(pattern, "validation"); err != nil {
			return fmt.Errorf("%s contains invalid pattern %q: %w", field, pattern, err)
		}
	}
	return nil
}

// EvaluatePolicy classifies every scanner finding without redefining scanner completeness.
func EvaluatePolicy(repoRoot string, audit *AuditResult, policy *Policy, options PolicyEvaluationOptions) (*PolicyReport, error) {
	if audit == nil {
		return nil, errors.New("audit result is required")
	}
	if policy == nil {
		policy = DefaultPolicy()
	} else if err := policy.validate(); err != nil {
		return nil, err
	}
	if len(options.CLIExceptions) > 0 && !*policy.AllowCLIIgnores {
		return nil, errors.New("CLI ignores are disabled by policy")
	}
	cliExceptions, err := compileCLIExceptions(options.CLIExceptions)
	if err != nil {
		return nil, err
	}

	details := audit.Details
	if len(details) == 0 {
		details = legacyAuditDetails(audit.Workflows)
	}
	needsClassification := policy.Baseline.Mode == "new" || options.ChangedLinesOnly
	if needsClassification && len(options.Classifications) != len(details) {
		return nil, fmt.Errorf("finding classifications are required for %d findings", len(details))
	}
	if len(options.Classifications) != 0 && len(options.Classifications) != len(details) {
		return nil, fmt.Errorf("got %d classifications for %d findings", len(options.Classifications), len(details))
	}

	now := options.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	today, _ := time.Parse(time.DateOnly, now.Format(time.DateOnly))
	report := &PolicyReport{
		Status:      audit.Status,
		Complete:    audit.Complete,
		Outcome:     PolicyOutcomePass,
		BaselineRef: policy.Baseline.Ref,
		Errors:      append([]ScanError(nil), audit.Errors...),
		Findings:    make([]EvaluatedFinding, 0, len(details)),
	}
	for i := range report.Errors {
		report.Errors[i].FilePath = repositoryRelativePath(repoRoot, report.Errors[i].FilePath)
	}
	for i, finding := range details {
		classification := FindingClassification{New: true, Changed: true}
		if len(options.Classifications) > 0 {
			classification = options.Classifications[i]
		}
		evaluated := evaluateFinding(repoRoot, finding, classification, policy, cliExceptions, today, options.ChangedLinesOnly)
		if evaluated.Blocking {
			report.ViolationCount++
		}
		report.Findings = append(report.Findings, evaluated)
	}
	if !report.Complete || report.Status == ScanStatusIncomplete {
		report.Outcome = PolicyOutcomeIncomplete
	} else if report.ViolationCount > 0 {
		report.Outcome = PolicyOutcomeFail
	}
	return report, nil
}

func evaluateFinding(repoRoot string, finding ReferenceFinding, classification FindingClassification, policy *Policy, cliExceptions []compiledCLIException, today time.Time, changedLinesOnly bool) EvaluatedFinding {
	filePath := repositoryRelativePath(repoRoot, finding.FilePath)
	evaluated := EvaluatedFinding{
		FilePath:       filePath,
		Reference:      finding,
		Classification: classification,
		State:          PolicyFindingOutsideRule,
		Message:        fmt.Sprintf("Mutable GitHub Actions reference %s is outside the configured policy rules.", finding.Original),
	}
	rule, ok := matchingRule(policy.Rules, filePath, finding.Repository)
	if !ok {
		return evaluated
	}
	evaluated.RuleID = rule.ID
	evaluated.Severity = rule.Severity
	evaluated.Remediation = remediationForFinding(finding)

	var active, expired *PolicyException
	for i := range policy.Exceptions {
		exception := &policy.Exceptions[i]
		if !exceptionMatches(*exception, filePath, finding) {
			continue
		}
		if !today.After(exception.expiresAt) {
			active = exception
			break
		}
		if expired == nil {
			expired = exception
		}
	}
	if active != nil {
		evaluated.State = PolicyFindingExcepted
		evaluated.ExceptionID = active.ID
		evaluated.Message = fmt.Sprintf("Mutable reference %s is suppressed by active exception %s through %s.", finding.Original, active.ID, active.Expires)
		return evaluated
	}
	if expired != nil {
		evaluated.State = PolicyFindingExpired
		evaluated.ExceptionID = expired.ID
		evaluated.Blocking = rule.Severity == "error"
		evaluated.Message = fmt.Sprintf("Exception %s for %s expired on %s.", expired.ID, finding.Original, expired.Expires)
		return evaluated
	}
	for _, exception := range cliExceptions {
		if exception.matches(finding) {
			evaluated.State = PolicyFindingIgnored
			evaluated.Message = fmt.Sprintf("Mutable reference %s is suppressed by CLI ignore %q.", finding.Original, exception.source)
			return evaluated
		}
	}
	if changedLinesOnly && classification.Classified {
		if !classification.Changed {
			evaluated.State = PolicyFindingUnchanged
			evaluated.Message = fmt.Sprintf("Mutable reference %s is outside changed lines and is non-blocking.", finding.Original)
			return evaluated
		}
	} else if policy.Baseline.Mode == "new" && classification.Classified && !classification.New {
		evaluated.State = PolicyFindingBaseline
		evaluated.Message = fmt.Sprintf("Existing baseline violation %s is visible but non-blocking.", finding.Original)
		return evaluated
	}

	evaluated.State = PolicyFindingViolation
	evaluated.Blocking = rule.Severity == "error"
	if finding.Original == "" && finding.Description != "" {
		evaluated.Message = finding.Description
		evaluated.Remediation = finding.FixMessage
		return evaluated
	}
	evaluated.Message = fmt.Sprintf("Mutable reference %s violates rule %s (%s).", finding.Original, rule.ID, rule.Requirement)
	return evaluated
}

func matchingRule(rules []PolicyRule, filePath, repository string) (PolicyRule, bool) {
	for _, rule := range rules {
		if patternsMatch(rule.Paths, filePath, false) && patternsMatch(rule.Repositories, repository, true) {
			return rule, true
		}
	}
	return PolicyRule{}, false
}

func exceptionMatches(exception PolicyException, filePath string, finding ReferenceFinding) bool {
	return strings.EqualFold(exception.Match.Repository, finding.Repository) &&
		(exception.Match.Subpath == "" || exception.Match.Subpath == finding.Subpath) &&
		(exception.Match.Ref == "" || exception.Match.Ref == finding.Ref) &&
		patternsMatch(exception.Match.Paths, filePath, false)
}

func patternsMatch(patterns []string, value string, foldCase bool) bool {
	if len(patterns) == 0 {
		return true
	}
	if foldCase {
		value = strings.ToLower(value)
	}
	for _, pattern := range patterns {
		if foldCase {
			pattern = strings.ToLower(pattern)
		}
		if matched, _ := path.Match(pattern, value); matched {
			return true
		}
	}
	return false
}

func compileCLIExceptions(values []string) ([]compiledCLIException, error) {
	compiled := make([]compiledCLIException, 0, len(values))
	for _, value := range values {
		if strings.HasPrefix(value, "regex:") {
			pattern := strings.TrimPrefix(value, "regex:")
			if pattern == "" {
				return nil, errors.New("CLI ignore regex cannot be empty")
			}
			re, err := regexp.Compile("^(?:" + pattern + ")$")
			if err != nil {
				return nil, fmt.Errorf("invalid CLI ignore %q: %w", value, err)
			}
			compiled = append(compiled, compiledCLIException{source: value, regex: re})
			continue
		}

		target, ref, _ := strings.Cut(value, "@")
		parts := strings.Split(target, "/")
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid CLI ignore %q: expected owner/repo[/subpath][@ref] or regex:<RE2>", value)
		}
		repository := strings.Join(parts[:2], "/")
		subpath := strings.Join(parts[2:], "/")
		if !validExactTarget(repository, subpath) || (strings.Contains(value, "@") && ref == "") ||
			(ref != "" && !validGitRef(ref)) || strings.Count(value, "@") > 1 {
			return nil, fmt.Errorf("invalid CLI ignore %q: expected owner/repo[/subpath][@ref] or regex:<RE2>", value)
		}
		compiled = append(compiled, compiledCLIException{source: value, repository: repository, subpath: subpath, ref: ref})
	}
	return compiled, nil
}

func validExactTarget(repository, subpath string) bool {
	parts := strings.Split(repository, "/")
	if len(parts) != 2 || !validRepositoryPart(parts[0], true) || !validRepositoryPart(parts[1], false) {
		return false
	}
	if subpath == "" {
		return true
	}
	for _, part := range strings.Split(subpath, "/") {
		if !validPathPart(part) {
			return false
		}
	}
	return true
}

func (exception compiledCLIException) matches(finding ReferenceFinding) bool {
	if exception.regex != nil {
		return exception.regex.MatchString(canonicalReference(finding))
	}
	return strings.EqualFold(exception.repository, finding.Repository) &&
		(exception.subpath == "" || exception.subpath == finding.Subpath) &&
		(exception.ref == "" || exception.ref == finding.Ref)
}

func canonicalReference(finding ReferenceFinding) string {
	target := finding.Repository
	if finding.Subpath != "" {
		target += "/" + finding.Subpath
	}
	return target + "@" + finding.Ref
}

func remediationForFinding(finding ReferenceFinding) string {
	if replacement, ok := suggestedReference(finding); ok {
		return fmt.Sprintf("Replace %s with %s.", finding.Original, replacement)
	}
	return fmt.Sprintf("Pin %s to a full 40-character commit SHA or add an accountable, time-bound policy exception.", finding.Original)
}

func suggestedReference(finding ReferenceFinding) (string, bool) {
	if !finding.Editable || !isFullSHA(finding.FixSHA) {
		return "", false
	}
	target := finding.Repository
	if finding.Subpath != "" {
		target += "/" + finding.Subpath
	}
	return target + "@" + strings.ToLower(finding.FixSHA), true
}

func repositoryRelativePath(repoRoot, filePath string) string {
	relative, err := filepath.Rel(repoRoot, filePath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(filePath)
	}
	return filepath.ToSlash(relative)
}

func legacyAuditDetails(workflows []Workflow) []ReferenceFinding {
	var details []ReferenceFinding
	for _, workflow := range workflows {
		for _, issue := range workflow.Issues {
			details = append(details, ReferenceFinding{
				FilePath:    workflow.FilePath,
				Line:        issue.Line,
				Column:      issue.Column,
				Repository:  issue.Action,
				Ref:         issue.Version,
				Original:    issue.Original,
				Description: issue.Description,
				FixSHA:      issue.FixSHA,
				FixMessage:  issue.FixMsg,
			})
		}
	}
	return details
}
