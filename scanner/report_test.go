// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestFormatPolicyHumanExplainsFailureAndRemediation(t *testing.T) {
	report := policyOutputTestReport()
	output := FormatPolicyHuman(report)
	for _, expected := range []string{
		"Scan status: complete-with-findings",
		"Policy outcome: violations",
		".github/workflows/ci.yml:4:15",
		"violates rule SCHARF001",
		"Replace owner/repo@main with owner/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("output %q does not contain %q", output, expected)
		}
	}
}

func TestFormatGitHubAnnotationsEscapesCommands(t *testing.T) {
	report := policyOutputTestReport()
	report.Findings[0].FilePath = ".github/workflows/a,b:ci.yml"
	report.Findings[0].Message = "unsafe%message\nnext"
	output := FormatGitHubAnnotations(report)
	if !strings.Contains(output, "file=.github/workflows/a%2Cb%3Aci.yml") ||
		!strings.Contains(output, "unsafe%25message%0Anext") ||
		!strings.Contains(output, "endColumn=30") {
		t.Fatalf("annotation was not safely escaped: %q", output)
	}
}

func TestWriteSARIFIncludesRuleLocationAndSafeFix(t *testing.T) {
	report := policyOutputTestReport()
	var output bytes.Buffer
	if err := WriteSARIF(&output, report); err != nil {
		t.Fatalf("WriteSARIF returned error: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatalf("SARIF is not JSON: %v\n%s", err, output.String())
	}
	if document["version"] != "2.1.0" || document["$schema"] != sarifSchema {
		t.Fatalf("SARIF header = %#v", document)
	}
	runs := document["runs"].([]any)
	run := runs[0].(map[string]any)
	if run["columnKind"] != "unicodeCodePoints" {
		t.Fatalf("column kind = %#v", run["columnKind"])
	}
	results := run["results"].([]any)
	result := results[0].(map[string]any)
	if result["ruleId"] != MutableReferenceRuleID {
		t.Fatalf("rule ID = %#v", result["ruleId"])
	}
	fixes, ok := result["fixes"].([]any)
	if !ok || len(fixes) != 1 || !strings.Contains(output.String(), "owner/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatalf("safe fix missing from SARIF: %s", output.String())
	}
}

func TestIncompleteSARIFCannotLookSuccessful(t *testing.T) {
	report := &PolicyReport{
		Status:   ScanStatusIncomplete,
		Complete: false,
		Outcome:  PolicyOutcomeIncomplete,
		Errors:   []ScanError{{FilePath: ".github/workflows/broken.yml", Message: "invalid YAML"}},
	}
	var output bytes.Buffer
	if err := WriteSARIF(&output, report); err != nil {
		t.Fatalf("WriteSARIF returned error: %v", err)
	}
	for _, expected := range []string{`"executionSuccessful": false`, ScanIncompleteRuleID, "invalid YAML", ".github/workflows/broken.yml"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("SARIF %s does not contain %q", output.String(), expected)
		}
	}
}

func TestCleanSARIFUsesEmptyResultsArray(t *testing.T) {
	report := &PolicyReport{Status: ScanStatusClean, Complete: true, Outcome: PolicyOutcomePass}
	var output bytes.Buffer
	if err := WriteSARIF(&output, report); err != nil {
		t.Fatalf("WriteSARIF returned error: %v", err)
	}
	if !strings.Contains(output.String(), `"results": []`) {
		t.Fatalf("clean SARIF must contain an empty results array: %s", output.String())
	}
}

func TestPolicyWarningSeveritySurvivesCIFormatting(t *testing.T) {
	report := policyOutputTestReport()
	report.Findings[0].Severity = "warning"
	report.Findings[0].Blocking = false
	if output := FormatGitHubAnnotations(report); !strings.HasPrefix(output, "::warning ") {
		t.Fatalf("GitHub warning was downgraded: %q", output)
	}
	var output bytes.Buffer
	if err := WriteSARIF(&output, report); err != nil {
		t.Fatalf("WriteSARIF returned error: %v", err)
	}
	if !strings.Contains(output.String(), `"level": "warning"`) {
		t.Fatalf("SARIF warning was downgraded: %s", output.String())
	}
}

func policyOutputTestReport() *PolicyReport {
	return &PolicyReport{
		Status:         ScanStatusFindings,
		Complete:       true,
		Outcome:        PolicyOutcomeFail,
		ViolationCount: 1,
		Findings: []EvaluatedFinding{{
			RuleID:   MutableReferenceRuleID,
			Severity: "error",
			FilePath: ".github/workflows/ci.yml",
			Reference: ReferenceFinding{
				FilePath: ".github/workflows/ci.yml", Line: 4, Column: 15, Repository: "owner/repo", Ref: "main", Original: "owner/repo@main",
				SourceText: "owner/repo@main", Editable: true, FixSHA: strings.Repeat("a", 40),
			},
			Classification: FindingClassification{Classified: true, New: true, Changed: true},
			State:          PolicyFindingViolation,
			Blocking:       true,
			Message:        "Mutable reference owner/repo@main violates rule SCHARF001 (full-commit-sha).",
			Remediation:    "Replace owner/repo@main with owner/repo@" + strings.Repeat("a", 40) + ".",
		}},
	}
}
