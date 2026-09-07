// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

// FormatPolicyHuman renders policy decisions with reasons and remediation.
func FormatPolicyHuman(report *PolicyReport) string {
	var output strings.Builder
	fmt.Fprintf(&output, "Scan status: %s\nPolicy outcome: %s\n", report.Status, report.Outcome)
	for _, finding := range report.Findings {
		location := fmt.Sprintf("%s:%d:%d", finding.FilePath, finding.Reference.Line, finding.Reference.Column)
		fmt.Fprintf(&output, "%s [%s %s %s] %s\n", location, finding.RuleID, finding.Severity, finding.State, finding.Message)
		if finding.Remediation != "" && finding.State != PolicyFindingExcepted && finding.State != PolicyFindingIgnored {
			fmt.Fprintf(&output, "  Fix: %s\n", finding.Remediation)
		}
	}
	if len(report.Findings) == 0 && report.Complete {
		output.WriteString("No mutable references found. Good job!\n")
	}
	for _, scanErr := range report.Errors {
		fmt.Fprintf(&output, "Scan error: %s\n", scanErr.Error())
	}
	return output.String()
}

// FormatGitHubAnnotations emits escaped GitHub workflow commands for findings and scan failures.
func FormatGitHubAnnotations(report *PolicyReport) string {
	var output strings.Builder
	for _, finding := range report.Findings {
		if finding.RuleID == "" {
			continue
		}
		level := annotationLevel(finding)
		properties := []string{
			"file=" + escapeGitHubProperty(finding.FilePath),
			fmt.Sprintf("line=%d", finding.Reference.Line),
			fmt.Sprintf("col=%d", finding.Reference.Column),
		}
		if finding.Reference.SourceText != "" {
			properties = append(properties, fmt.Sprintf("endColumn=%d", finding.Reference.Column+utf8.RuneCountInString(finding.Reference.SourceText)))
		}
		properties = append(properties, "title="+escapeGitHubProperty(finding.RuleID+" "+string(finding.State)))
		message := finding.Message
		if finding.Remediation != "" && finding.State != PolicyFindingExcepted && finding.State != PolicyFindingIgnored {
			message += " " + finding.Remediation
		}
		fmt.Fprintf(&output, "::%s %s::%s\n", level, strings.Join(properties, ","), escapeGitHubMessage(message))
	}
	for _, scanErr := range report.Errors {
		properties := "title=" + ScanIncompleteRuleID
		if scanErr.FilePath != "" {
			properties = "file=" + escapeGitHubProperty(scanErr.FilePath) + "," + properties
		}
		fmt.Fprintf(&output, "::error %s::%s\n", properties, escapeGitHubMessage(scanErr.Message))
	}
	return output.String()
}

func annotationLevel(finding EvaluatedFinding) string {
	if finding.State == PolicyFindingExcepted || finding.State == PolicyFindingIgnored ||
		finding.State == PolicyFindingBaseline || finding.State == PolicyFindingUnchanged {
		return "notice"
	}
	if finding.Severity == "warning" {
		return "warning"
	}
	return "error"
}

func escapeGitHubProperty(value string) string {
	replacer := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C")
	return replacer.Replace(value)
}

func escapeGitHubMessage(value string) string {
	replacer := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	return replacer.Replace(value)
}

// WriteSARIF writes a SARIF 2.1.0 log with stable rules, precise locations, suppressions, and safe fixes.
func WriteSARIF(writer io.Writer, report *PolicyReport) error {
	rulesByID := make(map[string]sarifReportingDescriptor)
	results := make([]sarifResult, 0)
	for _, finding := range report.Findings {
		if finding.RuleID == "" {
			continue
		}
		rulesByID[finding.RuleID] = sarifReportingDescriptor{
			ID:                   finding.RuleID,
			ShortDescription:     sarifMessage{Text: "Mutable GitHub Actions reference"},
			FullDescription:      sarifMessage{Text: "GitHub Actions references must use a full 40-character commit SHA unless an accountable, time-bound exception applies."},
			Help:                 sarifMessage{Text: "Pin the reference to the resolved commit SHA or request a policy exception with owner, rationale, approval, and expiration."},
			DefaultConfiguration: sarifConfiguration{Level: sarifLevel(finding.Severity)},
		}
		result := sarifResult{
			RuleID:  finding.RuleID,
			Level:   sarifFindingLevel(finding),
			Message: sarifMessage{Text: strings.TrimSpace(finding.Message + " " + finding.Remediation)},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: finding.FilePath},
				Region: sarifRegion{
					StartLine:   finding.Reference.Line,
					StartColumn: finding.Reference.Column,
					EndLine:     finding.Reference.Line,
					EndColumn:   finding.Reference.Column + utf8.RuneCountInString(finding.Reference.SourceText),
				},
			}}},
		}
		if finding.Classification.Classified {
			if finding.Classification.New {
				result.BaselineState = "new"
			} else {
				result.BaselineState = "unchanged"
			}
		}
		if finding.State == PolicyFindingExcepted || finding.State == PolicyFindingIgnored {
			result.Suppressions = []sarifSuppression{{Kind: "external", Status: "accepted", Justification: finding.Message}}
		}
		if replacement, ok := suggestedReference(finding.Reference); ok &&
			(finding.State == PolicyFindingViolation || finding.State == PolicyFindingExpired) {
			result.Fixes = []sarifFix{{
				Description: sarifMessage{Text: finding.Remediation},
				ArtifactChanges: []sarifArtifactChange{{
					ArtifactLocation: sarifArtifactLocation{URI: finding.FilePath},
					Replacements: []sarifReplacement{{
						DeletedRegion:   result.Locations[0].PhysicalLocation.Region,
						InsertedContent: sarifArtifactContent{Text: scalarReplacement(finding.Reference.style, replacement)},
					}},
				}},
			}}
		}
		results = append(results, result)
	}

	var notifications []sarifNotification
	if len(report.Errors) > 0 {
		rulesByID[ScanIncompleteRuleID] = sarifReportingDescriptor{
			ID:                   ScanIncompleteRuleID,
			ShortDescription:     sarifMessage{Text: "Scharf scan incomplete"},
			FullDescription:      sarifMessage{Text: "One or more workflow files or revision inputs could not be analyzed."},
			DefaultConfiguration: sarifConfiguration{Level: "error"},
		}
		for _, scanErr := range report.Errors {
			notification := sarifNotification{
				Descriptor: sarifDescriptorReference{ID: ScanIncompleteRuleID},
				Level:      "error",
				Message:    sarifMessage{Text: scanErr.Error()},
			}
			if scanErr.FilePath != "" {
				notification.Locations = []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: scanErr.FilePath}}}}
			}
			notifications = append(notifications, notification)
			results = append(results, sarifResult{
				RuleID:    ScanIncompleteRuleID,
				Level:     "error",
				Message:   sarifMessage{Text: scanErr.Error()},
				Locations: notification.Locations,
			})
		}
	}

	ruleIDs := make([]string, 0, len(rulesByID))
	for ruleID := range rulesByID {
		ruleIDs = append(ruleIDs, ruleID)
	}
	sort.Strings(ruleIDs)
	rules := make([]sarifReportingDescriptor, 0, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		rules = append(rules, rulesByID[ruleID])
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  sarifSchema,
		Runs: []sarifRun{{
			Tool:        sarifTool{Driver: sarifDriver{Name: "Scharf", InformationURI: "https://github.com/cybrota/scharf", Rules: rules}},
			ColumnKind:  "unicodeCodePoints",
			Results:     results,
			Invocations: []sarifInvocation{{ExecutionSuccessful: report.Complete, ToolExecutionNotifications: notifications}},
		}},
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
}

func sarifLevel(severity string) string {
	if severity == "warning" || severity == "note" {
		return severity
	}
	return "error"
}

func sarifFindingLevel(finding EvaluatedFinding) string {
	if finding.State == PolicyFindingExcepted || finding.State == PolicyFindingIgnored ||
		finding.State == PolicyFindingBaseline || finding.State == PolicyFindingUnchanged {
		return "note"
	}
	return sarifLevel(finding.Severity)
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	ColumnKind  string            `json:"columnKind"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string                     `json:"name"`
	InformationURI string                     `json:"informationUri"`
	Rules          []sarifReportingDescriptor `json:"rules"`
}

type sarifReportingDescriptor struct {
	ID                   string             `json:"id"`
	ShortDescription     sarifMessage       `json:"shortDescription"`
	FullDescription      sarifMessage       `json:"fullDescription"`
	Help                 sarifMessage       `json:"help,omitempty"`
	DefaultConfiguration sarifConfiguration `json:"defaultConfiguration"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID        string             `json:"ruleId"`
	Level         string             `json:"level"`
	Message       sarifMessage       `json:"message"`
	Locations     []sarifLocation    `json:"locations,omitempty"`
	BaselineState string             `json:"baselineState,omitempty"`
	Suppressions  []sarifSuppression `json:"suppressions,omitempty"`
	Fixes         []sarifFix         `json:"fixes,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status,omitempty"`
	Justification string `json:"justification,omitempty"`
}

type sarifFix struct {
	Description     sarifMessage          `json:"description"`
	ArtifactChanges []sarifArtifactChange `json:"artifactChanges"`
}

type sarifArtifactChange struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Replacements     []sarifReplacement    `json:"replacements"`
}

type sarifReplacement struct {
	DeletedRegion   sarifRegion          `json:"deletedRegion"`
	InsertedContent sarifArtifactContent `json:"insertedContent"`
}

type sarifArtifactContent struct {
	Text string `json:"text"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Descriptor sarifDescriptorReference `json:"descriptor"`
	Level      string                   `json:"level"`
	Message    sarifMessage             `json:"message"`
	Locations  []sarifLocation          `json:"locations,omitempty"`
}

type sarifDescriptorReference struct {
	ID string `json:"id"`
}
