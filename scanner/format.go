// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// Color codes
const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	Gray    = "\033[37m"
	White   = "\033[97m"
)

// Finding is a single issue in a workflow file.
type Finding struct {
	Line        int    // 1-based line number
	Column      int    // 1-based column number
	Description string // human-readable problem description
	FixSHA      string // suggested replacement
	FixMsg      string // Fix message
	Action      string
	Version     string // version
	Original    string // e.g. "actions/checkout@v2"
}

// Workflow holds all findings for one GitHub Actions YAML
type Workflow struct {
	Name     string    // workflow name (from the YAML)
	FilePath string    // path to the workflow file
	Issues   []Finding // all unpinned-version findings
}

// FormatAuditReport renders a slice of workflows into a colored CLI report.
func FormatAuditReport(workflows []Workflow) string {
	var b strings.Builder

	for _, wf := range workflows {
		// Header per workflow
		fmt.Fprintf(&b,
			"%s%s%s\n",
			Cyan, wf.FilePath, Reset,
		)

		for _, f := range wf.Issues {
			// Issue line: location + message
			loc := fmt.Sprintf("Line %d, Col %d", f.Line, f.Column)
			fmt.Fprintf(&b,
				"  - [%s%s%s] %s%s%s\n",
				Gray, loc, Reset,
				Red, f.Description, Reset,
			)
			// Fix line
			fmt.Fprintf(&b,
				"    🡆 %sFix:%s %s%s%s\n\n",
				Green, Reset,
				Yellow, f.FixMsg, Reset,
			)
		}
	}

	return b.String()
}

// ApplyFixesInFile preserves the v1 line-and-column replacement contract.
func ApplyFixesInFile(wf Workflow, isDryRun bool) error {
	data, err := os.ReadFile(wf.FilePath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", wf.FilePath, err)
	}
	lines := strings.Split(string(data), "\n")
	sort.Slice(wf.Issues, func(i, j int) bool {
		if wf.Issues[i].Line != wf.Issues[j].Line {
			return wf.Issues[i].Line < wf.Issues[j].Line
		}
		return wf.Issues[i].Column < wf.Issues[j].Column
	})

	for _, issue := range wf.Issues {
		loc := fmt.Sprintf("Line %d, Col %d", issue.Line, issue.Column)

		if issue.FixSHA == SHA256NotAvailable {
			fmt.Printf("  - [%s%s%s] %s Warning: Couldn't fix the reference: %s. Reference '%s' is not found on GitHub%s ⚠️\n", Gray, loc, Reset, Yellow, issue.Action, issue.Version, Reset)
			continue
		}
		idx := issue.Line - 1
		if idx < 0 || idx >= len(lines) {
			return fmt.Errorf("invalid line %d in %s", issue.Line, wf.FilePath)
		}
		line := lines[idx]
		if issue.Column-1 > len(line) {
			return fmt.Errorf("column %d out of range on line %d (%q)", issue.Column, issue.Line, line)
		}
		prefix := line[:issue.Column-1]
		suffix := line[issue.Column-1:]
		if !strings.Contains(suffix, issue.Original) {
			return fmt.Errorf("could not find %q at line %d, col %d in %s", issue.Original, issue.Line, issue.Column, wf.FilePath)
		}
		lines[idx] = prefix + strings.Replace(suffix, issue.Original, fmt.Sprintf("%s@%s # %s", issue.Action, issue.FixSHA, issue.Version), 1)
		fmt.Printf("  - [%s%s%s] %s Fixed: Pinned '%s%s' to '%s' %s\n", Gray, loc, Reset, Green, issue.Action, fmt.Sprintf("@%s", issue.Version), issue.FixSHA, Reset)
	}

	if !isDryRun {
		info, err := os.Stat(wf.FilePath)
		if err != nil {
			return fmt.Errorf("stat %s: %w", wf.FilePath, err)
		}
		if err := os.WriteFile(wf.FilePath, []byte(strings.Join(lines, "\n")), info.Mode().Perm()); err != nil {
			return fmt.Errorf("writing %s: %w", wf.FilePath, err)
		}
	}
	return nil
}

// ApplyReferenceFixesInFile applies verified source-span edits without reserializing YAML.
func ApplyReferenceFixesInFile(filePath string, findings []ReferenceFinding, isDryRun bool) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", filePath, err)
	}

	type sourceEdit struct {
		start       int
		end         int
		replacement string
	}
	var edits []sourceEdit
	for _, finding := range findings {
		if finding.FixSHA == SHA256NotAvailable {
			continue
		}
		if !finding.Editable {
			return fmt.Errorf("reference %q at %s:%d is not safely editable", finding.Original, filePath, finding.Line)
		}
		if finding.StartOffset < 0 || finding.EndOffset < finding.StartOffset || finding.EndOffset > len(data) ||
			finding.ScalarEndOffset < finding.EndOffset || finding.ScalarEndOffset > len(data) ||
			string(data[finding.StartOffset:finding.EndOffset]) != finding.SourceText {
			return fmt.Errorf("reference %q changed at line %d, col %d in %s", finding.Original, finding.Line, finding.Column, filePath)
		}

		target := finding.Repository
		if finding.Subpath != "" {
			target += "/" + finding.Subpath
		}
		edits = append(edits, sourceEdit{
			start: finding.StartOffset,
			end:   finding.EndOffset,
			replacement: scalarReplacement(
				scalarStyleAtSpan(data, finding.StartOffset, finding.EndOffset, finding.ScalarEndOffset),
				fmt.Sprintf("%s@%s", target, finding.FixSHA),
			),
		})
		lineEnd := sourceLineEnd(data, finding.ScalarEndOffset)
		if scalarIsLineTerminal(data, finding.ScalarEndOffset, lineEnd) {
			edits = append(edits, sourceEdit{
				start:       finding.ScalarEndOffset,
				end:         finding.ScalarEndOffset,
				replacement: fmt.Sprintf(" # %s", finding.Ref),
			})
		}
	}

	sort.SliceStable(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	updated := append([]byte(nil), data...)
	for _, edit := range edits {
		updated = append(updated[:edit.start], append([]byte(edit.replacement), updated[edit.end:]...)...)
	}
	if isDryRun {
		return nil
	}
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", filePath, err)
	}
	if err := os.WriteFile(filePath, updated, info.Mode().Perm()); err != nil {
		return fmt.Errorf("writing %s: %w", filePath, err)
	}
	return nil
}
