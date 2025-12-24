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

// ApplyFixesInFile opens the given file, applies all Findings in-place, and
// writes the file back. It applies fixes in top-to-bottom, left-to-right order
// so byte offsets remain valid.
func ApplyFixesInFile(wf Workflow, isDryRun bool) error {
	// 1) Read original content
	data, err := os.ReadFile(wf.FilePath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", wf.FilePath, err)
	}
	lines := strings.Split(string(data), "\n")

	// 2) Sort issues so earlier lines/columns are applied first
	sort.Slice(wf.Issues, func(i, j int) bool {
		if wf.Issues[i].Line != wf.Issues[j].Line {
			return wf.Issues[i].Line < wf.Issues[j].Line
		}
		return wf.Issues[i].Column < wf.Issues[j].Column
	})

	// 3) Apply each fix
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
			return fmt.Errorf(
				"column %d out of range on line %d (%q)",
				issue.Column, issue.Line, line,
			)
		}

		// Split at the byte offset; then replace the first occurrence of Original
		prefix := line[:issue.Column-1]
		suffix := line[issue.Column-1:]
		if !strings.Contains(suffix, issue.Original) {
			return fmt.Errorf(
				"could not find %q at line %d, col %d in %s",
				issue.Original, issue.Line, issue.Column, wf.FilePath,
			)
		}

		// Perform exactly one replacement
		newSuffix := strings.Replace(suffix, issue.Original, fmt.Sprintf("%s@%s # %s", issue.Action, issue.FixSHA, issue.Version), 1)
		lines[idx] = prefix + newSuffix
		fmt.Printf("  - [%s%s%s] %s Fixed: Pinned '%s%s' to '%s' %s\n", Gray, loc, Reset, Green, issue.Action, fmt.Sprintf("@%s", issue.Version), issue.FixSHA, Reset)
	}

	// 4) Write back (you could write to a temp file + rename for safety)
	output := strings.Join(lines, "\n")

	if !isDryRun {
		if err := os.WriteFile(wf.FilePath, []byte(output), os.ModeAppend); err != nil {
			return fmt.Errorf("writing %s: %w", wf.FilePath, err)
		}
	}
	return nil
}
