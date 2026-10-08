// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// WriteDependencyReport is intentionally separate from the v1 direct-audit contract.
func WriteDependencyReport(out io.Writer, report *DependencyReport, format string) error {
	switch format {
	case "json":
		return json.NewEncoder(out).Encode(report)
	case "human":
		if _, err := fmt.Fprintf(out, "Dependency scan: %s\n%s\n", report.Status, report.Scope); err != nil {
			return err
		}
		for _, e := range report.Edges {
			var parts []string
			for _, l := range e.Chain {
				parts = append(parts, fmt.Sprintf("%q:%d uses %q", l.File, l.Line, l.Uses))
			}
			if _, err := fmt.Fprintf(out, "%s [%s, mutable=%t, commit=%s]\n", strings.Join(parts, " -> "), e.Status, e.Mutable, e.Commit); err != nil {
				return err
			}
		}
		for _, e := range report.Errors {
			if _, err := fmt.Fprintf(out, "Incomplete: %q\n", e.Error()); err != nil {
				return err
			}
		}
		return nil
	case "sarif":
		results := []any{}
		for _, e := range report.Edges {
			if !e.Mutable && e.Status == "resolved" {
				continue
			}
			if e.Status == "container-not-traversed" {
				continue
			}
			l := e.Chain[0]
			results = append(results, map[string]any{"ruleId": "SCHARF_DEPENDENCY", "level": "warning", "message": map[string]string{"text": fmt.Sprintf("Dependency %s: %s (mutable=%t)", e.Chain[len(e.Chain)-1].Uses, e.Status, e.Mutable)}, "locations": []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]string{"uri": (&url.URL{Path: l.File}).EscapedPath()}, "region": map[string]int{"startLine": l.Line, "startColumn": l.Column}}}}, "properties": e})
		}
		notices := []any{}
		for _, e := range report.Errors {
			notices = append(notices, map[string]any{"level": "error", "message": map[string]string{"text": e.Error()}})
		}
		return json.NewEncoder(out).Encode(map[string]any{"version": "2.1.0", "$schema": sarifSchema, "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "scharf", "rules": []any{map[string]any{"id": "SCHARF_DEPENDENCY", "shortDescription": map[string]string{"text": "Declarative dependency reference review"}}}}}, "results": results, "invocations": []any{map[string]any{"executionSuccessful": report.Complete, "toolExecutionNotifications": notices}}, "properties": report}}})
	default:
		return fmt.Errorf("dependency output must be human, json, or sarif")
	}
}
