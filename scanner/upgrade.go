// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/cybrota/scharf/git"
	"github.com/cybrota/scharf/network"
)

var pinnedRefRegex = regexp.MustCompile(`([\w.-]+/[\w.-]+)@([a-f0-9]{40})\s+#\s+([^\s#]+)`)

type upgradeResolver interface {
	ResolveNext(action string, currentVersion string, cooldownHours int) (*network.UpgradeResult, error)
}

var newUpgradeResolver = func() upgradeResolver {
	return network.NewSHAResolver()
}

// PinnedRef is a strict Scharf-formatted pinned action reference.
type PinnedRef struct {
	Action  string
	SHA     string
	Version string
}

// ParsePinnedRef parses owner/repo@<40hexsha> # <version> from a line.
func ParsePinnedRef(line string) (PinnedRef, bool) {
	match := pinnedRefRegex.FindStringSubmatch(line)
	if len(match) != 4 {
		return PinnedRef{}, false
	}

	return PinnedRef{
		Action:  match[1],
		SHA:     match[2],
		Version: match[3],
	}, true
}

// CollectPinnedRefs returns strict Scharf-format pinned references found in content.
func CollectPinnedRefs(content []byte) []Finding {
	matches, err := ScanContentWithPosition(content, pinnedRefRegex)
	if err != nil {
		return []Finding{}
	}

	findings := make([]Finding, 0, len(matches))
	for _, m := range matches {
		parsed, ok := ParsePinnedRef(m.Text)
		if !ok {
			continue
		}

		findings = append(findings, Finding{
			Line:     m.Line,
			Column:   m.Col,
			Action:   parsed.Action,
			Version:  parsed.Version,
			FixSHA:   parsed.SHA,
			Original: m.Text,
		})
	}

	return findings
}

// UpgradePinnedSHAs upgrades Scharf-formatted pinned SHAs in workflow files.
func UpgradePinnedSHAs(path FilePath, cooldownHours int, isDryRun bool) error {
	abs, err := filepath.Abs(filepath.Join(string(path)))
	if err != nil {
		return fmt.Errorf("os: %w", err)
	}

	if !git.IsGitRepo(abs) {
		return fmt.Errorf("The directory: %s is not a Git repository", abs)
	}

	loc := filepath.Join(abs, ".github", "workflows")
	fileNames, err := ListFiles(FilePath(loc))
	if err != nil {
		return fmt.Errorf("file error: %w", err)
	}

	resolver := newUpgradeResolver()

	for _, fileName := range fileNames {
		workflowPath := filepath.Join(loc, string(*fileName))
		content, err := ReadFile(FilePath(workflowPath))
		if err != nil {
			if errors.Is(err, syscall.EISDIR) {
				continue
			}
			return fmt.Errorf("file error: %w", err)
		}

		updated, fileChanged := upgradePinnedSHAsInContent(content, workflowPath, resolver, cooldownHours, isDryRun)
		if fileChanged && !isDryRun {
			if err := os.WriteFile(workflowPath, updated, 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", workflowPath, err)
			}
		}
	}

	if isDryRun {
		fmt.Println("Dry-run complete. Re-run without --dry-run to write workflow updates.")
	}

	return nil
}

func upgradePinnedSHAsInContent(content []byte, workflowPath string, resolver upgradeResolver, cooldownHours int, isDryRun bool) ([]byte, bool) {
	lines := strings.Split(string(content), "\n")
	changed := false

	for i := range lines {
		if !strings.Contains(lines[i], "uses:") {
			continue
		}

		parsed, ok := ParsePinnedRef(lines[i])
		if !ok {
			fmt.Printf("%sWarning:%s skipping non-Scharf ref at %s:%d\n", Yellow, Reset, workflowPath, i+1)
			continue
		}

		result, err := resolver.ResolveNext(parsed.Action, parsed.Version, cooldownHours)
		if err != nil || result == nil || result.NextVersion == "" || result.NextSHA == "" {
			fmt.Printf("%sWarning:%s skipping %s@%s at %s:%d (no resolvable next version)\n", Yellow, Reset, parsed.Action, parsed.Version, workflowPath, i+1)
			continue
		}

		if result.UnderCooldown {
			fmt.Printf("%sWarning:%s %s@%s is under cooldown; proceeding with upgrade at %s:%d\n", Yellow, Reset, parsed.Action, parsed.Version, workflowPath, i+1)
		}

		fromRef := fmt.Sprintf("%s@%s # %s", parsed.Action, parsed.SHA, parsed.Version)
		toRef := fmt.Sprintf("%s@%s # %s", parsed.Action, result.NextSHA, result.NextVersion)

		if !strings.Contains(lines[i], fromRef) {
			fmt.Printf("%sWarning:%s could not safely replace ref at %s:%d\n", Yellow, Reset, workflowPath, i+1)
			continue
		}

		if isDryRun {
			fmt.Printf("Dry-run: planned update %s:%d %s -> %s\n", workflowPath, i+1, fromRef, toRef)
			continue
		}

		lines[i] = strings.Replace(lines[i], fromRef, toRef, 1)
		changed = true
		fmt.Printf("Updated %s:%d %s -> %s\n", workflowPath, i+1, fromRef, toRef)
	}

	if !changed {
		return content, false
	}

	return []byte(strings.Join(lines, "\n")), true
}
