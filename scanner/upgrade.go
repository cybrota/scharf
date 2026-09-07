// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/cybrota/scharf/git"
	"github.com/cybrota/scharf/network"
)

var pinnedRefRegex = regexp.MustCompile(`([\w.-]+/[\w.-]+)@([a-f0-9]{40})\s+#\s+([^\s]+)`)
var barePinnedRefRegex = regexp.MustCompile(`([\w.-]+/[\w.-]+)@([a-f0-9]{40})\s*$`)

const (
	skipReasonNoTagForSHA      = "no tag points to pinned SHA"
	skipReasonAmbiguousSHATags = "ambiguous: multiple tags point to pinned SHA"
)

type upgradeResolver interface {
	ResolveNext(action string, currentVersion string, cooldownHours int) (*network.UpgradeResult, error)
	ListTags(action string) ([]network.BranchOrTag, error)
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

// BarePinnedRef is a pinned action reference without version hint.
type BarePinnedRef struct {
	Action string
	SHA    string
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

// ParseBarePinnedRef parses owner/repo@<40hexsha> from a line.
func ParseBarePinnedRef(line string) (BarePinnedRef, bool) {
	match := barePinnedRefRegex.FindStringSubmatch(line)
	if len(match) != 3 {
		return BarePinnedRef{}, false
	}
	return BarePinnedRef{Action: match[1], SHA: match[2]}, true
}

// CollectPinnedRefs returns strict Scharf-format pinned references found in content.
func CollectPinnedRefs(content []byte) []Finding {
	references, _ := parseWorkflowReferences(content)

	findings := make([]Finding, 0, len(references))
	for _, reference := range references {
		if !reference.Pinned {
			continue
		}
		version, _, _, ok := referenceVersionHint(content, reference)
		if !ok {
			continue
		}

		findings = append(findings, Finding{
			Line:     reference.Line,
			Column:   reference.Column,
			Action:   reference.Repository,
			Version:  version,
			FixSHA:   reference.Ref,
			Original: fmt.Sprintf("%s@%s # %s", referenceTarget(reference), reference.Ref, version),
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
	fileNames, err := ListWorkflowFiles(FilePath(loc))
	if err != nil {
		return fmt.Errorf("file error: %w", err)
	}

	type workflowUpdate struct {
		path    string
		content []byte
		mode    os.FileMode
		changed bool
	}
	updates := make([]workflowUpdate, 0, len(fileNames))
	for _, fileName := range fileNames {
		workflowPath := string(fileName)
		content, err := ReadFile(fileName)
		if err != nil {
			return fmt.Errorf("reading %s: %w", workflowPath, err)
		}
		references, err := parseWorkflowReferences(content)
		if err != nil {
			return fmt.Errorf("parse workflow %s: %w", workflowPath, err)
		}
		for _, reference := range references {
			if reference.Pinned && !reference.Editable {
				return fmt.Errorf("parse workflow %s: pinned reference %q at line %d is not safely editable", workflowPath, reference.Original, reference.Line)
			}
		}
		info, err := os.Stat(workflowPath)
		if err != nil {
			return fmt.Errorf("stat %s: %w", workflowPath, err)
		}
		updates = append(updates, workflowUpdate{path: workflowPath, content: content, mode: info.Mode().Perm()})
	}

	resolver := newUpgradeResolver()
	for i := range updates {
		updated, changed, err := upgradePinnedSHAsInContent(updates[i].content, updates[i].path, resolver, cooldownHours, isDryRun)
		if err != nil {
			return err
		}
		updates[i].content = updated
		updates[i].changed = changed
	}
	if !isDryRun {
		for _, update := range updates {
			if !update.changed {
				continue
			}
			if err := os.WriteFile(update.path, update.content, update.mode); err != nil {
				return fmt.Errorf("writing %s: %w", update.path, err)
			}
		}
	}

	if isDryRun {
		fmt.Println("Dry-run complete. Re-run without --dry-run to write workflow updates.")
	}

	return nil
}

func upgradePinnedSHAsInContent(content []byte, workflowPath string, resolver upgradeResolver, cooldownHours int, isDryRun bool) ([]byte, bool, error) {
	references, err := parseWorkflowReferences(content)
	if err != nil {
		return content, false, fmt.Errorf("parse workflow %s: %w", workflowPath, err)
	}

	type sourceEdit struct {
		start       int
		end         int
		replacement string
	}
	var edits []sourceEdit
	skippedNonScharf := 0
	tagIndexByAction := map[string]map[string][]string{}

	for _, reference := range references {
		if !reference.Pinned {
			skippedNonScharf++
			continue
		}

		currentVersion, hintStart, hintEnd, hadVersionHint := referenceVersionHint(content, reference)
		if !hadVersionHint {
			bare := BarePinnedRef{
				Action: reference.Repository,
				SHA:    reference.Ref,
			}
			var reason string
			var inferred bool
			currentVersion, reason, inferred = inferVersionForBarePinnedSHA(bare, resolver, tagIndexByAction)
			if !inferred {
				fmt.Printf("%sWarning:%s skipping %s@%s at %s:%d (%s)\n", Yellow, Reset, referenceTarget(reference), bare.SHA, workflowPath, reference.Line, reason)
				continue
			}
		}

		result, err := resolver.ResolveNext(reference.Repository, currentVersion, cooldownHours)
		if err != nil || result == nil || result.NextVersion == "" || result.NextSHA == "" {
			fmt.Printf("%sWarning:%s skipping %s@%s at %s:%d (no resolvable next version)\n", Yellow, Reset, reference.Repository, currentVersion, workflowPath, reference.Line)
			continue
		}

		if result.UnderCooldown {
			fmt.Printf("%sWarning:%s %s@%s is under cooldown; proceeding with upgrade at %s:%d\n", Yellow, Reset, reference.Repository, currentVersion, workflowPath, reference.Line)
		}

		fromRef := reference.Original
		toRef := fmt.Sprintf("%s@%s", referenceTarget(reference), result.NextSHA)

		if isDryRun {
			fmt.Printf("Dry-run: planned update %s:%d %s -> %s # %s\n", workflowPath, reference.Line, fromRef, toRef, result.NextVersion)
			continue
		}

		edits = append(edits, sourceEdit{
			start:       reference.StartOffset,
			end:         reference.EndOffset,
			replacement: scalarReplacement(reference.Style, toRef),
		})
		if hadVersionHint {
			edits = append(edits, sourceEdit{start: hintStart, end: hintEnd, replacement: result.NextVersion})
		} else if lineEnd := sourceLineEnd(content, reference.ScalarEndOffset); scalarIsLineTerminal(content, reference.ScalarEndOffset, lineEnd) {
			edits = append(edits, sourceEdit{start: reference.ScalarEndOffset, end: reference.ScalarEndOffset, replacement: " # " + result.NextVersion})
		}
		fmt.Printf("Updated %s:%d %s -> %s # %s\n", workflowPath, reference.Line, fromRef, toRef, result.NextVersion)
	}

	if skippedNonScharf > 0 {
		fmt.Printf("%sInfo:%s skipped %d non-Scharf references in %s (expected format: owner/repo@<40hexsha> # <version>)\n", Yellow, Reset, skippedNonScharf, workflowPath)
	}

	if len(edits) == 0 {
		return content, false, nil
	}

	sort.SliceStable(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	updated := append([]byte(nil), content...)
	for _, edit := range edits {
		updated = append(updated[:edit.start], append([]byte(edit.replacement), updated[edit.end:]...)...)
	}
	return updated, true, nil
}

func referenceTarget(reference actionReference) string {
	target := reference.Repository
	if reference.Subpath != "" {
		target += "/" + reference.Subpath
	}
	return target
}

func referenceVersionHint(content []byte, reference actionReference) (string, int, int, bool) {
	lineEnd := sourceLineEnd(content, reference.ScalarEndOffset)
	if !scalarIsLineTerminal(content, reference.ScalarEndOffset, lineEnd) {
		return "", 0, 0, false
	}
	suffix := content[reference.ScalarEndOffset:lineEnd]
	comment := bytes.IndexByte(suffix, '#')
	if comment < 0 {
		return "", 0, 0, false
	}
	start := reference.ScalarEndOffset + comment + 1
	for start < lineEnd && (content[start] == ' ' || content[start] == '\t') {
		start++
	}
	end := start
	for end < lineEnd && content[end] != ' ' && content[end] != '\t' && content[end] != '\r' {
		end++
	}
	if start == end {
		return "", 0, 0, false
	}
	return string(content[start:end]), start, end, true
}

func inferVersionForBarePinnedSHA(
	bare BarePinnedRef,
	resolver upgradeResolver,
	tagIndexByAction map[string]map[string][]string,
) (string, string, bool) {
	shaToTags, ok := tagIndexByAction[bare.Action]
	if !ok {
		tags, err := resolver.ListTags(bare.Action)
		if err != nil {
			return "", fmt.Sprintf("failed to list tags: %v", err), false
		}

		shaToTags = map[string][]string{}
		for _, tag := range tags {
			if tag.Name == "" || tag.Commit.Sha == "" {
				continue
			}
			shaToTags[tag.Commit.Sha] = append(shaToTags[tag.Commit.Sha], tag.Name)
		}

		tagIndexByAction[bare.Action] = shaToTags
	}

	matches := shaToTags[bare.SHA]
	if len(matches) == 0 {
		for sha, tags := range shaToTags {
			if strings.EqualFold(sha, bare.SHA) {
				matches = tags
				break
			}
		}
	}
	if len(matches) == 0 {
		return "", skipReasonNoTagForSHA, false
	}
	if len(matches) > 1 {
		return "", skipReasonAmbiguousSHATags, false
	}

	return matches[0], "", true
}
