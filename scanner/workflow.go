// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package scanner

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// ScanStatus distinguishes a clean scan from findings and incomplete analysis.
type ScanStatus string

const (
	ScanStatusClean      ScanStatus = "complete-clean"
	ScanStatusFindings   ScanStatus = "complete-with-findings"
	ScanStatusIncomplete ScanStatus = "incomplete"
)

// ScanError describes one file or directory that could not be scanned.
type ScanError struct {
	FilePath string `json:"file"`
	Message  string `json:"message"`
}

func (e ScanError) Error() string {
	if e.FilePath == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.FilePath, e.Message)
}

// NewScanError preserves file context without exposing an implementation error type in JSON.
func NewScanError(filePath string, err error) ScanError {
	return ScanError{FilePath: filePath, Message: err.Error()}
}

// IncompleteScanError aggregates failures while callers retain the accompanying result.
type IncompleteScanError struct {
	Errors []ScanError
}

func (e *IncompleteScanError) Error() string {
	messages := make([]string, 0, len(e.Errors))
	for _, scanErr := range e.Errors {
		messages = append(messages, scanErr.Error())
	}
	return fmt.Sprintf("scan incomplete: %s", strings.Join(messages, "; "))
}

func scanStatus(findingCount int, scanErrors []ScanError) (ScanStatus, bool) {
	if len(scanErrors) > 0 {
		return ScanStatusIncomplete, false
	}
	if findingCount > 0 {
		return ScanStatusFindings, true
	}
	return ScanStatusClean, true
}

func (inv *InventoryResult) setStatus() {
	inv.Status, inv.Complete = scanStatus(len(inv.Records), inv.Errors)
}

// Err returns a non-nil aggregate only when the scan was incomplete.
func (inv *InventoryResult) Err() error {
	if inv == nil || len(inv.Errors) == 0 {
		return nil
	}
	return &IncompleteScanError{Errors: inv.Errors}
}

type actionReference struct {
	Repository      string
	Subpath         string
	Ref             string
	Original        string
	Line            int
	Column          int
	StartOffset     int
	EndOffset       int
	ScalarEndOffset int
	Pinned          bool
	Editable        bool
	SourceText      string
	Style           yaml.Style
}

// ReferenceFinding is the structured mutable-reference model used by safe edits.
type ReferenceFinding struct {
	FilePath        string `json:"file"`
	Line            int    `json:"line"`
	Column          int    `json:"column"`
	Repository      string `json:"repository"`
	Subpath         string `json:"subpath,omitempty"`
	Ref             string `json:"ref"`
	Original        string `json:"original"`
	SourceText      string `json:"source_text,omitempty"`
	StartOffset     int    `json:"start_offset,omitempty"`
	EndOffset       int    `json:"end_offset,omitempty"`
	ScalarEndOffset int    `json:"scalar_end_offset,omitempty"`
	Editable        bool   `json:"editable"`
	Description     string `json:"description,omitempty"`
	FixSHA          string `json:"fix_sha,omitempty"`
	FixMessage      string `json:"fix_message,omitempty"`
	style           yaml.Style
}

func (finding ReferenceFinding) legacy() Finding {
	return Finding{
		Line:        finding.Line,
		Column:      finding.Column,
		Description: finding.Description,
		FixSHA:      finding.FixSHA,
		FixMsg:      finding.FixMessage,
		Action:      finding.Repository,
		Version:     finding.Ref,
		Original:    finding.Original,
	}
}

// ScanWorkflowReferences parses one workflow and returns mutable external uses references.
// It may return findings together with an error when semantic detection succeeds but a safe edit span cannot be produced.
func ScanWorkflowReferences(content []byte, filePath string) ([]ReferenceFinding, error) {
	references, scanErr := parseWorkflowReferences(content)
	findings := make([]ReferenceFinding, 0, len(references))
	for _, reference := range references {
		if reference.Pinned {
			continue
		}
		findings = append(findings, ReferenceFinding{
			FilePath:        filePath,
			Line:            reference.Line,
			Column:          reference.Column,
			Repository:      reference.Repository,
			Subpath:         reference.Subpath,
			Ref:             reference.Ref,
			Original:        reference.Original,
			SourceText:      reference.SourceText,
			StartOffset:     reference.StartOffset,
			EndOffset:       reference.EndOffset,
			ScalarEndOffset: reference.ScalarEndOffset,
			Editable:        reference.Editable,
			style:           reference.Style,
		})
	}
	if scanErr != nil {
		return findings, fmt.Errorf("parse workflow %s: %w", filePath, scanErr)
	}
	return findings, nil
}

// ScanWorkflow is retained as the initial structured scanner spelling.
func ScanWorkflow(content []byte, filePath string) ([]ReferenceFinding, error) {
	return ScanWorkflowReferences(content, filePath)
}

func parseWorkflowReferences(content []byte) ([]actionReference, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, err
	}

	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return nil, errors.New("multiple YAML documents are not a valid GitHub Actions workflow")
	} else if !errors.Is(err, io.EOF) {
		return nil, err
	}

	root := documentRoot(&document)
	if root == nil || root.Kind != yaml.MappingNode {
		return nil, nil
	}
	jobs, jobsAlias := collectionNode(mappingValue(root, "jobs"), yaml.MappingNode)
	if jobs == nil {
		return nil, nil
	}

	var references []actionReference
	var referenceErrors []error
	for i := 1; i < len(jobs.Content); i += 2 {
		job, jobAlias := collectionNode(jobs.Content[i], yaml.MappingNode)
		if job == nil {
			continue
		}
		aliasUse := jobsAlias
		if jobAlias != nil {
			aliasUse = jobAlias
		}

		if uses := mappingValue(job, "uses"); uses != nil {
			if reference, ok, err := referenceFromContext(content, uses, aliasUse); ok && isReusableWorkflowReference(reference) {
				references = append(references, reference)
				if err != nil {
					referenceErrors = append(referenceErrors, err)
				}
			}
		}

		steps, stepsAlias := collectionNode(mappingValue(job, "steps"), yaml.SequenceNode)
		if steps == nil {
			continue
		}
		if stepsAlias != nil {
			aliasUse = stepsAlias
		}
		for _, step := range steps.Content {
			step, stepAlias := collectionNode(step, yaml.MappingNode)
			if step == nil {
				continue
			}
			stepAliasUse := aliasUse
			if stepAlias != nil {
				stepAliasUse = stepAlias
			}
			if uses := mappingValue(step, "uses"); uses != nil {
				if reference, ok, err := referenceFromContext(content, uses, stepAliasUse); ok {
					references = append(references, reference)
					if err != nil {
						referenceErrors = append(referenceErrors, err)
					}
				}
			}
		}
	}
	return references, errors.Join(referenceErrors...)
}

func collectionNode(node *yaml.Node, kind yaml.Kind) (*yaml.Node, *yaml.Node) {
	var aliasUse *yaml.Node
	for node != nil && node.Kind == yaml.AliasNode {
		if aliasUse == nil {
			aliasUse = node
		}
		node = node.Alias
	}
	if node == nil || node.Kind != kind {
		return nil, aliasUse
	}
	return node, aliasUse
}

func referenceFromContext(content []byte, node *yaml.Node, aliasUse *yaml.Node) (actionReference, bool, error) {
	reference, ok, err := referenceFromNode(content, node)
	if !ok || aliasUse == nil || node.Kind == yaml.AliasNode {
		return reference, ok, err
	}

	reference.Line = aliasUse.Line
	reference.Column = aliasUse.Column
	reference.StartOffset = 0
	reference.EndOffset = 0
	reference.ScalarEndOffset = 0
	reference.Editable = false
	reference.SourceText = ""
	if reference.Pinned {
		return reference, true, nil
	}
	return reference, true, fmt.Errorf("line %d: mutable external uses %q uses unsupported YAML aliases", aliasUse.Line, reference.Original)
}

func isReusableWorkflowReference(reference actionReference) bool {
	const workflowPrefix = ".github/workflows/"
	if !strings.HasPrefix(reference.Subpath, workflowPrefix) {
		return false
	}
	fileName := strings.TrimPrefix(reference.Subpath, workflowPrefix)
	if fileName == "" || strings.Contains(fileName, "/") {
		return false
	}
	ext := filepath.Ext(fileName)
	return ext == ".yml" || ext == ".yaml"
}

func documentRoot(document *yaml.Node) *yaml.Node {
	if document.Kind == yaml.DocumentNode {
		if len(document.Content) == 0 {
			return nil
		}
		return document.Content[0]
	}
	return document
}

func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Kind == yaml.ScalarNode && mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func referenceFromNode(content []byte, node *yaml.Node) (actionReference, bool, error) {
	semanticNode := node
	unsupported := ""
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		semanticNode = node.Alias
		unsupported = "YAML aliases"
	}
	if semanticNode.Kind != yaml.ScalarNode || semanticNode.Tag != "!!str" {
		return actionReference{}, false, nil
	}
	value := semanticNode.Value
	if semanticNode.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		value = strings.TrimSpace(value)
		unsupported = "block scalars"
	}
	repository, subpath, ref, pinned, ok := parseExternalReference(value)
	if !ok {
		return actionReference{}, false, nil
	}
	reference := actionReference{
		Repository: repository,
		Subpath:    subpath,
		Ref:        ref,
		Original:   value,
		Line:       node.Line,
		Column:     node.Column,
		Pinned:     pinned,
		Style:      semanticNode.Style,
	}
	if node.Kind != yaml.AliasNode && semanticNode.Anchor != "" {
		unsupported = "YAML anchors"
	}
	if unsupported != "" {
		if pinned {
			return reference, true, nil
		}
		return reference, true, fmt.Errorf("line %d: mutable external uses %q uses unsupported %s", node.Line, value, unsupported)
	}
	start, end, scalarEnd, ok := scalarValueSpan(content, node)
	if !ok {
		if pinned {
			return reference, true, nil
		}
		return reference, true, fmt.Errorf("line %d: mutable external uses %q has no trustworthy source span", node.Line, value)
	}
	sourceText := string(content[start:end])
	if node.Style == 0 && sourceText != value {
		if pinned {
			return reference, true, nil
		}
		return reference, true, fmt.Errorf("line %d: mutable external uses %q has no trustworthy source span", node.Line, value)
	}
	reference.Column = sourceColumn(content, start)
	reference.StartOffset = start
	reference.EndOffset = end
	reference.ScalarEndOffset = scalarEnd
	reference.Editable = true
	reference.SourceText = sourceText
	return reference, true, nil
}

func parseExternalReference(value string) (string, string, string, bool, bool) {
	if value == "" || value != strings.TrimSpace(value) || strings.Contains(value, "${{") ||
		strings.HasPrefix(value, "./") || strings.HasPrefix(value, "docker://") {
		return "", "", "", false, false
	}

	at := strings.IndexByte(value, '@')
	if at <= 0 || at == len(value)-1 {
		return "", "", "", false, false
	}
	target, ref := value[:at], value[at+1:]
	parts := strings.Split(target, "/")
	if len(parts) < 2 || !validRepositoryPart(parts[0], true) || !validRepositoryPart(parts[1], false) || !validGitRef(ref) {
		return "", "", "", false, false
	}
	for _, part := range parts[2:] {
		if !validPathPart(part) {
			return "", "", "", false, false
		}
	}

	repository := parts[0] + "/" + parts[1]
	subpath := strings.Join(parts[2:], "/")
	return repository, subpath, ref, isFullSHA(ref), true
}

func validRepositoryPart(value string, owner bool) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || (!owner && (r == '_' || r == '.')) {
			continue
		}
		return false
	}
	return !owner || (value[0] != '-' && value[len(value)-1] != '-')
}

func validPathPart(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune(`\\:@`, r) {
			return false
		}
	}
	return true
}

func validGitRef(ref string) bool {
	if ref == "" || ref == "@" || strings.HasPrefix(ref, "/") || strings.HasSuffix(ref, "/") ||
		strings.HasSuffix(ref, ".") || strings.Contains(ref, "..") || strings.Contains(ref, "//") ||
		strings.Contains(ref, "@{") || strings.ContainsRune(ref, '\\') {
		return false
	}
	for _, part := range strings.Split(ref, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	for _, r := range ref {
		if unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune(`~^:?*[`, r) {
			return false
		}
	}
	return true
}

func isFullSHA(ref string) bool {
	if len(ref) != 40 {
		return false
	}
	for _, r := range ref {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func scalarValueSpan(content []byte, node *yaml.Node) (int, int, int, bool) {
	offset, ok := sourceOffset(content, node.Line, node.Column)
	if !ok || offset >= len(content) {
		return 0, 0, 0, false
	}
	lineEnd := bytes.IndexByte(content[offset:], '\n')
	if lineEnd < 0 {
		lineEnd = len(content)
	} else {
		lineEnd += offset
	}

	switch {
	case node.Style&yaml.SingleQuotedStyle != 0:
		if content[offset] != '\'' {
			return 0, 0, 0, false
		}
		for i := offset + 1; i < lineEnd; i++ {
			if content[i] != '\'' {
				continue
			}
			if i+1 < lineEnd && content[i+1] == '\'' {
				i++
				continue
			}
			return offset + 1, i, i + 1, true
		}
	case node.Style&yaml.DoubleQuotedStyle != 0:
		if content[offset] != '"' {
			return 0, 0, 0, false
		}
		escaped := false
		for i := offset + 1; i < lineEnd; i++ {
			if escaped {
				escaped = false
				continue
			}
			if content[i] == '\\' {
				escaped = true
				continue
			}
			if content[i] == '"' {
				return offset + 1, i, i + 1, true
			}
		}
	case node.Style == 0:
		end := offset + len(node.Value)
		if end <= lineEnd {
			return offset, end, end, true
		}
	}
	return 0, 0, 0, false
}

func scalarReplacement(style yaml.Style, value string) string {
	switch {
	case style&yaml.SingleQuotedStyle != 0:
		return strings.ReplaceAll(value, "'", "''")
	case style&yaml.DoubleQuotedStyle != 0:
		quoted := strconv.Quote(value)
		return quoted[1 : len(quoted)-1]
	default:
		return value
	}
}

func scalarStyleAtSpan(content []byte, start, end, scalarEnd int) yaml.Style {
	if start == 0 || end >= len(content) || scalarEnd != end+1 {
		return 0
	}
	switch {
	case content[start-1] == '\'' && content[end] == '\'':
		return yaml.SingleQuotedStyle
	case content[start-1] == '"' && content[end] == '"':
		return yaml.DoubleQuotedStyle
	default:
		return 0
	}
}

func sourceOffset(content []byte, line, column int) (int, bool) {
	if line < 1 || column < 1 {
		return 0, false
	}
	offset := 0
	for currentLine := 1; currentLine < line; currentLine++ {
		newline := bytes.IndexByte(content[offset:], '\n')
		if newline < 0 {
			return 0, false
		}
		offset += newline + 1
	}
	for currentColumn := 1; currentColumn < column; currentColumn++ {
		if offset >= len(content) || content[offset] == '\n' {
			return 0, false
		}
		_, size := utf8.DecodeRune(content[offset:])
		offset += size
	}
	return offset, true
}

func sourceColumn(content []byte, offset int) int {
	lineStart := bytes.LastIndexByte(content[:offset], '\n') + 1
	return utf8.RuneCount(content[lineStart:offset]) + 1
}

func sourceLineEnd(content []byte, offset int) int {
	lineEnd := bytes.IndexByte(content[offset:], '\n')
	if lineEnd < 0 {
		lineEnd = len(content)
	} else {
		lineEnd += offset
	}
	if lineEnd > offset && content[lineEnd-1] == '\r' {
		lineEnd--
	}
	return lineEnd
}

func scalarIsLineTerminal(content []byte, scalarEnd, lineEnd int) bool {
	for scalarEnd < lineEnd && (content[scalarEnd] == ' ' || content[scalarEnd] == '\t') {
		scalarEnd++
	}
	return scalarEnd == lineEnd || content[scalarEnd] == '#'
}

// ListWorkflowFiles returns regular .yml and .yaml files. A missing directory is clean.
func ListWorkflowFiles(loc FilePath) ([]FilePath, error) {
	entries, err := os.ReadDir(string(loc))
	if errors.Is(err, os.ErrNotExist) {
		return []FilePath{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read workflow directory: %w", err)
	}

	files := make([]FilePath, 0, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yml" && ext != ".yaml" {
			continue
		}
		files = append(files, FilePath(filepath.Join(string(loc), entry.Name())))
	}
	return files, nil
}
