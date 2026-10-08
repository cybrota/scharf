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
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// DependencySource only reads declarative metadata; implementations must never run actions.
type DependencySource interface {
	Resolve(action string) (string, error)
	ReadMetadata(repository, commit, name string) ([]byte, error)
}

// DependencyLimits bound expansion, including repeated caller paths and YAML aliases.
// Nodes counts visited YAML structures, aliases and mapping keys, not just uses edges.
type DependencyLimits struct{ Depth, Nodes, Bytes int }

func DefaultDependencyLimits() DependencyLimits { return DependencyLimits{12, 5000, 8 << 20} }

type DependencyLocation struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
	Uses   string `json:"uses"`
}
type DependencyEdge struct {
	Chain      []DependencyLocation `json:"chain"`
	Repository string               `json:"repository,omitempty"`
	Ref        string               `json:"ref,omitempty"`
	Commit     string               `json:"commit,omitempty"`
	Metadata   string               `json:"metadata,omitempty"`
	Mutable    bool                 `json:"mutable"`
	Status     string               `json:"status"`
}
type DependencyReport struct {
	Status   ScanStatus       `json:"status"`
	Complete bool             `json:"complete"`
	Edges    []DependencyEdge `json:"edges"`
	Errors   []ScanError      `json:"errors,omitempty"`
	Scope    string           `json:"scope"`
}
type dependencyDocument struct {
	repo, commit, file     string
	workflow               bool
	aliasLine, aliasColumn int
}
type dependencyWalker struct {
	rootFS       *os.Root
	root         string
	source       DependencySource
	limits       DependencyLimits
	bytes, nodes int
	exhausted    bool
	cache        map[string][]byte
	resolved     map[string]string
	active       map[string]bool
	report       DependencyReport
}

// AuditDependencies follows uses edges with per-run immutable metadata caching.
// Local workspace files are read-only snapshots, not claims about a remote commit.
func AuditDependencies(root string, source DependencySource, limits DependencyLimits) (*DependencyReport, error) {
	if limits.Depth <= 0 || limits.Nodes <= 0 || limits.Bytes <= 0 {
		return nil, errors.New("dependency limits must be positive")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	rootFS, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	defer rootFS.Close()
	w := &dependencyWalker{rootFS: rootFS, root: abs, source: source, limits: limits, cache: map[string][]byte{}, resolved: map[string]string{}, active: map[string]bool{}}
	w.report.Scope = "GitHub repository uses edges only; Docker image references, shell/JavaScript downloads, package dependencies and container contents are not audited. Pinning does not establish trust."
	names, err := dependencyWorkflowFiles(abs, rootFS)
	if err != nil {
		w.fail(".github/workflows", err)
	}
	for _, name := range names {
		if w.exhausted {
			break
		}
		relative, e := filepath.Rel(abs, string(name))
		if e != nil {
			w.fail(string(name), e)
			continue
		}
		w.walk(dependencyDocument{file: filepath.ToSlash(relative), workflow: true}, nil, 0)
	}
	count := 0
	for _, edge := range w.report.Edges {
		if edge.Mutable {
			count++
		}
	}
	w.report.Status, w.report.Complete = scanStatus(count, w.report.Errors)
	if !w.report.Complete {
		return &w.report, &IncompleteScanError{Errors: w.report.Errors}
	}
	return &w.report, nil
}
func dependencyWorkflowFiles(root string, rootFS *os.Root) ([]FilePath, error) {
	dir := filepath.Join(".github", "workflows")
	info, err := rootFS.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("workflow path must be a directory")
	}
	f, err := openDependencyFile(rootFS, dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	var names []FilePath
	for _, entry := range entries {
		ext := filepath.Ext(entry.Name())
		if ext == ".yml" || ext == ".yaml" {
			names = append(names, FilePath(filepath.Join(root, dir, entry.Name())))
		}
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	return names, nil
}
func (w *dependencyWalker) fail(file string, err error) {
	w.report.Errors = append(w.report.Errors, NewScanError(file, err))
}

func (w *dependencyWalker) consumeNode(d dependencyDocument) bool {
	if w.exhausted {
		return false
	}
	if w.nodes >= w.limits.Nodes {
		w.exhausted = true
		w.fail(d.file, errors.New("dependency node budget exhausted"))
		return false
	}
	w.nodes++
	return true
}
func safeDependencyPath(name string) bool {
	if name == "" || strings.ContainsAny(name, "\\\x00") || path.IsAbs(name) || path.Clean(name) != name {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." || part == "." || part == "" {
			return false
		}
	}
	return true
}
func (w *dependencyWalker) read(d dependencyDocument) ([]byte, error) {
	if !safeDependencyPath(d.file) {
		return nil, fmt.Errorf("unsafe metadata path %q", d.file)
	}
	key := d.repo + "@" + d.commit + ":" + d.file
	if b, ok := w.cache[key]; ok {
		return b, nil
	}
	var b []byte
	var err error
	if d.repo != "" {
		if w.source == nil {
			return nil, errors.New("remote dependency source unavailable")
		}
		b, err = w.source.ReadMetadata(d.repo, d.commit, d.file)
	} else {
		rooted := w.rootFS
		name := filepath.FromSlash(d.file)
		info, e := rooted.Stat(name)
		if e != nil {
			return nil, e
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("metadata must be a regular file")
		}
		f, e := openDependencyFile(rooted, name)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		info, e = f.Stat()
		if e != nil {
			return nil, e
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("metadata must be a regular file")
		}
		b, err = io.ReadAll(io.LimitReader(f, int64(w.limits.Bytes-w.bytes)+1))
	}
	if err != nil {
		return nil, err
	}
	if len(b) > w.limits.Bytes-w.bytes {
		// Failed oversized reads also cost I/O. Stop the whole traversal instead
		// of repeatedly reading the remaining allowance for every sibling file.
		w.exhausted = true
		return nil, errors.New("dependency byte budget exhausted")
	}
	w.bytes += len(b)
	w.cache[key] = b
	return b, nil
}
func (w *dependencyWalker) walk(d dependencyDocument, chain []DependencyLocation, depth int) {
	if !w.consumeNode(d) {
		return
	}
	if depth > w.limits.Depth {
		w.fail(d.file, errors.New("dependency depth budget exhausted"))
		return
	}
	key := d.repo + "@" + d.commit + ":" + d.file
	if w.active[key] {
		w.fail(d.file, errors.New("dependency cycle"))
		return
	}
	w.active[key] = true
	defer delete(w.active, key)
	b, err := w.read(d)
	if err != nil {
		w.fail(d.file, err)
		return
	}
	var doc yaml.Node
	decoder := yaml.NewDecoder(strings.NewReader(string(b)))
	if err = decoder.Decode(&doc); err != nil {
		w.fail(d.file, err)
		return
	}
	var extra yaml.Node
	if err = decoder.Decode(&extra); err != io.EOF {
		w.fail(d.file, errors.New("metadata must contain exactly one YAML document"))
		return
	}
	root := w.node(d, documentRoot(&doc), yaml.MappingNode)
	if root == nil {
		return
	}
	if d.workflow {
		jobs := mappingValue(root, "jobs")
		w.visitJobs(d, jobs, chain, depth)
	} else {
		runs := w.node(d, mappingValue(root, "runs"), yaml.MappingNode)
		if runs == nil {
			return
		}
		using := w.node(d, mappingValue(runs, "using"), yaml.ScalarNode)
		if using == nil {
			return
		}
		switch using.Value {
		case "composite":
			w.visitSteps(d, mappingValue(runs, "steps"), chain, depth)
		case "docker", "node12", "node16", "node20", "node24":
		default:
			w.fail(d.file, errors.New("unknown action runtime requires manual dependency review"))
		}
	}
}

// Aliases are resolved only at the expected structural position. Cyclic aliases and
// merges cannot silently omit dependencies: unresolved structures make the scan incomplete.
func (w *dependencyWalker) node(d dependencyDocument, n *yaml.Node, kind yaml.Kind) *yaml.Node {
	if !w.consumeNode(d) {
		return nil
	}
	seen := map[*yaml.Node]bool{}
	for n != nil && n.Kind == yaml.AliasNode {
		if !w.consumeNode(d) {
			return nil
		}
		if seen[n] {
			w.fail(d.file, errors.New("cyclic YAML alias"))
			return nil
		}
		seen[n] = true
		n = n.Alias
	}
	if n == nil || n.Kind != kind {
		w.fail(d.file, errors.New("invalid dependency metadata structure"))
		return nil
	}
	if kind == yaml.ScalarNode && n.Tag != "!!str" {
		w.fail(d.file, errors.New("dependency metadata value must be a string"))
		return nil
	}
	if kind == yaml.MappingNode {
		keys := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			if !w.consumeNode(d) {
				return nil
			}
			if n.Content[i].Kind != yaml.ScalarNode || (n.Content[i].Tag != "!!str" && n.Content[i].Tag != "!!merge") {
				w.fail(d.file, errors.New("unsupported YAML mapping key"))
				return nil
			}
			key := n.Content[i].Value
			if key == "<<" {
				w.fail(d.file, errors.New("YAML merge keys require manual dependency review"))
			}
			if keys[key] {
				w.fail(d.file, errors.New("duplicate YAML mapping key"))
			}
			keys[key] = true
		}
	}
	return n
}
func (w *dependencyWalker) visitJobs(d dependencyDocument, n *yaml.Node, chain []DependencyLocation, depth int) {
	if n != nil && n.Kind == yaml.AliasNode && d.aliasLine == 0 {
		d.aliasLine = n.Line
		d.aliasColumn = n.Column
	}
	n = w.node(d, n, yaml.MappingNode)
	if n == nil {
		return
	}
	for i := 1; i < len(n.Content); i += 2 {
		if w.exhausted {
			return
		}
		jobD := d
		if n.Content[i].Kind == yaml.AliasNode && jobD.aliasLine == 0 {
			jobD.aliasLine = n.Content[i].Line
			jobD.aliasColumn = n.Content[i].Column
		}
		job := w.node(jobD, n.Content[i], yaml.MappingNode)
		if job == nil {
			continue
		}
		if mappingValue(job, "uses") == nil && mappingValue(job, "steps") == nil {
			w.fail(d.file, errors.New("job has neither uses nor steps"))
			continue
		}
		if u := mappingValue(job, "uses"); u != nil {
			if n.Content[i].Kind == yaml.AliasNode {
				copy := *u
				copy.Line = n.Content[i].Line
				copy.Column = n.Content[i].Column
				u = &copy
			}
			w.edge(jobD, u, chain, depth, true)
		}
		if s := mappingValue(job, "steps"); s != nil {
			w.visitSteps(jobD, s, chain, depth)
		}
	}
}
func (w *dependencyWalker) visitSteps(d dependencyDocument, n *yaml.Node, chain []DependencyLocation, depth int) {
	if n != nil && n.Kind == yaml.AliasNode && d.aliasLine == 0 {
		d.aliasLine = n.Line
		d.aliasColumn = n.Column
	}
	n = w.node(d, n, yaml.SequenceNode)
	if n == nil {
		return
	}
	for _, s := range n.Content {
		if w.exhausted {
			return
		}
		step := w.node(d, s, yaml.MappingNode)
		if step == nil {
			continue
		}
		if u := mappingValue(step, "uses"); u != nil {
			if s.Kind == yaml.AliasNode {
				copy := *u
				copy.Line = s.Line
				copy.Column = s.Column
				u = &copy
			}
			w.edge(d, u, chain, depth, false)
		}
	}
}
func (w *dependencyWalker) edge(d dependencyDocument, n *yaml.Node, chain []DependencyLocation, depth int, workflow bool) {
	loc := DependencyLocation{File: d.file, Line: n.Line, Column: n.Column, Uses: n.Value}
	if d.aliasLine != 0 {
		loc.Line = d.aliasLine
		loc.Column = d.aliasColumn
	}
	n = w.node(d, n, yaml.ScalarNode)
	if n == nil {
		return
	}
	loc.Uses = n.Value
	next := append(append([]DependencyLocation{}, chain...), loc)
	e := DependencyEdge{Chain: next, Status: "resolved"}
	target := dependencyDocument{workflow: workflow}
	value := n.Value
	switch {
	case strings.HasPrefix(value, "docker://"):
		e.Status = "container-not-traversed"
		w.report.Edges = append(w.report.Edges, e)
		return
	case strings.HasPrefix(value, "./"):
		if d.repo != "" && !workflow {
			e.Status = "workspace-context-unknown"
		} else {
			target.repo = d.repo
			target.commit = d.commit
			target.file = strings.TrimPrefix(value, "./")
		}
	case strings.HasPrefix(value, "$/"):
		if strings.Contains(value, "@") {
			e.Status = "invalid-self-reference"
		} else {
			target.repo = d.repo
			target.commit = d.commit
			target.file = strings.TrimPrefix(value, "$/")
		}
	default:
		repo, sub, ref, pinned, ok := parseExternalReference(value)
		if !ok {
			e.Status = "unresolved-reference"
			break
		}
		e.Repository = repo
		e.Ref = ref
		e.Mutable = !pinned
		target.repo = repo
		target.file = sub
		target.commit = ref
		if !pinned {
			target.commit = ""
		}
		if !pinned && depth < w.limits.Depth {
			key := repo + "@" + ref
			sha, ok := w.resolved[key]
			if !ok {
				var err error
				if w.source == nil {
					err = errors.New("remote source unavailable")
				} else {
					sha, err = w.source.Resolve(key)
				}
				if err != nil || !isFullSHA(sha) {
					e.Status = "resolution-unavailable"
					if err != nil {
						w.fail(d.file, fmt.Errorf("resolve %s: %w", key, err))
					} else {
						w.fail(d.file, errors.New("resolver returned invalid commit SHA"))
					}
				} else {
					w.resolved[key] = sha
				}
			}
			target.commit = sha
		}
	}
	if e.Status != "resolved" {
		w.report.Edges = append(w.report.Edges, e)
		w.fail(d.file, fmt.Errorf("%s: %s", value, e.Status))
		return
	}
	e.Repository = target.repo
	e.Commit = target.commit
	if depth >= w.limits.Depth {
		// Do not resolve refs or prefetch action.yml beyond the traversal boundary.
		e.Status = "depth-budget-exhausted"
		w.report.Edges = append(w.report.Edges, e)
		w.fail(d.file, errors.New("dependency depth budget exhausted"))
		return
	}
	if !workflow {
		prefix := target.file
		if prefix != "" {
			prefix += "/"
		}
		target.file = prefix + "action.yml"
		if _, err := w.read(target); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				target.file = prefix + "action.yaml"
			} else {
				e.Status = "metadata-unavailable"
				w.report.Edges = append(w.report.Edges, e)
				w.fail(target.file, err)
				return
			}
		}
	}
	if workflow && (!strings.HasPrefix(target.file, ".github/workflows/") || strings.Count(target.file, "/") != 2 || !(strings.HasSuffix(target.file, ".yml") || strings.HasSuffix(target.file, ".yaml"))) {
		w.fail(d.file, errors.New("invalid reusable workflow path"))
		e.Status = "invalid-workflow-path"
		w.report.Edges = append(w.report.Edges, e)
		return
	}
	e.Metadata = target.file
	w.report.Edges = append(w.report.Edges, e)
	w.walk(target, next, depth+1)
}
