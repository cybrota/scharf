// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	ProvenanceVerified         = "verified"
	ProvenanceUnverified       = "unverified"
	ProvenanceIdentityMismatch = "identity-mismatch"
	ProvenanceMovedReference   = "moved-reference"
	provenanceMaxRequests      = 128
	provenanceMaxPages         = 5
	provenanceMaxBody          = 2 << 20
)

var provenanceSHA = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
var provenancePartialSHA = regexp.MustCompile(`^[a-fA-F0-9]{7,39}$`)
var provenanceRepository = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
var provenanceMajorTag = regexp.MustCompile(`^v?[0-9]+$`)

// ProvenanceRef records the exact branch snapshot supporting ancestry evidence.
type ProvenanceRef struct {
	Ref string `json:"ref"`
	SHA string `json:"sha"`
}

// ProvenanceObservation is historical evidence, never a current verification cache.
type ProvenanceObservation struct {
	Repository     string          `json:"repository"`
	RepositoryID   int64           `json:"repository_id"`
	OriginalRef    string          `json:"original_ref"`
	RefKind        string          `json:"ref_kind"`
	SHA            string          `json:"sha"`
	CheckedAt      string          `json:"checked_at"`
	SupportingRefs []ProvenanceRef `json:"supporting_refs"`
}

// ProvenanceEvidence proves only reachability from the documented branch set,
// not that code is benign or the repository/branch owner is trustworthy.
type ProvenanceEvidence struct {
	Status         string                 `json:"status"`
	Repository     string                 `json:"repository"`
	RepositoryID   int64                  `json:"repository_id,omitempty"`
	OriginalRef    string                 `json:"original_ref"`
	RefKind        string                 `json:"ref_kind"`
	SHA            string                 `json:"sha,omitempty"`
	CheckedAt      string                 `json:"checked_at"`
	SupportingRefs []ProvenanceRef        `json:"supporting_refs"`
	Reason         string                 `json:"reason"`
	Previous       *ProvenanceObservation `json:"previous,omitempty"`
	Moved          bool                   `json:"moved"`
	RequiresReview bool                   `json:"requires_review"`
}

// AllowsUpdate rejects unknown provenance and suspicious history changes.
func (e *ProvenanceEvidence) AllowsUpdate() bool {
	return e != nil && (e.Status == ProvenanceVerified || e.Status == ProvenanceMovedReference) && !e.RequiresReview && len(e.SupportingRefs) > 0
}

// ProvenanceResolver is opt-in. It does not read the ordinary SHA resolution cache.
// The mutex protects historical observation writes within this resolver instance.
type ProvenanceResolver struct {
	client    *http.Client
	baseURL   string
	statePath string
	mu        sync.Mutex
}

func NewProvenanceResolver() *ProvenanceResolver {
	client := *http.DefaultClient
	client.Timeout = 15 * time.Second
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || req.URL.Scheme != "https" || req.URL.Host != "api.github.com" {
			return errors.New("untrusted or excessive GitHub API redirect")
		}
		return nil
	}
	return &ProvenanceResolver{client: &client, baseURL: apiURL, statePath: filepath.Join(scharfDir, "provenance.json")}
}

type provenanceRequest struct {
	resolver *ProvenanceResolver
	ctx      context.Context
	requests int
}

type provenanceHTTPError struct{ status int }

func (e provenanceHTTPError) Error() string {
	return fmt.Sprintf("GitHub API HTTP %d; evidence unavailable", e.status)
}

func (r *provenanceRequest) get(path string, target any) error {
	if r.requests >= provenanceMaxRequests {
		return errors.New("provenance request limit reached; evidence incomplete")
	}
	r.requests++
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, r.resolver.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := r.resolver.client.Do(req)
	if err != nil {
		return fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return provenanceHTTPError{status: resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, provenanceMaxBody+1))
	if err != nil {
		return err
	}
	if len(body) > provenanceMaxBody {
		return errors.New("GitHub API response limit reached")
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("invalid GitHub API response: %w", err)
	}
	return nil
}

func validProvenanceRepository(repository string) bool {
	if !provenanceRepository.MatchString(repository) {
		return false
	}
	for _, part := range strings.Split(repository, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

func validProvenanceRef(ref string) bool {
	return ref != "" && !strings.ContainsAny(ref, "~^:?*[\\\x00\r\n\t ") && !strings.Contains(ref, "..") && !strings.Contains(ref, "@{") && !strings.HasPrefix(ref, "/") && !strings.HasSuffix(ref, "/")
}

type provenanceGitObject struct {
	SHA  string `json:"sha"`
	Type string `json:"type"`
}

func (r *provenanceRequest) resolveRef(repository, ref string) (string, string, error) {
	if provenanceSHA.MatchString(ref) {
		return strings.ToLower(ref), "sha", nil
	}
	if !validProvenanceRef(ref) || provenancePartialSHA.MatchString(ref) {
		return "", "", errors.New("ref must be a named tag/branch or full 40-character SHA; abbreviated SHAs are not verified")
	}
	for _, kind := range []string{"tags", "heads"} {
		var result struct {
			Object provenanceGitObject `json:"object"`
		}
		err := r.get("/"+repository+"/git/ref/"+kind+"/"+url.PathEscape(ref), &result)
		if err != nil {
			var status provenanceHTTPError
			if kind == "tags" && errors.As(err, &status) && status.status == http.StatusNotFound {
				continue
			}
			return "", "", err
		}
		object := result.Object
		for depth := 0; depth < 8; depth++ {
			if !provenanceSHA.MatchString(object.SHA) {
				return "", "", errors.New("ref returned a malformed object SHA")
			}
			if object.Type == "commit" {
				return strings.ToLower(object.SHA), kind, nil
			}
			if object.Type != "tag" || kind != "tags" {
				return "", "", errors.New("ref does not resolve to a commit")
			}
			var tag struct {
				Object provenanceGitObject `json:"object"`
			}
			if err := r.get("/"+repository+"/git/tags/"+object.SHA, &tag); err != nil {
				return "", "", err
			}
			object = tag.Object
		}
		return "", "", errors.New("annotated tag depth limit reached")
	}
	return "", "", errors.New("ref unavailable")
}

func (r *provenanceRequest) ancestor(repository, base, head string) (bool, error) {
	if strings.EqualFold(base, head) {
		return true, nil
	}
	var comparison struct {
		Status    string `json:"status"`
		MergeBase Commit `json:"merge_base_commit"`
	}
	// Request a single commit page: only merge-base/status metadata is needed.
	err := r.get("/"+repository+"/compare/"+base+"..."+head+"?per_page=1", &comparison)
	if err != nil {
		return false, err
	}
	return (comparison.Status == "ahead" || comparison.Status == "identical") && strings.EqualFold(comparison.MergeBase.Sha, base), nil
}

func (r *provenanceRequest) supportingRef(repository, sha string) (*ProvenanceRef, error) {
	var unavailable error
	for page := 1; page <= provenanceMaxPages; page++ {
		var branches []BranchOrTag
		if err := r.get(fmt.Sprintf("/%s/branches?per_page=100&page=%d", repository, page), &branches); err != nil {
			return nil, err
		}
		if len(branches) > 100 {
			return nil, errors.New("branch page exceeds requested limit")
		}
		for _, branch := range branches {
			if !validProvenanceRef(branch.Name) || !provenanceSHA.MatchString(branch.Commit.Sha) {
				return nil, errors.New("malformed upstream branch evidence")
			}
			matches, err := r.ancestor(repository, sha, branch.Commit.Sha)
			if err != nil {
				unavailable = err
				continue
			}
			if matches {
				return &ProvenanceRef{Ref: "refs/heads/" + branch.Name, SHA: strings.ToLower(branch.Commit.Sha)}, nil
			}
		}
		if len(branches) < 100 {
			if unavailable != nil {
				return nil, unavailable
			}
			return nil, errors.New("SHA is not reachable from any checked current upstream branch; deleted or rewritten history may explain this")
		}
	}
	return nil, errors.New("branch pagination limit reached; upstream evidence incomplete")
}

// Verify checks a specific full SHA. For existing pins, pass that SHA as ref too;
// version comments are not claims about the current target of a mutable tag.
func (s *ProvenanceResolver) Verify(repository, ref, sha string) *ProvenanceEvidence {
	return s.verify(repository, ref, sha, false)
}

func (s *ProvenanceResolver) verify(repository, ref, sha string, resolve bool) *ProvenanceEvidence {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := &ProvenanceEvidence{Status: ProvenanceUnverified, Repository: repository, OriginalRef: ref, SHA: sha, CheckedAt: time.Now().UTC().Format(time.RFC3339Nano), SupportingRefs: []ProvenanceRef{}}
	if !validProvenanceRepository(repository) || !validProvenanceRef(ref) || (!resolve && (!provenanceSHA.MatchString(sha) || !strings.EqualFold(ref, sha))) {
		e.Reason = "invalid repository, reference, or full commit SHA"
		return e
	}
	observations, err := loadProvenanceObservations(s.statePath)
	if err != nil {
		e.Reason = "historical evidence unavailable: " + err.Error()
		return e
	}
	key := strings.ToLower(repository) + "@" + ref
	if old, ok := observations.Entries[key]; ok {
		e.Previous = &old
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	r := &provenanceRequest{resolver: s, ctx: ctx}
	var repo struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
	}
	if err := r.get("/"+repository, &repo); err != nil {
		e.Reason = err.Error()
		return e
	}
	if repo.ID <= 0 || !validProvenanceRepository(repo.FullName) {
		e.Reason = "repository identity response is incomplete"
		return e
	}
	e.Repository, e.RepositoryID = repo.FullName, repo.ID
	for oldKey, old := range observations.Entries {
		knownPath := strings.HasPrefix(oldKey, strings.ToLower(repository)+"@") || strings.HasPrefix(oldKey, strings.ToLower(repo.FullName)+"@") || strings.EqualFold(old.Repository, repository) || strings.EqualFold(old.Repository, repo.FullName)
		if knownPath && old.RepositoryID != repo.ID {
			copy := old
			e.Previous = &copy
			e.Status, e.RequiresReview, e.Reason = ProvenanceIdentityMismatch, true, "repository ID changed for a previously observed repository; review identity before accepting any new ref"
			return e
		}
	}
	// A renamed repository retains its ID. The old URL or new canonical name
	// may be used, but an existing path must never silently acquire a new ID.
	if e.Previous == nil || e.Previous.RepositoryID == repo.ID {
		for _, old := range observations.Entries {
			if old.RepositoryID == repo.ID && old.OriginalRef == ref {
				if e.Previous == nil || observationTime(old).After(observationTime(*e.Previous)) {
					copy := old
					e.Previous = &copy
				}
			}
		}
	}
	if e.Previous != nil && e.Previous.RepositoryID != repo.ID {
		e.Status, e.RequiresReview, e.Reason = ProvenanceIdentityMismatch, true, "repository ID changed; review the repository identity before accepting a new observation"
		return e
	}
	kind := "sha"
	if resolve {
		sha, kind, err = r.resolveRef(repo.FullName, ref)
		if err != nil {
			e.Reason = err.Error()
			if e.Previous != nil {
				e.RequiresReview = true
				e.Reason = "previously observed ref is unavailable: " + e.Reason
			}
			return e
		}
	}
	e.SHA, e.RefKind = strings.ToLower(sha), kind
	if e.Previous != nil && (!strings.EqualFold(e.Previous.SHA, e.SHA) || e.Previous.RefKind != kind) {
		e.Moved, e.RequiresReview = true, true
	}
	support, err := r.supportingRef(repo.FullName, e.SHA)
	if err != nil {
		e.Reason = err.Error()
		if e.Moved {
			e.Reason = "previously observed ref moved and its new SHA is unverifiable: " + e.Reason
		}
		return e
	}
	e.SupportingRefs = []ProvenanceRef{*support}
	e.Status, e.Reason = ProvenanceVerified, "SHA is reachable from the recorded current upstream branch snapshot; this does not establish benign code"
	if e.Moved {
		e.Moved, e.Status, e.RequiresReview = true, ProvenanceMovedReference, true
		e.Reason = "previously observed ref moved; explicit history review is required"
		if e.Previous.RefKind != kind {
			e.Reason = "ref namespace changed between tag, branch, or SHA; explicit review is required"
		} else if kind == "heads" || (kind == "tags" && provenanceMajorTag.MatchString(ref)) {
			forward, err := r.ancestor(repo.FullName, e.Previous.SHA, e.SHA)
			if err == nil && forward {
				e.RequiresReview = false
				e.Reason = "expected forward advancement of a branch or major-version tag; both ancestry and current upstream membership were checked"
			} else if err != nil {
				e.Reason = "ref moved and its prior ancestry is unavailable: " + err.Error()
			}
		}
	}
	if !e.AllowsUpdate() {
		return e
	}
	// Ref and branch responses do not carry a repository ID. Recheck both the
	// requested path (which the workflow will keep using) and any canonical path
	// used for proof, so a lasting rename/replacement during those calls cannot
	// bind another repository's history to the ID read at the start.
	paths := []string{repository}
	if !strings.EqualFold(repository, repo.FullName) {
		paths = append(paths, repo.FullName)
	}
	for _, path := range paths {
		var current struct {
			ID       int64  `json:"id"`
			FullName string `json:"full_name"`
		}
		if err := r.get("/"+path, &current); err != nil {
			e.Status, e.RequiresReview, e.Reason = ProvenanceUnverified, true, "repository identity recheck unavailable: "+err.Error()
			return e
		}
		if current.ID <= 0 || !validProvenanceRepository(current.FullName) {
			e.Status, e.RequiresReview, e.Reason = ProvenanceUnverified, true, "repository identity recheck is incomplete"
			return e
		}
		if current.ID != repo.ID {
			e.Status, e.RequiresReview = ProvenanceIdentityMismatch, true
			e.Reason = fmt.Sprintf("repository ID changed during verification of %s from %d to %d; review identity before accepting evidence", path, repo.ID, current.ID)
			return e
		}
		if !strings.EqualFold(current.FullName, repo.FullName) {
			e.Status, e.RequiresReview, e.Reason = ProvenanceUnverified, true, "repository canonical name changed during verification; retry with fresh evidence"
			return e
		}
	}
	observation := ProvenanceObservation{Repository: e.Repository, RepositoryID: e.RepositoryID, OriginalRef: ref, RefKind: kind, SHA: e.SHA, CheckedAt: e.CheckedAt, SupportingRefs: e.SupportingRefs}
	if err := saveProvenanceObservation(s.statePath, observations, key, observation); err != nil {
		e.Status, e.RequiresReview, e.Reason = ProvenanceUnverified, true, "cannot safely persist historical evidence: "+err.Error()
	}
	return e
}

func (s *ProvenanceResolver) ResolveWithProvenance(action string) (string, *ProvenanceEvidence, error) {
	parts := splitRawAction(action)
	e := s.verify(parts[0], parts[1], "", true)
	if !e.AllowsUpdate() {
		return e.SHA, e, fmt.Errorf("provenance %s: %s", e.Status, e.Reason)
	}
	return e.SHA, e, nil
}

func (s *ProvenanceResolver) Resolve(action string) (string, error) {
	sha, _, err := s.ResolveWithProvenance(action)
	if err != nil {
		return "", err
	}
	return sha, nil
}

// ListTags is fresh and bounded; incomplete pagination cannot select an upgrade.
func (s *ProvenanceResolver) ListTags(repository string) ([]BranchOrTag, error) {
	if !validProvenanceRepository(repository) {
		return nil, errors.New("invalid repository")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	r := &provenanceRequest{resolver: s, ctx: ctx}
	var tags []BranchOrTag
	for page := 1; page <= provenanceMaxPages; page++ {
		var batch []BranchOrTag
		if err := r.get(fmt.Sprintf("/%s/tags?per_page=100&page=%d", repository, page), &batch); err != nil {
			return nil, err
		}
		if len(batch) > 100 {
			return nil, errors.New("tag page exceeds requested limit")
		}
		tags = append(tags, batch...)
		if len(batch) < 100 {
			return tags, nil
		}
	}
	return nil, errors.New("tag pagination limit reached")
}

func (s *ProvenanceResolver) ResolveNext(action, currentVersion string, cooldownHours int) (*UpgradeResult, error) {
	tags, err := s.ListTags(action)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(tags))
	for _, tag := range tags {
		names = append(names, tag.Name)
	}
	next, found := nextVersion(names, currentVersion)
	if !found {
		return nil, fmt.Errorf("no next version found for %s@%s", action, currentVersion)
	}
	currentSHA, _, err := s.ResolveWithProvenance(action + "@" + currentVersion)
	if err != nil {
		return nil, err
	}
	nextSHA, evidence, err := s.ResolveWithProvenance(action + "@" + next)
	if err != nil {
		return nil, err
	}
	// A missing timestamp keeps the existing cooldown behavior (warning only).
	underCooldown := false
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r := &provenanceRequest{resolver: s, ctx: ctx}
	var commit commitLookupResponse
	if err := r.get("/"+evidence.Repository+"/commits/"+nextSHA, &commit); err == nil {
		if timestamp, err := time.Parse(time.RFC3339, commit.Commit.Committer.Date); err == nil {
			underCooldown = isUnderCooldown(timestamp, cooldownHours)
		}
	}
	return &UpgradeResult{Action: action, CurrentVersion: currentVersion, CurrentSHA: currentSHA, NextVersion: next, NextSHA: nextSHA, CooldownHours: normalizeCooldownHours(cooldownHours), UnderCooldown: underCooldown, Provenance: evidence}, nil
}
