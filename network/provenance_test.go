// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package network

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var provenanceTestSHA = strings.Repeat("a", 40)
var provenanceTestNext = strings.Repeat("b", 40)
var provenanceTestTag = strings.Repeat("c", 40)

func fakeProvenance(t *testing.T, handler http.HandlerFunc) *ProvenanceResolver {
	t.Helper()
	t.Setenv("GITHUB_TOKEN", "")
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &ProvenanceResolver{client: server.Client(), baseURL: server.URL, statePath: filepath.Join(t.TempDir(), "provenance.json")}
}

func provenanceJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func provenanceBranch(w http.ResponseWriter, sha string) {
	provenanceJSON(w, []BranchOrTag{{Name: "main", Commit: Commit{Sha: sha}}})
}

func provenanceIdentity(w http.ResponseWriter, id int64, name string) {
	provenanceJSON(w, map[string]any{"id": id, "full_name": name})
}

func writeProvenanceHistory(t *testing.T, resolver *ProvenanceResolver, ref, sha string, id int64) {
	t.Helper()
	store, err := loadProvenanceObservations(resolver.statePath)
	if err != nil {
		t.Fatal(err)
	}
	kind := "tags"
	if provenanceSHA.MatchString(ref) {
		kind = "sha"
	} else if ref == "main" || ref == "removed-branch" {
		kind = "heads"
	}
	err = saveProvenanceObservation(resolver.statePath, store, "owner/action@"+ref, ProvenanceObservation{
		Repository: "owner/action", RepositoryID: id, OriginalRef: ref, RefKind: kind, SHA: sha,
		CheckedAt:      time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339Nano),
		SupportingRefs: []ProvenanceRef{{Ref: "refs/heads/main", SHA: sha}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestProvenanceReachability(t *testing.T) {
	for _, tc := range []struct {
		name, branch, status, mergeBase string
		verified                        bool
	}{
		{"branch-tip", provenanceTestSHA, "", "", true},
		{"ancestor", provenanceTestNext, "ahead", provenanceTestSHA, true},
		{"fork-only-addressable", provenanceTestNext, "diverged", provenanceTestTag, false},
		{"ahead-with-wrong-merge-base", provenanceTestNext, "ahead", provenanceTestTag, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			commitsCalled := false
			resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/owner/action":
					provenanceIdentity(w, 1, "owner/action")
				case r.URL.Path == "/owner/action/branches":
					provenanceBranch(w, tc.branch)
				case strings.Contains(r.URL.Path, "/compare/"):
					if r.URL.Query().Get("per_page") != "1" {
						t.Error("comparison must be bounded")
					}
					provenanceJSON(w, map[string]any{"status": tc.status, "merge_base_commit": Commit{Sha: tc.mergeBase}})
				case strings.Contains(r.URL.Path, "/commits/"):
					commitsCalled = true
					provenanceJSON(w, Commit{Sha: provenanceTestSHA})
				default:
					t.Errorf("unexpected request %s", r.URL)
					http.NotFound(w, r)
				}
			})
			evidence := resolver.Verify("owner/action", provenanceTestSHA, provenanceTestSHA)
			if evidence.AllowsUpdate() != tc.verified {
				t.Fatalf("unexpected evidence: %+v", evidence)
			}
			if commitsCalled {
				t.Fatal("commit addressability must not be used as membership")
			}
			if evidence.CheckedAt == "" || evidence.RepositoryID != 1 {
				t.Fatal("missing identity/check timestamp")
			}
			if tc.verified && (len(evidence.SupportingRefs) != 1 || evidence.SupportingRefs[0].Ref != "refs/heads/main" || evidence.SupportingRefs[0].SHA != tc.branch) {
				t.Fatal("missing exact supporting branch snapshot")
			}
		})
	}
}

func TestProvenanceAnnotatedTag(t *testing.T) {
	resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owner/action":
			provenanceIdentity(w, 1, "owner/action")
		case "/owner/action/git/ref/tags/v1.2.3":
			provenanceJSON(w, map[string]any{"object": provenanceGitObject{SHA: provenanceTestTag, Type: "tag"}})
		case "/owner/action/git/tags/" + provenanceTestTag:
			provenanceJSON(w, map[string]any{"object": provenanceGitObject{SHA: provenanceTestSHA, Type: "commit"}})
		case "/owner/action/branches":
			provenanceBranch(w, provenanceTestSHA)
		default:
			t.Errorf("unexpected request %s", r.URL)
			http.NotFound(w, r)
		}
	})
	sha, evidence, err := resolver.ResolveWithProvenance("owner/action@v1.2.3")
	if err != nil || sha != provenanceTestSHA || !evidence.AllowsUpdate() {
		t.Fatalf("annotated tag: %s %+v %v", sha, evidence, err)
	}
}

func TestProvenanceRejectsMalformedSHA(t *testing.T) {
	for _, sha := range []string{"abcdef0", strings.Repeat("a", 39), strings.Repeat("g", 40), strings.Repeat("a", 41), ""} {
		t.Run(fmt.Sprintf("length-%d-%s", len(sha), sha), func(t *testing.T) {
			resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) { t.Error("invalid SHA must not make requests") })
			evidence := resolver.Verify("owner/action", sha, sha)
			if evidence.AllowsUpdate() || evidence.Status != ProvenanceUnverified {
				t.Fatalf("invalid SHA accepted: %+v", evidence)
			}
		})
	}
}

func TestProvenanceIdentityChanges(t *testing.T) {
	for _, tc := range []struct {
		name     string
		id       int64
		expected string
	}{
		{"rename-preserves-id", 1, ProvenanceVerified},
		{"replacement-changes-id", 2, ProvenanceIdentityMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/owner/action", "/new-owner/renamed":
					provenanceIdentity(w, tc.id, "new-owner/renamed")
				case "/new-owner/renamed/branches":
					provenanceBranch(w, provenanceTestSHA)
				default:
					t.Errorf("unexpected request %s", r.URL)
					http.NotFound(w, r)
				}
			})
			writeProvenanceHistory(t, resolver, provenanceTestSHA, provenanceTestSHA, 1)
			evidence := resolver.Verify("owner/action", provenanceTestSHA, provenanceTestSHA)
			if evidence.Status != tc.expected || evidence.Repository != "new-owner/renamed" {
				t.Fatalf("identity evidence: %+v", evidence)
			}
			if tc.id == 2 && (!evidence.RequiresReview || evidence.AllowsUpdate()) {
				t.Fatal("identity mismatch must require review")
			}
		})
	}
}

func TestProvenanceMovedRefs(t *testing.T) {
	for _, tc := range []struct {
		name, ref, compare string
		allowed            bool
	}{
		{"major-forward", "v1", "ahead", true},
		{"major-force-moved", "v1", "diverged", false},
		{"patch-force-moved", "v1.2.3", "diverged", false},
		{"patch-forward-still-review", "v1.2.3", "ahead", false},
		{"branch-forward", "main", "ahead", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/owner/action":
					provenanceIdentity(w, 1, "owner/action")
				case r.URL.Path == "/owner/action/git/ref/tags/main":
					http.NotFound(w, r)
				case strings.Contains(r.URL.Path, "/git/ref/"):
					provenanceJSON(w, map[string]any{"object": provenanceGitObject{SHA: provenanceTestNext, Type: "commit"}})
				case r.URL.Path == "/owner/action/branches":
					provenanceBranch(w, provenanceTestNext)
				case strings.Contains(r.URL.Path, "/compare/"):
					provenanceJSON(w, map[string]any{"status": tc.compare, "merge_base_commit": Commit{Sha: provenanceTestSHA}})
				default:
					t.Errorf("unexpected request %s", r.URL)
					http.NotFound(w, r)
				}
			})
			writeProvenanceHistory(t, resolver, tc.ref, provenanceTestSHA, 1)
			_, evidence, err := resolver.ResolveWithProvenance("owner/action@" + tc.ref)
			if !evidence.Moved || evidence.Status != ProvenanceMovedReference || evidence.AllowsUpdate() != tc.allowed || (err == nil) != tc.allowed {
				t.Fatalf("moved evidence: %+v err=%v", evidence, err)
			}
			store, loadErr := loadProvenanceObservations(resolver.statePath)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			want := provenanceTestSHA
			if tc.allowed {
				want = provenanceTestNext
			}
			if store.Entries["owner/action@"+tc.ref].SHA != want {
				t.Fatal("suspicious movement replaced historical observation")
			}
		})
	}
}

func TestProvenanceUnavailableNeverReusesOldEvidence(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusTooManyRequests, http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
			writeProvenanceHistory(t, resolver, provenanceTestSHA, provenanceTestSHA, 1)
			evidence := resolver.Verify("owner/action", provenanceTestSHA, provenanceTestSHA)
			if evidence.AllowsUpdate() || evidence.Status != ProvenanceUnverified || !strings.Contains(evidence.Reason, fmt.Sprint(status)) {
				t.Fatalf("stale evidence reused: %+v", evidence)
			}
			if len(evidence.SupportingRefs) != 0 || evidence.Previous == nil {
				t.Fatal("current and historical evidence must remain separate")
			}
		})
	}
}

func TestProvenanceRemovedBranchAndInaccessibleHistory(t *testing.T) {
	for _, removed := range []bool{false, true} {
		t.Run(fmt.Sprint(removed), func(t *testing.T) {
			resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/owner/action":
					provenanceIdentity(w, 1, "owner/action")
				case r.URL.Path == "/owner/action/branches":
					if removed {
						provenanceJSON(w, []BranchOrTag{})
					} else {
						provenanceBranch(w, provenanceTestNext)
					}
				default:
					http.NotFound(w, r)
				}
			})
			writeProvenanceHistory(t, resolver, provenanceTestSHA, provenanceTestSHA, 1)
			evidence := resolver.Verify("owner/action", provenanceTestSHA, provenanceTestSHA)
			if evidence.AllowsUpdate() || evidence.Status != ProvenanceUnverified {
				t.Fatalf("unavailable history accepted: %+v", evidence)
			}
		})
	}
}

func TestProvenancePaginationAndRequestLimit(t *testing.T) {
	for _, found := range []bool{false, true} {
		t.Run(fmt.Sprint(found), func(t *testing.T) {
			requests := 0
			resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) {
				requests++
				switch {
				case r.URL.Path == "/owner/action":
					provenanceIdentity(w, 1, "owner/action")
				case r.URL.Path == "/owner/action/branches":
					if found && r.URL.Query().Get("page") == "2" {
						provenanceBranch(w, provenanceTestSHA)
						return
					}
					branches := make([]BranchOrTag, 100)
					for i := range branches {
						branches[i] = BranchOrTag{Name: fmt.Sprintf("branch-%d", i), Commit: Commit{Sha: provenanceTestNext}}
					}
					provenanceJSON(w, branches)
				case strings.Contains(r.URL.Path, "/compare/"):
					provenanceJSON(w, map[string]any{"status": "diverged", "merge_base_commit": Commit{Sha: provenanceTestTag}})
				default:
					t.Errorf("unexpected request %s", r.URL)
					http.NotFound(w, r)
				}
			})
			evidence := resolver.Verify("owner/action", provenanceTestSHA, provenanceTestSHA)
			if evidence.AllowsUpdate() != found {
				t.Fatalf("pagination evidence: %+v", evidence)
			}
			if requests > provenanceMaxRequests {
				t.Fatalf("unbounded requests: %d", requests)
			}
		})
	}
}

func TestProvenanceDoesNotReadLegacyCache(t *testing.T) {
	resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTooManyRequests) })
	legacy := filepath.Join(filepath.Dir(resolver.statePath), "cache.json")
	if err := os.WriteFile(legacy, []byte(`{"owner/action@v1":{"sha":"`+provenanceTestSHA+`","updated_at":"2020-01-01T00:00:00Z"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sha, evidence, err := resolver.ResolveWithProvenance("owner/action@v1")
	if err == nil || sha != "" || evidence.AllowsUpdate() {
		t.Fatalf("legacy cache used as proof: %s %+v %v", sha, evidence, err)
	}
}

func TestProvenanceCorruptStateFailsClosed(t *testing.T) {
	resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) { t.Error("corrupt history must fail before network") })
	if err := os.WriteFile(resolver.statePath, []byte("invalid JSON"), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence := resolver.Verify("owner/action", provenanceTestSHA, provenanceTestSHA)
	if evidence.AllowsUpdate() || !strings.Contains(evidence.Reason, "historical evidence unavailable") {
		t.Fatalf("corrupt state ignored: %+v", evidence)
	}
}

func TestProvenanceReplacementCannotBypassIdentityWithNewRef(t *testing.T) {
	resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/owner/action" {
			t.Errorf("must reject identity before resolving new ref: %s", r.URL)
		}
		provenanceIdentity(w, 2, "owner/action")
	})
	writeProvenanceHistory(t, resolver, "v1", provenanceTestSHA, 1)
	_, evidence, err := resolver.ResolveWithProvenance("owner/action@v2")
	if err == nil || evidence.Status != ProvenanceIdentityMismatch || !evidence.RequiresReview {
		t.Fatalf("new ref bypassed identity history: %+v %v", evidence, err)
	}
}

func TestProvenanceBoundsResponseAndAnnotatedTagDepth(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		t.Run(fmt.Sprint(oversized), func(t *testing.T) {
			requests := 0
			resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.URL.Path == "/owner/action" {
					if oversized {
						_, _ = fmt.Fprint(w, strings.Repeat(" ", provenanceMaxBody+1))
						return
					}
					provenanceIdentity(w, 1, "owner/action")
					return
				}
				provenanceJSON(w, map[string]any{"object": provenanceGitObject{SHA: provenanceTestTag, Type: "tag"}})
			})
			_, evidence, err := resolver.ResolveWithProvenance("owner/action@v1")
			if err == nil || evidence.AllowsUpdate() || !strings.Contains(evidence.Reason, "limit") {
				t.Fatalf("limit not enforced: %+v %v", evidence, err)
			}
			if requests > 10 {
				t.Fatalf("unbounded tag peeling: %d", requests)
			}
		})
	}
}

func TestProvenanceStateConcurrentChangeFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provenance.json")
	first, err := loadProvenanceObservations(path)
	if err != nil {
		t.Fatal(err)
	}
	other, err := loadProvenanceObservations(path)
	if err != nil {
		t.Fatal(err)
	}
	observation := ProvenanceObservation{Repository: "owner/action", RepositoryID: 1, OriginalRef: "v1", RefKind: "tags", SHA: provenanceTestSHA, CheckedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := saveProvenanceObservation(path, first, "owner/action@v1", observation); err != nil {
		t.Fatal(err)
	}
	if err := saveProvenanceObservation(path, other, "owner/action@v1", observation); err == nil {
		t.Fatal("stale state snapshot overwrote another verifier")
	}
}

func TestProvenanceMissingObservedRefStaysUnknown(t *testing.T) {
	resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/owner/action" {
			provenanceIdentity(w, 1, "owner/action")
			return
		}
		http.NotFound(w, r)
	})
	writeProvenanceHistory(t, resolver, "removed-branch", provenanceTestSHA, 1)
	_, evidence, err := resolver.ResolveWithProvenance("owner/action@removed-branch")
	if err == nil || evidence.Status != ProvenanceUnverified || !evidence.RequiresReview || evidence.Previous == nil {
		t.Fatalf("removed ref evidence: %+v %v", evidence, err)
	}
}

func TestProvenanceMalformedStateSchemaFailsClosed(t *testing.T) {
	for _, content := range []string{`{}`, `null`, `{"unrelated":true}`, `{"version":1}`, `{"observations":{}}`, `{"version":2,"observations":{}}`} {
		t.Run(content, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "provenance.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadProvenanceObservations(path); err == nil {
				t.Fatal("malformed state accepted")
			}
		})
	}
}

func TestProvenanceMovedRefRetainedWhenNewHistoryUnavailable(t *testing.T) {
	resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owner/action":
			provenanceIdentity(w, 1, "owner/action")
		case "/owner/action/git/ref/tags/v1.2.3":
			provenanceJSON(w, map[string]any{"object": provenanceGitObject{SHA: provenanceTestNext, Type: "commit"}})
		case "/owner/action/branches":
			provenanceJSON(w, []BranchOrTag{})
		default:
			http.NotFound(w, r)
		}
	})
	writeProvenanceHistory(t, resolver, "v1.2.3", provenanceTestSHA, 1)
	_, evidence, err := resolver.ResolveWithProvenance("owner/action@v1.2.3")
	if err == nil || evidence.Status != ProvenanceUnverified || !evidence.Moved || !evidence.RequiresReview || evidence.SHA != provenanceTestNext || evidence.Previous.SHA != provenanceTestSHA {
		t.Fatalf("movement evidence lost: %+v %v", evidence, err)
	}
}

func TestProvenanceNamespaceChangesRequireReview(t *testing.T) {
	for _, previousKind := range []string{"heads", "tags"} {
		t.Run(previousKind, func(t *testing.T) {
			resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/owner/action":
					provenanceIdentity(w, 1, "owner/action")
				case previousKind == "tags" && r.URL.Path == "/owner/action/git/ref/tags/v1":
					http.NotFound(w, r)
				case strings.Contains(r.URL.Path, "/git/ref/"):
					provenanceJSON(w, map[string]any{"object": provenanceGitObject{SHA: provenanceTestNext, Type: "commit"}})
				case r.URL.Path == "/owner/action/branches":
					provenanceBranch(w, provenanceTestNext)
				case strings.Contains(r.URL.Path, "/compare/"):
					provenanceJSON(w, map[string]any{"status": "ahead", "merge_base_commit": Commit{Sha: provenanceTestSHA}})
				default:
					http.NotFound(w, r)
				}
			})
			store, err := loadProvenanceObservations(resolver.statePath)
			if err != nil {
				t.Fatal(err)
			}
			observation := ProvenanceObservation{Repository: "owner/action", RepositoryID: 1, OriginalRef: "v1", RefKind: previousKind, SHA: provenanceTestSHA, CheckedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)}
			if err := saveProvenanceObservation(resolver.statePath, store, "owner/action@v1", observation); err != nil {
				t.Fatal(err)
			}
			_, evidence, err := resolver.ResolveWithProvenance("owner/action@v1")
			if err == nil || evidence.AllowsUpdate() || !evidence.Moved || !evidence.RequiresReview || !strings.Contains(evidence.Reason, "namespace changed") {
				t.Fatalf("namespace change accepted: %+v %v", evidence, err)
			}
		})
	}
}

func TestProvenanceRedirectsStayOnTrustedGitHubAPI(t *testing.T) {
	for _, destination := range []string{"https://untrusted.example/repos/owner/action", "http://api.github.com/repos/owner/action", "https://api.github.com/repos/owner/action"} {
		t.Run(destination, func(t *testing.T) {
			t.Setenv("GITHUB_TOKEN", "fixture-token")
			resolver := NewProvenanceResolver()
			resolver.statePath = filepath.Join(t.TempDir(), "provenance.json")
			calls := 0
			resolver.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.URL.Host != "api.github.com" || request.URL.Scheme != "https" {
					t.Errorf("followed untrusted redirect: %s", request.URL)
				}
				return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{destination}}, Body: http.NoBody, Request: request}, nil
			})
			evidence := resolver.Verify("owner/action", provenanceTestSHA, provenanceTestSHA)
			if evidence.AllowsUpdate() || evidence.Status != ProvenanceUnverified {
				t.Fatalf("redirect verified: %+v", evidence)
			}
			if calls > 3 {
				t.Fatalf("redirect limit exceeded: %d", calls)
			}
		})
	}
}

func TestProvenanceTimeoutIsUnverified(t *testing.T) {
	resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	resolver.client.Timeout = 10 * time.Millisecond
	evidence := resolver.Verify("owner/action", provenanceTestSHA, provenanceTestSHA)
	if evidence.AllowsUpdate() || evidence.Status != ProvenanceUnverified {
		t.Fatalf("timeout verified: %+v", evidence)
	}
}

func TestProvenancePersistenceFailureRefusesUpdates(t *testing.T) {
	resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/owner/action" {
			provenanceIdentity(w, 1, "owner/action")
			return
		}
		provenanceBranch(w, provenanceTestSHA)
	})
	if err := os.Mkdir(resolver.statePath+".lock", 0o700); err != nil {
		t.Fatal(err)
	}
	evidence := resolver.Verify("owner/action", provenanceTestSHA, provenanceTestSHA)
	if evidence.AllowsUpdate() || evidence.Status != ProvenanceUnverified || !evidence.RequiresReview || !strings.Contains(evidence.Reason, "persist") {
		t.Fatalf("unpersisted observation accepted: %+v", evidence)
	}
}

func TestProvenanceNonCommitTagAndMalformedResponses(t *testing.T) {
	for _, stage := range []string{"tag-blob", "malformed-branch", "malformed-comparison"} {
		t.Run(stage, func(t *testing.T) {
			resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/owner/action":
					provenanceIdentity(w, 1, "owner/action")
				case strings.Contains(r.URL.Path, "/git/ref/"):
					objectType := "commit"
					if stage == "tag-blob" {
						objectType = "blob"
					}
					provenanceJSON(w, map[string]any{"object": provenanceGitObject{SHA: provenanceTestSHA, Type: objectType}})
				case r.URL.Path == "/owner/action/branches":
					if stage == "malformed-branch" {
						_, _ = fmt.Fprint(w, "not JSON")
						return
					}
					provenanceBranch(w, provenanceTestNext)
				default:
					_, _ = fmt.Fprint(w, "not JSON")
				}
			})
			_, evidence, err := resolver.ResolveWithProvenance("owner/action@v1")
			if err == nil || evidence.AllowsUpdate() {
				t.Fatalf("malformed API evidence accepted: %+v %v", evidence, err)
			}
		})
	}
}

func TestProvenanceTagPaginationIsBounded(t *testing.T) {
	for _, complete := range []bool{false, true} {
		t.Run(fmt.Sprint(complete), func(t *testing.T) {
			requests := 0
			resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.URL.Path != "/owner/action/tags" {
					t.Errorf("unexpected tag request: %s", r.URL)
				}
				if complete && r.URL.Query().Get("page") == "2" {
					provenanceJSON(w, []BranchOrTag{})
					return
				}
				tags := make([]BranchOrTag, 100)
				for i := range tags {
					tags[i] = BranchOrTag{Name: fmt.Sprintf("v%d", i), Commit: Commit{Sha: provenanceTestSHA}}
				}
				provenanceJSON(w, tags)
			})
			tags, err := resolver.ListTags("owner/action")
			if (err == nil) != complete || requests > provenanceMaxPages {
				t.Fatalf("tag pagination unbounded/incomplete: %d %v", requests, err)
			}
			if complete && len(tags) != 100 {
				t.Fatalf("lost paginated tags: %d", len(tags))
			}
		})
	}
}

func TestProvenanceRejectsIdentityReplacementDuringVerification(t *testing.T) {
	for _, mode := range []string{"pin", "mutable", "redirected-input", "canonical-path"} {
		t.Run(mode, func(t *testing.T) {
			canonical := "owner/action"
			if mode == "redirected-input" || mode == "canonical-path" {
				canonical = "new-owner/action"
			}
			proofRead := false
			resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/owner/action", "/new-owner/action":
					id := int64(1)
					if proofRead && (mode == "pin" || mode == "mutable" ||
						mode == "redirected-input" && r.URL.Path == "/owner/action" ||
						mode == "canonical-path" && r.URL.Path == "/new-owner/action") {
						id = 2
					}
					provenanceIdentity(w, id, canonical)
				case "/" + canonical + "/git/ref/tags/v1":
					provenanceJSON(w, map[string]any{"object": provenanceGitObject{SHA: provenanceTestSHA, Type: "commit"}})
				case "/" + canonical + "/branches":
					// The path now addresses a replacement repository, but its
					// branch response contains no repository ID to reveal that.
					proofRead = true
					provenanceBranch(w, provenanceTestSHA)
				default:
					t.Errorf("unexpected request %s", r.URL)
					http.NotFound(w, r)
				}
			})
			var evidence *ProvenanceEvidence
			if mode == "mutable" {
				_, evidence, _ = resolver.ResolveWithProvenance("owner/action@v1")
			} else {
				evidence = resolver.Verify("owner/action", provenanceTestSHA, provenanceTestSHA)
			}
			if evidence.AllowsUpdate() || evidence.Status != ProvenanceIdentityMismatch || !evidence.RequiresReview {
				t.Fatalf("mixed repository identities accepted: %+v", evidence)
			}
			if _, err := os.Stat(resolver.statePath); !os.IsNotExist(err) {
				t.Fatalf("mixed-identity observation persisted: %v", err)
			}
		})
	}
}

func TestProvenanceFinalIdentityCheckFailsClosed(t *testing.T) {
	for _, failure := range []string{"rate-limited", "missing-id", "malformed-json", "renamed-during-proof"} {
		t.Run(failure, func(t *testing.T) {
			identityReads := 0
			resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/owner/action":
					identityReads++
					if identityReads == 1 {
						provenanceIdentity(w, 1, "owner/action")
						return
					}
					switch failure {
					case "rate-limited":
						w.WriteHeader(http.StatusTooManyRequests)
					case "missing-id":
						provenanceIdentity(w, 0, "owner/action")
					case "malformed-json":
						_, _ = fmt.Fprint(w, "invalid JSON")
					case "renamed-during-proof":
						provenanceIdentity(w, 1, "new-owner/renamed")
					}
				case "/owner/action/branches":
					provenanceBranch(w, provenanceTestSHA)
				default:
					t.Errorf("unexpected request %s", r.URL)
					http.NotFound(w, r)
				}
			})
			writeProvenanceHistory(t, resolver, provenanceTestSHA, provenanceTestSHA, 1)
			before, err := os.ReadFile(resolver.statePath)
			if err != nil {
				t.Fatal(err)
			}
			evidence := resolver.Verify("owner/action", provenanceTestSHA, provenanceTestSHA)
			if identityReads != 2 || evidence.AllowsUpdate() || evidence.Status != ProvenanceUnverified || !evidence.RequiresReview {
				t.Fatalf("incomplete final identity accepted: %+v, reads=%d", evidence, identityReads)
			}
			after, err := os.ReadFile(resolver.statePath)
			if err != nil || string(after) != string(before) {
				t.Fatalf("failed recheck overwrote prior history: %s, %v", after, err)
			}
		})
	}
}

func TestProvenanceIdentityRecheckSharesRequestBudget(t *testing.T) {
	requests := 0
	resolver := fakeProvenance(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch {
		case r.URL.Path == "/owner/action":
			provenanceIdentity(w, 1, "owner/action")
		case r.URL.Path == "/owner/action/branches":
			count := 100
			if r.URL.Query().Get("page") == "2" {
				count = 26
			}
			branches := make([]BranchOrTag, count)
			for i := range branches {
				branches[i] = BranchOrTag{Name: fmt.Sprintf("branch-%d", i), Commit: Commit{Sha: provenanceTestNext}}
			}
			if count == 26 {
				branches[25].Commit.Sha = provenanceTestSHA
			}
			provenanceJSON(w, branches)
		case strings.Contains(r.URL.Path, "/compare/"):
			provenanceJSON(w, map[string]any{"status": "diverged", "merge_base_commit": Commit{Sha: provenanceTestTag}})
		default:
			t.Errorf("unexpected request %s", r.URL)
			http.NotFound(w, r)
		}
	})
	evidence := resolver.Verify("owner/action", provenanceTestSHA, provenanceTestSHA)
	if requests != provenanceMaxRequests || evidence.AllowsUpdate() || evidence.Status != ProvenanceUnverified || !strings.Contains(evidence.Reason, "request limit") {
		t.Fatalf("final identity check escaped budget or allowed incomplete proof: %+v, requests=%d", evidence, requests)
	}
	if _, err := os.Stat(resolver.statePath); !os.IsNotExist(err) {
		t.Fatalf("incomplete observation persisted: %v", err)
	}
}
