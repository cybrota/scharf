// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// package network handles all GitHub API related network calls

package network

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

// --- Helper functions for testing ---

// roundTripFunc type is an adapter to allow the use of
// ordinary functions as http.RoundTripper.
type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// withHTTPClientTransport temporarily replaces the default transport.
func withHTTPClientTransport(rt http.RoundTripper, fn func()) {
	orig := http.DefaultClient.Transport
	http.DefaultClient.Transport = rt
	defer func() { http.DefaultClient.Transport = orig }()
	fn()
}

// --- Tests for splitRawAction ---

func TestSplitRawAction(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected [2]string
	}{
		{
			name:     "action with version",
			input:    "owner/repo@v1.0.0",
			expected: [2]string{"owner/repo", "v1.0.0"},
		},
		{
			name:     "action without version",
			input:    "owner/repo",
			expected: [2]string{"owner/repo", ""},
		},
		{
			name:     "empty string",
			input:    "",
			expected: [2]string{"", ""},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := splitRawAction(tc.input)
			if got != tc.expected {
				t.Errorf("splitRawAction(%q) = %v; want %v", tc.input, got, tc.expected)
			}
		})
	}
}

// --- Tests for makeAPIEndpoint ---

func TestMakeAPIEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		action   string
		version  string
		expected string
	}{
		{
			name:     "version starts with v (tag)",
			action:   "owner/repo",
			version:  "v1.0.0",
			expected: "https://api.github.com/repos/owner/repo/tags",
		},
		{
			name:     "version does not start with v (branch)",
			action:   "owner/repo",
			version:  "main",
			expected: "https://api.github.com/repos/owner/repo/branches",
		},
		{
			name:     "version lowercase check",
			action:   "owner/repo",
			version:  "V2.0.0", // Even if uppercase, we lowercase the prefix
			expected: "https://api.github.com/repos/owner/repo/tags",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := makeAPIEndpoint(tc.action, tc.version)
			if got != tc.expected {
				t.Errorf("makeAPIEndpoint(%q, %q) = %v; want %v", tc.action, tc.version, got, tc.expected)
			}
		})
	}
}

// --- Tests for searchTag ---

func TestSearchTag(t *testing.T) {
	tags := []BranchOrTag{
		{
			Name: "v1.0.0",
			Commit: Commit{
				Sha: "sha-1",
			},
		},
		{
			Name: "main",
			Commit: Commit{
				Sha: "sha-main",
			},
		},
		{
			Name: "v2.0.0",
			Commit: Commit{
				Sha: "",
			},
		},
	}

	tests := []struct {
		name          string
		version       string
		expectedFound bool
		expectedSHA   string
	}{
		{
			name:          "found valid tag",
			version:       "v1.0.0",
			expectedFound: true,
			expectedSHA:   "sha-1",
		},
		{
			name:          "found branch",
			version:       "main",
			expectedFound: true,
			expectedSHA:   "sha-main",
		},
		{
			name:          "tag exists but empty sha",
			version:       "v2.0.0",
			expectedFound: false,
			expectedSHA:   "",
		},
		{
			name:          "non-existing version",
			version:       "v3.0.0",
			expectedFound: false,
			expectedSHA:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			found, sha := searchTag(tags, tc.version)
			if found != tc.expectedFound || sha != tc.expectedSHA {
				t.Errorf("searchTag(tags, %q) = (%v, %q); want (%v, %q)", tc.version, found, sha, tc.expectedFound, tc.expectedSHA)
			}
		})
	}
}

func TestNextVersion(t *testing.T) {
	// GitHub tags API returns newest first.
	tags := []string{"v1.2.0", "v1.1.0", "v1.0.0"}

	t.Run("finds immediate next version", func(t *testing.T) {
		got, found := nextVersion(tags, "v1.1.0")
		if !found || got != "v1.2.0" {
			t.Fatalf("nextVersion(tags, v1.1.0) = (%s,%v), want (v1.2.0,true)", got, found)
		}
	})

	t.Run("returns not found when current is newest", func(t *testing.T) {
		got, found := nextVersion(tags, "v1.2.0")
		if found || got != "" {
			t.Fatalf("nextVersion(tags, v1.2.0) = (%s,%v), want (\"\",false)", got, found)
		}
	})
}

func TestIsUnderCooldown(t *testing.T) {
	now := time.Now().UTC()

	t.Run("returns true for a fresh tag", func(t *testing.T) {
		fresh := now.Add(-2 * time.Hour)
		if !isUnderCooldown(fresh, 24) {
			t.Fatalf("expected fresh tag to be under cooldown")
		}
	})

	t.Run("returns false for a stale tag", func(t *testing.T) {
		stale := now.Add(-48 * time.Hour)
		if isUnderCooldown(stale, 24) {
			t.Fatalf("expected stale tag to not be under cooldown")
		}
	})

	t.Run("uses safe default when cooldown is non-positive", func(t *testing.T) {
		fresh := now.Add(-2 * time.Hour)
		if !isUnderCooldown(fresh, 0) {
			t.Fatalf("expected cooldown=0 to use safe default and keep tag under cooldown")
		}
	})
}

func TestSHAResolver_ResolveNext(t *testing.T) {
	customTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		data := []BranchOrTag{
			{Name: "v1.2.0", Commit: Commit{Sha: "sha-120"}},
			{Name: "v1.1.0", Commit: Commit{Sha: "sha-110"}},
			{Name: "v1.0.0", Commit: Commit{Sha: "sha-100"}},
		}

		b, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(b)),
			Header:     make(http.Header),
		}, nil
	})

	withHTTPClientTransport(customTransport, func() {
		resolver := SHAResolver{cache: map[string]string{}}
		got, err := resolver.ResolveNext("owner/repo", "v1.1.0", 24)
		if err != nil {
			t.Fatalf("ResolveNext() returned error: %v", err)
		}

		if got.NextVersion != "v1.2.0" {
			t.Fatalf("ResolveNext() next version = %q; want %q", got.NextVersion, "v1.2.0")
		}

		if got.NextSHA != "sha-120" {
			t.Fatalf("ResolveNext() next SHA = %q; want %q", got.NextSHA, "sha-120")
		}
	})
}

func TestSHAResolver_ResolveNext_UnderCooldownFromCommitTimestamp(t *testing.T) {
	now := time.Now().UTC()
	fresh := now.Add(-2 * time.Hour).Format(time.RFC3339)

	customTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var b []byte
		var err error

		switch req.URL.String() {
		case "https://api.github.com/repos/owner/repo/tags":
			data := []BranchOrTag{
				{Name: "v1.2.0", Commit: Commit{Sha: "sha-120"}},
				{Name: "v1.1.0", Commit: Commit{Sha: "sha-110"}},
				{Name: "v1.0.0", Commit: Commit{Sha: "sha-100"}},
			}
			b, err = json.Marshal(data)
		default:
			if strings.Contains(req.URL.String(), "/commits/sha-120") {
				payload := map[string]any{
					"commit": map[string]any{
						"committer": map[string]any{
							"date": fresh,
						},
					},
				}
				b, err = json.Marshal(payload)
			} else {
				return nil, fmt.Errorf("unexpected URL: %s", req.URL.String())
			}
		}

		if err != nil {
			return nil, err
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(b)),
			Header:     make(http.Header),
		}, nil
	})

	withHTTPClientTransport(customTransport, func() {
		resolver := SHAResolver{cache: map[string]string{}}
		got, err := resolver.ResolveNext("owner/repo", "v1.1.0", 24)
		if err != nil {
			t.Fatalf("ResolveNext() returned error: %v", err)
		}

		if !got.UnderCooldown {
			t.Fatalf("ResolveNext() underCooldown = false; want true")
		}
	})
}

// --- Tests for SHAResolver.resolve ---
// We simulate the HTTP response by intercepting http.Get using a custom RoundTripper.
func TestSHAResolver_resolve(t *testing.T) {
	// Prepare a fake list of tags/branches response.
	// For this test we simulate both a valid SHA and a not-found scenario.
	responses := map[string][]BranchOrTag{
		// When version is v1.0.0, return valid tag list.
		"https://api.github.com/repos/owner/repo/tags": {
			{
				Name: "v1.0.0",
				Commit: Commit{
					Sha: "sha-valid",
				},
			},
		},
		// When version is main (or any branch), return branch list.
		"https://api.github.com/repos/owner/repo/branches": {
			{
				Name: "main",
				Commit: Commit{
					Sha: "sha-main",
				},
			},
		},
		// When version is not found.
		"https://api.github.com/repos/owner/repo/tags-notfound": {},
	}

	// customTransport intercepts HTTP requests and returns a fake response.
	customTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		// Use the request URL to determine which fake response to return.
		url := req.URL.String()
		// For test of not found case, we simulate a valid empty list.
		var data []BranchOrTag
		if url == "https://api.github.com/repos/owner/repo/tags" {
			data = responses["https://api.github.com/repos/owner/repo/tags"]
		} else if url == "https://api.github.com/repos/owner/repo/branches" {
			data = responses["https://api.github.com/repos/owner/repo/branches"]
		} else {
			data = responses["https://api.github.com/repos/owner/repo/tags-notfound"]
		}

		b, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(b)),
			Header:     make(http.Header),
		}
		return resp, nil
	})

	// Override the HTTP transport for the duration of these tests.
	withHTTPClientTransport(customTransport, func() {
		tests := []struct {
			name        string
			inputAction string
			expectedSHA string
			expectError bool
		}{
			{
				name:        "valid tag resolution",
				inputAction: "owner/repo@v1.0.0",
				expectedSHA: "sha-valid",
				expectError: false,
			},
			{
				name:        "empty version defaults to main branch",
				inputAction: "owner/repo",
				// When no version is provided, resolve() sets it to "main"
				expectedSHA: "sha-main",
				expectError: false,
			},
			{
				name:        "version not found",
				inputAction: "owner/repo@nonexistent",
				expectError: true,
			},
		}

		resolver := NewSHAResolver()

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				sha, err := resolver.Resolve(tc.inputAction)
				if tc.expectError {
					if err == nil {
						t.Errorf("Expected error for input %q, got nil", tc.inputAction)
					}
				} else {
					if err != nil {
						t.Errorf("Unexpected error for input %q: %v", tc.inputAction, err)
					}
					if sha != tc.expectedSHA {
						t.Errorf("resolve(%q) returned sha %q; want %q", tc.inputAction, sha, tc.expectedSHA)
					}
				}
			})
		}
	})
}

// --- Test for handling HTTP errors in resolve ---
func TestSHAResolver_resolve_HTTPError(t *testing.T) {
	// Create a custom transport that simulates an HTTP error.
	customTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("simulated http error")
	})

	withHTTPClientTransport(customTransport, func() {
		resolver := SHAResolver{}
		_, err := resolver.Resolve("owner/repo@v1.0.0")
		if err == nil {
			t.Errorf("Expected error when HTTP GET fails, got nil")
		}
	})
}

// --- Test for handling invalid JSON in resolve ---
func TestSHAResolver_resolve_InvalidJSON(t *testing.T) {
	// Create a custom transport that returns invalid JSON.
	customTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		b := []byte("invalid json")
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(b)),
			Header:     make(http.Header),
		}
		return resp, nil
	})

	withHTTPClientTransport(customTransport, func() {
		resolver := SHAResolver{}
		_, err := resolver.Resolve("owner/repo@v1.0.0")
		if err == nil {
			t.Errorf("Expected error when JSON decoding fails, got nil")
		}
	})
}

// --- Tests for GetRefList ---
func TestGetRefList(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		// Prepare the expected list of BranchOrTag objects.
		expectedRefs := []BranchOrTag{
			{
				Name: "v1.0.0",
				Commit: Commit{
					Sha: "sha-1",
					URL: "https://example.com/commit/sha-1",
				},
			},
			{
				Name: "v2.0.0",
				Commit: Commit{
					Sha: "sha-2",
					URL: "https://example.com/commit/sha-2",
				},
			},
		}
		// Marshal the expected data into JSON.
		b, err := json.Marshal(expectedRefs)
		if err != nil {
			t.Fatalf("failed to marshal expectedRefs: %v", err)
		}

		// Create a custom transport that returns the expected JSON.
		customTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			// Verify that the URL is constructed as expected.
			expectedURL := "https://api.github.com/repos/owner/repo/tags"
			if req.URL.String() != expectedURL {
				t.Errorf("unexpected URL: got %q, want %q", req.URL.String(), expectedURL)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(b)),
				Header:     make(http.Header),
			}, nil
		})

		// Use the custom transport to override http.DefaultClient.Transport.
		withHTTPClientTransport(customTransport, func() {
			refs, err := GetRefList("owner/repo")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(refs, expectedRefs) {
				t.Errorf("GetRefList() = %v; want %v", refs, expectedRefs)
			}
		})
	})

	t.Run("http error", func(t *testing.T) {
		// Create a custom transport that simulates an HTTP error.
		customTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("simulated http error")
		})
		withHTTPClientTransport(customTransport, func() {
			_, err := GetRefList("owner/repo")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), "simulated http error") {
				t.Errorf("unexpected error message: %v", err)
			}
		})
	})

	t.Run("invalid JSON", func(t *testing.T) {
		// Create a custom transport that returns invalid JSON.
		customTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			invalidJSON := []byte("invalid json")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(invalidJSON)),
				Header:     make(http.Header),
			}, nil
		})
		withHTTPClientTransport(customTransport, func() {
			_, err := GetRefList("owner/repo")
			if err == nil {
				t.Fatal("expected error due to invalid JSON, got nil")
			}
			if !strings.Contains(err.Error(), "json:") {
				t.Errorf("unexpected error message: %v", err)
			}
		})
	})
}

func TestGetRefList_UsesGitHubTokenWhenPresent(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "test-token")

	customTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		authHeader := req.Header.Get("Authorization")
		if authHeader != "Bearer test-token" {
			t.Fatalf("authorization header = %q; want %q", authHeader, "Bearer test-token")
		}

		b := []byte(`[]`)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(b)),
			Header:     make(http.Header),
		}, nil
	})

	withHTTPClientTransport(customTransport, func() {
		_, err := GetRefList("owner/repo")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
