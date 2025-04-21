package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
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
				sha, err := resolver.resolve(tc.inputAction)
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
		_, err := resolver.resolve("owner/repo@v1.0.0")
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
		_, err := resolver.resolve("owner/repo@v1.0.0")
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
