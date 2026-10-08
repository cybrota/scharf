// Copyright (c) 2025 Naren Yellavula & Cybrota contributors
// Apache License, Version 2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package network

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const metadataSHA = "1111111111111111111111111111111111111111"

func TestDependencyClientExactCommit(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("missing token")
		}
		if strings.Contains(r.URL.Path, "/commits/") {
			fmt.Fprintf(w, `{"sha":%q}`, metadataSHA)
			return
		}
		fmt.Fprintf(w, `{"type":"file","encoding":"base64","size":4,"content":%q}`, base64.StdEncoding.EncodeToString([]byte("data")))
	}))
	defer server.Close()
	c := NewDependencyClient()
	c.BaseURL = server.URL
	c.Token = "fixture-token"
	sha, err := c.Resolve("example/action@v1")
	if err != nil || sha != metadataSHA {
		t.Fatalf("%s %v", sha, err)
	}
	b, err := c.ReadMetadata("example/action", sha, "nested/action.yml")
	if err != nil || string(b) != "data" {
		t.Fatalf("%s %v", b, err)
	}
	if paths[1] != "/repos/example/action/contents/nested/action.yml?ref="+metadataSHA {
		t.Fatal(paths)
	}
}
func TestDependencyClientFailures(t *testing.T) {
	for _, status := range []int{404, 403, 429, 500, 302} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "http://127.0.0.1:1")
				w.WriteHeader(status)
			}))
			defer server.Close()
			c := NewDependencyClient()
			c.BaseURL = server.URL
			_, err := c.ReadMetadata("example/action", metadataSHA, "action.yml")
			if err == nil {
				t.Fatal("expected error")
			}
			if status == 404 && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
		})
	}
	c := NewDependencyClient()
	c.MaxRequests = 0
	if _, err := c.Resolve("example/action@v1"); err == nil {
		t.Fatal("missing budget enforcement")
	}
	for _, name := range []string{"../action.yml", "/action.yml", "nested/../action.yml", "a\\b"} {
		if _, err := c.ReadMetadata("example/action", metadataSHA, name); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
}
func TestDependencyClientRejectsSymlinkAndOversize(t *testing.T) {
	for _, body := range []string{`{"type":"symlink","encoding":"base64","content":""}`, `{"type":"file","encoding":"none","content":""}`, `{"type":"file","encoding":"base64","size":1048577}`, strings.Repeat("x", (2<<20)+1)} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		c := NewDependencyClient()
		c.BaseURL = server.URL
		_, err := c.ReadMetadata("example/action", metadataSHA, "action.yml")
		server.Close()
		if err == nil {
			t.Fatal("accepted unsupported metadata")
		}
	}
}
