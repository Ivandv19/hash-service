// Package api contains tests for the HTTP helper utilities.
package api

import (
	"net/http/httptest"
	"testing"
)

func TestSecureCompare(t *testing.T) {
	if !SecureCompare("abc123", "abc123") {
		t.Fatal("expected SecureCompare to return true for equal strings")
	}
	if SecureCompare("abc123", "abc124") {
		t.Fatal("expected SecureCompare to return false for different strings")
	}
}

func TestIsJSONContentType(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		expects bool
	}{
		{name: "plain json", input: "application/json", expects: true},
		{name: "json with charset", input: "application/json; charset=utf-8", expects: true},
		{name: "wrong type", input: "text/plain", expects: false},
		{name: "empty", input: "", expects: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsJSONContentType(tc.input); got != tc.expects {
				t.Fatalf("expected %v, got %v", tc.expects, got)
			}
		})
	}
}

func TestExtractClientIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	if got := ExtractClientIP(req); got != "127.0.0.1" {
		t.Fatalf("expected 127.0.0.1, got %s", got)
	}

	req.Header.Set("X-Forwarded-For", "203.0.113.7, 198.51.100.2")
	if got := ExtractClientIP(req); got != "203.0.113.7" {
		t.Fatalf("expected forwarded ip, got %s", got)
	}
}
