package main

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestSecureCompare(t *testing.T) {
	if !secureCompare("abc123", "abc123") {
		t.Fatal("expected secureCompare to return true for equal strings")
	}
	if secureCompare("abc123", "abc124") {
		t.Fatal("expected secureCompare to return false for different strings")
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
			if got := isJSONContentType(tc.input); got != tc.expects {
				t.Fatalf("expected %v, got %v", tc.expects, got)
			}
		})
	}
}

func TestExtractClientIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	if got := extractClientIP(req); got != "127.0.0.1" {
		t.Fatalf("expected 127.0.0.1, got %s", got)
	}

	req.Header.Set("X-Forwarded-For", "203.0.113.7, 198.51.100.2")
	if got := extractClientIP(req); got != "203.0.113.7" {
		t.Fatalf("expected forwarded ip, got %s", got)
	}
}

func TestRateLimiterAllow(t *testing.T) {
	rl := &RateLimiter{
		visitors: make(map[string]*Visitor),
		limit:    2,
		window:   50 * time.Millisecond,
	}

	ip := "10.0.0.1"
	if !rl.Allow(ip) {
		t.Fatal("first request should be allowed")
	}
	if !rl.Allow(ip) {
		t.Fatal("second request should be allowed")
	}
	if rl.Allow(ip) {
		t.Fatal("third request should be blocked")
	}

	time.Sleep(60 * time.Millisecond)
	if !rl.Allow(ip) {
		t.Fatal("request should be allowed after window reset")
	}
}

func TestLoggerDoesNotPanicWithNilFields(t *testing.T) {
	logger := NewLogger()

	assertNoPanic := func(fn func()) {
		t.Helper()
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("logger panicked with nil fields: %v", r)
			}
		}()
		fn()
	}

	assertNoPanic(func() {
		logger.Info("req-1", "info", nil)
	})
	assertNoPanic(func() {
		logger.Warn("req-1", "warn", nil)
	})
	assertNoPanic(func() {
		logger.Error("req-1", "error", nil, nil)
	})
}
