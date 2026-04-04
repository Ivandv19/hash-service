// Package infra contains tests for rate limiting behavior.
package infra

import (
	"testing"
	"time"
)

func TestRateLimiterAllow(t *testing.T) {
	limiter := NewRateLimiter(2, 50*time.Millisecond)
	ip := "10.0.0.1"

	if !limiter.Allow(ip) {
		t.Fatal("first request should be allowed")
	}
	if !limiter.Allow(ip) {
		t.Fatal("second request should be allowed")
	}
	if limiter.Allow(ip) {
		t.Fatal("third request should be blocked")
	}

	time.Sleep(60 * time.Millisecond)
	if !limiter.Allow(ip) {
		t.Fatal("request should be allowed after window reset")
	}
}
