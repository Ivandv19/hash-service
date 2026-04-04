// Package infra contains tests for shared infrastructure components.
package infra

import "testing"

func TestLoggerDoesNotPanicWithNilFields(t *testing.T) {
	logger := NewLogger()

	assertNoPanic := func(fn func()) {
		t.Helper()
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("logger panicked with nil fields: %v", recovered)
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
