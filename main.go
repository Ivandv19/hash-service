package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/alexedwards/argon2id"
)

// Rate limiter structure
type RateLimiter struct {
	visitors map[string]*Visitor
	mu       sync.RWMutex
	limit    int
	window   time.Duration
}

type Visitor struct {
	requests []time.Time
	mu       sync.Mutex
}

// CORS configuration
var allowedOrigins = map[string]bool{
	"https://sinx-pomodoro.mgdc.site": true,
	"http://localhost:4321":            true,
	"https://gestor.mgdc.site":         true,
	"http://localhost:3000":            true,
}

// Global rate limiter (30 requests per minute per IP)
var limiter = &RateLimiter{
	visitors: make(map[string]*Visitor),
	limit:    30,
	window:   time.Minute,
}

// Check if IP is allowed to make a request
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	v, exists := rl.visitors[ip]
	if !exists {
		v = &Visitor{requests: []time.Time{}}
		rl.visitors[ip] = v
	}
	rl.mu.Unlock()

	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()
	// Remove old requests outside the time window
	validRequests := []time.Time{}
	for _, t := range v.requests {
		if now.Sub(t) < rl.window {
			validRequests = append(validRequests, t)
		}
	}
	v.requests = validRequests

	// Check if limit is exceeded
	if len(v.requests) >= rl.limit {
		return false
	}

	// Add current request
	v.requests = append(v.requests, now)
	return true
}

// Cleanup old visitors periodically
func (rl *RateLimiter) Cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			rl.mu.Lock()
			for ip, v := range rl.visitors {
				v.mu.Lock()
				if len(v.requests) == 0 || time.Since(v.requests[len(v.requests)-1]) > rl.window {
					delete(rl.visitors, ip)
				}
				v.mu.Unlock()
			}
			rl.mu.Unlock()
		}
	}()
}

// CORS middleware
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Check if origin is allowed
		if allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, x-api-key")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// Rate limiting middleware
func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if !limiter.Allow(ip) {
			log.Printf("Rate limit exceeded for IP: %s", ip)
			http.Error(w, "Too many requests. Please try again later.", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// API key validation middleware
func authMiddleware(authKey string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		providedKey := r.Header.Get("x-api-key")
		
		// Constant-time comparison to prevent timing attacks
		if !secureCompare(providedKey, authKey) {
			log.Printf("Unauthorized request from IP: %s", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// Secure string comparison (constant-time)
func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	result := 0
	for i := 0; i < len(a); i++ {
		result |= int(a[i]) ^ int(b[i])
	}
	return result == 0
}

// Hash endpoint handler
func hashHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data map[string]string
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		log.Printf("Error decoding request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	password, ok := data["password"]
	if !ok || password == "" {
		http.Error(w, "Password is required", http.StatusBadRequest)
		return
	}

	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		log.Printf("Error creating hash: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"hash": hash})
	log.Printf("Hash created successfully for IP: %s", r.RemoteAddr)
}

// Verify endpoint handler
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data map[string]string
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		log.Printf("Error decoding request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	password, okPassword := data["password"]
	hash, okHash := data["hash"]
	if !okPassword || !okHash || password == "" || hash == "" {
		http.Error(w, "Password and hash are required", http.StatusBadRequest)
		return
	}

	match, err := argon2id.ComparePasswordAndHash(password, hash)
	if err != nil {
		log.Printf("Error verifying hash: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"match": match})
	log.Printf("Hash verification completed for IP: %s (match: %v)", r.RemoteAddr, match)
}

// Health check endpoint
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"service": "argon2id-hash-service",
	})
}

func main() {
	authKey := os.Getenv("AUTH_KEY")
	if authKey == "" {
		log.Fatal("AUTH_KEY environment variable is required")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "3010"
	}

	// Start rate limiter cleanup
	limiter.Cleanup()

	// Setup routes with middleware chain
	http.HandleFunc("/hash", corsMiddleware(rateLimitMiddleware(authMiddleware(authKey, hashHandler))))
	http.HandleFunc("/verify", corsMiddleware(rateLimitMiddleware(authMiddleware(authKey, verifyHandler))))
	http.HandleFunc("/health", healthHandler)

	log.Printf("🚀 Hash service starting on port %s", port)
	log.Printf("✅ Rate limiting: %d requests per minute per IP", limiter.limit)
	log.Printf("✅ CORS enabled for: sinx-pomodoro.mgdc.site, localhost:4321")
	
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
