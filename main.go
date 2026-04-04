package main

import (
	"context"
	"encoding/json"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/google/uuid"
)

// ==================== ESTRUCTURAS DE DATOS ====================

// RateLimiter - Controla el límite de peticiones por IP
type RateLimiter struct {
	visitors map[string]*Visitor
	mu       sync.RWMutex
	limit    int
	window   time.Duration
}

// Visitor - Almacena las peticiones de un visitante
type Visitor struct {
	requests []time.Time
	mu       sync.Mutex
}

// ErrorResponse - Estructura para respuestas de error
type ErrorResponse struct {
	Error   string `json:"error"`   // Tipo de error (ej: "Bad Request")
	Message string `json:"message"` // Mensaje descriptivo
	Code    int    `json:"code"`    // Código HTTP
}

// SuccessResponse - Estructura para respuestas exitosas
type SuccessResponse struct {
	Data    interface{} `json:"data,omitempty"`    // Datos de respuesta
	Message string      `json:"message,omitempty"` // Mensaje opcional
}

type contextKey string

const (
	requestIDContextKey contextKey = "request_id"
	clientIPContextKey  contextKey = "client_ip"
)

type HashRequestBody struct {
	Password string `json:"password" doc:"Contrasena en texto plano" example:"mi_password_seguro" minLength:"6"`
}

type HashInput struct {
	APIKey string          `header:"x-api-key" doc:"API key del servicio"`
	Body   HashRequestBody `body:""`
}

type HashData struct {
	Hash string `json:"hash" example:"$argon2id$v=19$m=65536,t=1,p=24$..."`
}

type HashResponseBody struct {
	Data HashData `json:"data" nameHint:"HashData"`
}

type HashOutput struct {
	Body HashResponseBody `json:"body" nameHint:"HashResponse"`
}

type VerifyRequestBody struct {
	Password string `json:"password" doc:"Contrasena en texto plano" example:"mi_password_seguro"`
	Hash     string `json:"hash" doc:"Hash Argon2id generado previamente" example:"$argon2id$v=19$m=65536,t=1,p=24$..."`
}

type VerifyInput struct {
	APIKey string            `header:"x-api-key" doc:"API key del servicio"`
	Body   VerifyRequestBody `body:""`
}

type VerifyData struct {
	Match bool `json:"match" example:"true"`
}

type VerifyResponseBody struct {
	Data VerifyData `json:"data" nameHint:"VerifyData"`
}

type VerifyOutput struct {
	Body VerifyResponseBody `json:"body" nameHint:"VerifyResponse"`
}

type HealthOutput struct {
	Body struct {
		Status    string `json:"status" example:"saludable"`
		Service   string `json:"service" example:"argon2id-hash-service"`
		Timestamp string `json:"timestamp" example:"2026-04-04T19:00:00Z"`
		Version   string `json:"version" example:"1.1.0"`
	} `json:"body" nameHint:"HealthResponse"`
}

// Logger personalizado con formato y colores
type Logger struct {
	*log.Logger
}

// Configuración CORS
var allowedOrigins = map[string]bool{
	"https://sinx-pomodoro.mgdc.site": true,
	"https://gestor.mgdc.site":         true,
}

// Rate limiter global (30 peticiones por minuto por IP)
var limiter = &RateLimiter{
	visitors: make(map[string]*Visitor),
	limit:    30,
	window:   time.Minute,
}

// Logger global
var appLogger = NewLogger()

// ==================== FUNCIONES DEL LOGGER ====================

// NewLogger - Crea una nueva instancia del logger
func NewLogger() *Logger {
	return &Logger{
		Logger: log.New(os.Stdout, "", 0),
	}
}

// Info - Registra un mensaje informativo
func (l *Logger) Info(requestID string, msg string, fields map[string]interface{}) {
	if fields == nil {
		fields = map[string]interface{}{}
	}
	fields["timestamp"] = time.Now().Format(time.RFC3339)
	fields["level"] = "INFO"
	fields["request_id"] = requestID

	jsonFields, _ := json.Marshal(fields)
	l.Printf("📗 %s | %s", msg, jsonFields)
}

// Error - Registra un mensaje de error
func (l *Logger) Error(requestID string, msg string, err error, fields map[string]interface{}) {
	if fields == nil {
		fields = map[string]interface{}{}
	}
	fields["timestamp"] = time.Now().Format(time.RFC3339)
	fields["level"] = "ERROR"
	fields["request_id"] = requestID
	if err != nil {
		fields["error"] = err.Error()
	}

	jsonFields, _ := json.Marshal(fields)
	l.Printf("📕 %s | %s", msg, jsonFields)
}

// Warn - Registra un mensaje de advertencia
func (l *Logger) Warn(requestID string, msg string, fields map[string]interface{}) {
	if fields == nil {
		fields = map[string]interface{}{}
	}
	fields["timestamp"] = time.Now().Format(time.RFC3339)
	fields["level"] = "WARN"
	fields["request_id"] = requestID

	jsonFields, _ := json.Marshal(fields)
	l.Printf("📙 %s | %s", msg, jsonFields)
}

// ==================== FUNCIONES DEL RATE LIMITER ====================

// Allow - Verifica si una IP puede hacer una petición
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
	validRequests := []time.Time{}
	for _, t := range v.requests {
		if now.Sub(t) < rl.window {
			validRequests = append(validRequests, t)
		}
	}
	v.requests = validRequests

	if len(v.requests) >= rl.limit {
		return false
	}

	v.requests = append(v.requests, now)
	return true
}

// Cleanup - Limpia visitantes antiguos periódicamente
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

// ==================== FUNCIONES HELPER ====================

// sendJSONError - Envía una respuesta de error en formato JSON
func sendJSONError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:   http.StatusText(code),
		Message: message,
		Code:    code,
	})
}

// sendJSONSuccess - Envía una respuesta exitosa en formato JSON
func sendJSONSuccess(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(SuccessResponse{
		Data: data,
	})
}

func getRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(requestIDContextKey).(string); ok && requestID != "" {
		return requestID
	}
	return "unknown"
}

func getClientIP(ctx context.Context) string {
	if ip, ok := ctx.Value(clientIPContextKey).(string); ok && ip != "" {
		return ip
	}
	return "unknown"
}

// secureCompare - Comparación en tiempo constante para prevenir timing attacks
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

// getKeys - Obtiene las llaves de un map (para logging)
func getKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// isJSONContentType valida application/json con o sin parametros (charset, etc.)
func isJSONContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return strings.EqualFold(mediaType, "application/json")
}

// extractClientIP obtiene la IP real del cliente considerando proxies.
func extractClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return ip
	}

	return r.RemoteAddr
}

// ==================== MIDDLEWARES ====================

// requestIDMiddleware - Añade un ID único a cada petición
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		clientIP := extractClientIP(r)

		w.Header().Set("X-Request-ID", requestID)
		r = r.WithContext(context.WithValue(r.Context(), requestIDContextKey, requestID))
		r = r.WithContext(context.WithValue(r.Context(), clientIPContextKey, clientIP))

		appLogger.Info(requestID, "Petición recibida", map[string]interface{}{
			"method":     r.Method,
			"path":       r.URL.Path,
			"ip":         clientIP,
			"user_agent": r.UserAgent(),
			"origin":     r.Header.Get("Origin"),
		})

		next.ServeHTTP(w, r)
	})
}

// corsMiddleware - Maneja CORS (Cross-Origin Resource Sharing)
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		requestID := getRequestID(r.Context())

		appLogger.Info(requestID, "Verificando CORS", map[string]interface{}{
			"origin": origin,
		})

		if allowedOrigins[origin] || allowedOrigins["*"] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			if allowedOrigins["*"] && origin == "" {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, x-api-key")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func authAndRateLimitMiddleware(authKey string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		req, res := humago.Unwrap(ctx)
		requestID := getRequestID(req.Context())
		ip := extractClientIP(req)

		if !limiter.Allow(ip) {
			appLogger.Warn(requestID, "Límite de peticiones excedido", map[string]interface{}{
				"ip": ip,
			})
			sendJSONError(res, "Demasiadas peticiones. Intenta de nuevo más tarde.", http.StatusTooManyRequests)
			return
		}

		providedKey := req.Header.Get("x-api-key")
		if !secureCompare(providedKey, authKey) {
			appLogger.Warn(requestID, "Petición no autorizada", map[string]interface{}{
				"ip": ip,
			})
			sendJSONError(res, "No autorizado", http.StatusUnauthorized)
			return
		}

		next(ctx)
	}
}

// ==================== HANDLERS (MANEJADORES) ====================

func hashOperation(ctx context.Context, input *HashInput) (*HashOutput, error) {
	requestID := getRequestID(ctx)
	clientIP := getClientIP(ctx)

	if input.Body.Password == "" {
		appLogger.Warn(requestID, "Contraseña vacía", nil)
		return nil, huma.Error400BadRequest("La contraseña no puede estar vacía")
	}

	if len(input.Body.Password) < 6 {
		appLogger.Warn(requestID, "Contraseña muy corta", map[string]interface{}{
			"length": len(input.Body.Password),
		})
		return nil, huma.Error400BadRequest("La contraseña debe tener al menos 6 caracteres")
	}

	startTime := time.Now()
	hash, err := argon2id.CreateHash(input.Body.Password, argon2id.DefaultParams)
	duration := time.Since(startTime)
	if err != nil {
		appLogger.Error(requestID, "Error creando hash", err, map[string]interface{}{
			"duration_ms": duration.Milliseconds(),
		})
		return nil, huma.Error500InternalServerError("Error interno al generar el hash")
	}

	appLogger.Info(requestID, "Hash creado exitosamente", map[string]interface{}{
		"duration_ms": duration.Milliseconds(),
		"ip":          clientIP,
	})

	resp := &HashOutput{}
	resp.Body.Data.Hash = hash
	return resp, nil
}

func verifyOperation(ctx context.Context, input *VerifyInput) (*VerifyOutput, error) {
	requestID := getRequestID(ctx)
	clientIP := getClientIP(ctx)

	if input.Body.Password == "" || input.Body.Hash == "" {
		appLogger.Warn(requestID, "Campos vacíos", map[string]interface{}{
			"password_empty": input.Body.Password == "",
			"hash_empty":     input.Body.Hash == "",
		})
		return nil, huma.Error400BadRequest("La contraseña y el hash no pueden estar vacíos")
	}

	if len(input.Body.Hash) < 10 {
		appLogger.Warn(requestID, "Formato de hash inválido (muy corto)", map[string]interface{}{
			"hash_length": len(input.Body.Hash),
		})
		return nil, huma.Error400BadRequest("Formato de hash inválido")
	}

	startTime := time.Now()
	match, err := argon2id.ComparePasswordAndHash(input.Body.Password, input.Body.Hash)
	duration := time.Since(startTime)
	if err != nil {
		appLogger.Error(requestID, "Error verificando hash", err, map[string]interface{}{
			"duration_ms": duration.Milliseconds(),
		})
		return nil, huma.Error500InternalServerError("Error interno al verificar el hash")
	}

	appLogger.Info(requestID, "Verificación completada", map[string]interface{}{
		"duration_ms": duration.Milliseconds(),
		"ip":          clientIP,
		"match":       match,
	})

	resp := &VerifyOutput{}
	resp.Body.Data.Match = match
	return resp, nil
}

func healthOperation(ctx context.Context, input *struct{}) (*HealthOutput, error) {
	requestID := getRequestID(ctx)
	resp := &HealthOutput{}
	resp.Body.Status = "saludable"
	resp.Body.Service = "argon2id-hash-service"
	resp.Body.Timestamp = time.Now().Format(time.RFC3339)
	resp.Body.Version = "1.1.0"

	appLogger.Info(requestID, "Health check", map[string]interface{}{
		"status": "saludable",
	})

	return resp, nil
}

func registerOpenAPI(api huma.API, authKey string) {
	secured := huma.Middlewares{authAndRateLimitMiddleware(authKey)}

	huma.Register(api, huma.Operation{
		OperationID: "healthCheck",
		Method:      http.MethodGet,
		Path:        "/health",
		Tags:        []string{"Health"},
		Summary:     "Verifica el estado del servicio",
		Description: "Endpoint simple para comprobar que el microservicio esta arriba y respondiendo.",
		Errors:      []int{500},
	}, healthOperation)

	huma.Register(api, huma.Operation{
		OperationID: "createHash",
		Method:      http.MethodPost,
		Path:        "/hash",
		Tags:        []string{"Hashing"},
		Summary:     "Genera un hash Argon2id",
		Description: "Recibe una contrasena en texto plano y devuelve su hash Argon2id.",
		Errors:      []int{400, 401, 415, 429, 500},
		Security:    []map[string][]string{{"apiKey": {}}},
		Middlewares: secured,
	}, hashOperation)

	huma.Register(api, huma.Operation{
		OperationID: "verifyHash",
		Method:      http.MethodPost,
		Path:        "/verify",
		Tags:        []string{"Hashing"},
		Summary:     "Verifica una contrasena contra un hash",
		Description: "Compara una contrasena en texto plano contra un hash Argon2id existente.",
		Errors:      []int{400, 401, 415, 429, 500},
		Security:    []map[string][]string{{"apiKey": {}}},
		Middlewares: secured,
	}, verifyOperation)
}

// ==================== FUNCIÓN PRINCIPAL ====================

func main() {
	authKey := os.Getenv("AUTH_KEY")
	if authKey == "" {
		appLogger.Error("system", "AUTH_KEY no configurada", nil, map[string]interface{}{
			"fatal": true,
		})
		log.Fatal("AUTH_KEY environment variable is required")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "3010"
	}

	limiter.Cleanup()

	config := huma.DefaultConfig("Hash Service API", "1.1.0")
	config.OpenAPIPath = "/openapi"
	config.DocsPath = "/docs"
	config.DocsRenderer = huma.DocsRendererScalar
	config.SchemasPath = "/schemas"
	config.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"apiKey": {
			Type:        "apiKey",
			Name:        "x-api-key",
			In:          "header",
			Description: "API key requerida para los endpoints protegidos del servicio.",
		},
	}

	mux := http.NewServeMux()
	api := humago.New(mux, config)
	registerOpenAPI(api, authKey)

	handler := requestIDMiddleware(corsMiddleware(mux))

	appLogger.Info("system", "Servicio iniciado", map[string]interface{}{
		"port":         port,
		"rate_limit":   limiter.limit,
		"rate_window":  limiter.window.String(),
		"allowed_cors": len(allowedOrigins),
		"docs":         "/docs",
		"openapi":      "/openapi.json",
	})

	log.Printf("🚀 Servicio de hash iniciado en puerto %s", port)
	log.Printf("✅ Límite de peticiones: %d por %v", limiter.limit, limiter.window)
	log.Printf("✅ CORS habilitado para orígenes configurados")
	log.Printf("📘 Docs disponibles en /docs")

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		appLogger.Error("system", "Error fatal del servidor", err, nil)
		log.Fatal(err)
	}
}
