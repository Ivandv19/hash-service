package main

import (
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
	// Eliminar peticiones antiguas fuera de la ventana de tiempo
	validRequests := []time.Time{}
	for _, t := range v.requests {
		if now.Sub(t) < rl.window {
			validRequests = append(validRequests, t)
		}
	}
	v.requests = validRequests

	// Verificar si se excedió el límite
	if len(v.requests) >= rl.limit {
		return false
	}

	// Agregar petición actual
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
func requestIDMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Generar o reutilizar ID de petición
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		clientIP := extractClientIP(r)
		
		// Añadir a los headers de respuesta
		w.Header().Set("X-Request-ID", requestID)
		
		// Registrar petición entrante
		appLogger.Info(requestID, "Petición recibida", map[string]interface{}{
			"method":     r.Method,
			"path":       r.URL.Path,
			"ip":         clientIP,
			"user_agent": r.UserAgent(),
			"origin":     r.Header.Get("Origin"),
		})
		
		next(w, r)
	}
}

// corsMiddleware - Maneja CORS (Cross-Origin Resource Sharing)
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		requestID := r.Header.Get("X-Request-ID")
		
		appLogger.Info(requestID, "Verificando CORS", map[string]interface{}{
			"origin": origin,
		})

		// Verificar si el origen está permitido
		if allowedOrigins[origin] || allowedOrigins["*"] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			if allowedOrigins["*"] && origin == "" {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, x-api-key")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}

		// Manejar peticiones preflight (OPTIONS)
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}


// rateLimitMiddleware - Controla el límite de peticiones por IP
func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		ip := extractClientIP(r)
		
		if !limiter.Allow(ip) {
			appLogger.Warn(requestID, "Límite de peticiones excedido", map[string]interface{}{
				"ip": ip,
			})
			sendJSONError(w, "Demasiadas peticiones. Intenta de nuevo más tarde.", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// authMiddleware - Valida la API key
func authMiddleware(authKey string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		providedKey := r.Header.Get("x-api-key")
		ip := extractClientIP(r)
		
		// Comparación en tiempo constante
		if !secureCompare(providedKey, authKey) {
			appLogger.Warn(requestID, "Petición no autorizada", map[string]interface{}{
				"ip": ip,
			})
			sendJSONError(w, "No autorizado", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ==================== HANDLERS (MANEJADORES) ====================

// hashHandler - Procesa peticiones de hashing de contraseñas
func hashHandler(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	
	// Validar método HTTP
	if r.Method != "POST" {
		appLogger.Warn(requestID, "Método no permitido", map[string]interface{}{
			"method_used": r.Method,
		})
		sendJSONError(w, "Método no permitido. Usa POST", http.StatusMethodNotAllowed)
		return
	}

	// Validar Content-Type
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		appLogger.Warn(requestID, "Content-Type incorrecto", map[string]interface{}{
			"content_type": r.Header.Get("Content-Type"),
		})
		sendJSONError(w, "Content-Type debe ser application/json", http.StatusBadRequest)
		return
	}

	// Decodificar JSON
	var data map[string]string
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		appLogger.Error(requestID, "Error decodificando JSON", err, map[string]interface{}{
			"body_size": r.ContentLength,
		})
		sendJSONError(w, "JSON inválido. Verifica el formato", http.StatusBadRequest)
		return
	}

	// Validar campo password
	password, ok := data["password"]
	if !ok {
		appLogger.Warn(requestID, "Campo password faltante", map[string]interface{}{
			"fields_present": getKeys(data),
		})
		sendJSONError(w, "Campo 'password' es requerido", http.StatusBadRequest)
		return
	}

	if password == "" {
		appLogger.Warn(requestID, "Contraseña vacía", nil)
		sendJSONError(w, "La contraseña no puede estar vacía", http.StatusBadRequest)
		return
	}

	if len(password) < 6 {
		appLogger.Warn(requestID, "Contraseña muy corta", map[string]interface{}{
			"length": len(password),
		})
		sendJSONError(w, "La contraseña debe tener al menos 6 caracteres", http.StatusBadRequest)
		return
	}

	startTime := time.Now()
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	duration := time.Since(startTime)
	if err != nil {
		appLogger.Error(requestID, "Error creando hash", err, map[string]interface{}{
			"duration_ms": duration.Milliseconds(),
		})
		sendJSONError(w, "Error interno al generar el hash", http.StatusInternalServerError)
		return
	}

	appLogger.Info(requestID, "Hash creado exitosamente", map[string]interface{}{
		"duration_ms": duration.Milliseconds(),
		"ip":          extractClientIP(r),
	})

	sendJSONSuccess(w, map[string]string{"hash": hash}, http.StatusOK)
}

// verifyHandler - Procesa peticiones de verificación de contraseñas
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	
	// Validar método HTTP
	if r.Method != "POST" {
		appLogger.Warn(requestID, "Método no permitido", map[string]interface{}{
			"method_used": r.Method,
		})
		sendJSONError(w, "Método no permitido. Usa POST", http.StatusMethodNotAllowed)
		return
	}

	// Validar Content-Type
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		appLogger.Warn(requestID, "Content-Type incorrecto", map[string]interface{}{
			"content_type": r.Header.Get("Content-Type"),
		})
		sendJSONError(w, "Content-Type debe ser application/json", http.StatusBadRequest)
		return
	}

	// Decodificar JSON
	var data map[string]string
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		appLogger.Error(requestID, "Error decodificando JSON", err, map[string]interface{}{
			"body_size": r.ContentLength,
		})
		sendJSONError(w, "JSON inválido. Verifica el formato", http.StatusBadRequest)
		return
	}

	// Validar campos requeridos
	password, okPassword := data["password"]
	hash, okHash := data["hash"]

	if !okPassword || !okHash {
		appLogger.Warn(requestID, "Campos requeridos faltantes", map[string]interface{}{
			"fields_present": getKeys(data),
			"has_password":   okPassword,
			"has_hash":       okHash,
		})
		sendJSONError(w, "Campos 'password' y 'hash' son requeridos", http.StatusBadRequest)
		return
	}

	if password == "" || hash == "" {
		appLogger.Warn(requestID, "Campos vacíos", map[string]interface{}{
			"password_empty": password == "",
			"hash_empty":     hash == "",
		})
		sendJSONError(w, "La contraseña y el hash no pueden estar vacíos", http.StatusBadRequest)
		return
	}

	if len(hash) < 10 {
		appLogger.Warn(requestID, "Formato de hash inválido (muy corto)", map[string]interface{}{
			"hash_length": len(hash),
		})
		sendJSONError(w, "Formato de hash inválido", http.StatusBadRequest)
		return
	}

	startTime := time.Now()
	match, err := argon2id.ComparePasswordAndHash(password, hash)
	duration := time.Since(startTime)
	if err != nil {
		appLogger.Error(requestID, "Error verificando hash", err, map[string]interface{}{
			"duration_ms": duration.Milliseconds(),
		})
		sendJSONError(w, "Error interno al verificar el hash", http.StatusInternalServerError)
		return
	}

	appLogger.Info(requestID, "Verificación completada", map[string]interface{}{
		"duration_ms": duration.Milliseconds(),
		"ip":          extractClientIP(r),
		"match":       match,
	})

	sendJSONSuccess(w, map[string]bool{"match": match}, http.StatusOK)
}

// healthHandler - Endpoint de verificación de salud del servicio
func healthHandler(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "saludable",
		"service":   "argon2id-hash-service",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "1.0.0",
	})

	appLogger.Info(requestID, "Health check", map[string]interface{}{
		"status": "saludable",
	})
}

// ==================== FUNCIÓN PRINCIPAL ====================

func main() {
	// Obtener y validar variables de entorno
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

	// Iniciar limpieza del rate limiter
	limiter.Cleanup()

	// Configurar rutas con todos los middlewares
	http.HandleFunc("/hash", requestIDMiddleware(
		corsMiddleware(
			rateLimitMiddleware(
				authMiddleware(authKey, hashHandler)))))

	http.HandleFunc("/verify", requestIDMiddleware(
		corsMiddleware(
			rateLimitMiddleware(
				authMiddleware(authKey, verifyHandler)))))

	http.HandleFunc("/health", requestIDMiddleware(healthHandler))

	// Registrar inicio del servicio
	appLogger.Info("system", "Servicio iniciado", map[string]interface{}{
		"port":          port,
		"rate_limit":    limiter.limit,
		"rate_window":   limiter.window.String(),
		"allowed_cors":  len(allowedOrigins),
	})

	log.Printf("🚀 Servicio de hash iniciado en puerto %s", port)
	log.Printf("✅ Límite de peticiones: %d por %v", limiter.limit, limiter.window)
	log.Printf("✅ CORS habilitado para orígenes configurados")
	
	// Iniciar servidor (HTTP porque Cloudflare Tunnel maneja HTTPS)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		appLogger.Error("system", "Error fatal del servidor", err, nil)
		log.Fatal(err)
	}
}