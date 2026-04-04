// Paquete api: capa HTTP del servicio.
// Este archivo define los middlewares que se aplican a todas las peticiones:
// inyección de request ID, validación de CORS y autenticación + rate limiting.
package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/google/uuid"
)

// RequestIDMiddleware reutiliza el X-Request-ID del cliente o genera uno nuevo con UUID.
// Lo guarda en el contexto y en el header de respuesta para trazabilidad end-to-end.
func (s *Service) RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Si el cliente ya manda su propio X-Request-ID lo reutilizamos;
		// así podemos correlacionar logs entre servicios en una arquitectura mayor.
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			// No vino nada: generamos un UUID v4 único para esta petición.
			requestID = uuid.New().String()
		}

		// Resolvemos la IP real del cliente (considerando proxies con X-Forwarded-For).
		clientIP := ExtractClientIP(r)

		// Devolvemos el ID en la respuesta para que el cliente pueda usarlo al reportar errores.
		w.Header().Set("X-Request-ID", requestID)

		// Inyectamos el ID y la IP en el contexto para que handlers y middleware
		// downstream los lean sin necesidad de volver a parsear los headers.
		r = r.WithContext(context.WithValue(r.Context(), requestIDContextKey, requestID))
		r = r.WithContext(context.WithValue(r.Context(), clientIPContextKey, clientIP))

		// Log de acceso: quedará en stdout con todos los campos útiles para debugging.
		s.Logger.Info(requestID, "Petición recibida", map[string]interface{}{
			"method":     r.Method,
			"path":       r.URL.Path,
			"ip":         clientIP,
			"user_agent": r.UserAgent(),
			"origin":     r.Header.Get("Origin"),
		})

		// Pasamos el control al siguiente handler en la cadena.
		next.ServeHTTP(w, r)
	})
}

// CORSMiddleware solo agrega los headers Access-Control-* si el origen de la petición
// está en la lista blanca. Los preflight (OPTIONS) se responden aquí directamente.
func (s *Service) CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// El header Origin viene solo en peticiones cross-origin desde el navegador.
		origin := r.Header.Get("Origin")
		requestID := getRequestID(r.Context())

		s.Logger.Info(requestID, "Verificando CORS", map[string]interface{}{
			"origin": origin,
		})

		// Solo agregamos los headers CORS si el origen está en la lista blanca.
		// Si no está, el navegador bloqueará la respuesta por sí solo (no nosotros).
		if s.AllowedOrigins[origin] || s.AllowedOrigins["*"] {
			w.Header().Set("Access-Control-Allow-Origin", origin)

			// Caso especial: si se configuró "*" pero no hay Origin en el request
			// (p.ej. curl o Postman), ponemos el wildcard explícitamente.
			if s.AllowedOrigins["*"] && origin == "" {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}

			// Indicamos qué métodos y headers puede usar el navegador en sus peticiones.
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, x-api-key")

			// 86400 segundos = 24 horas de caché para el preflight, evita roundtrips extra.
			w.Header().Set("Access-Control-Max-Age", "86400")
		}

		// Las peticiones preflight (OPTIONS) las terminamos aquí mismo.
		// El navegador las manda primero para preguntar si puede hacer el POST real.
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// authAndRateLimitMiddleware es un middleware de Huma (no de net/http) que primero
// verifica que la IP no haya excedido su cuota y luego valida la API key.
// El orden importa: rechazar por rate limit antes de validar credenciales.
func (s *Service) authAndRateLimitMiddleware(authKey string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		// Huma maneja su propio contexto; necesitamos el *http.Request y
		// el http.ResponseWriter nativos para leer headers y escribir errores.
		req, res := humago.Unwrap(ctx)
		requestID := getRequestID(req.Context())
		ip := ExtractClientIP(req)

		// Paso 1: verificar cuota ANTES de validar la clave.
		// Si la IP ya superó el límite, ni siquiera miramos si la clave es válida.
		// Esto evita que un atacante haga fuerza bruta aunque tenga la clave.
		if !s.Limiter.Allow(ip) {
			s.Logger.Warn(requestID, "Límite de peticiones excedido", map[string]interface{}{
				"ip": ip,
			})
			sendJSONError(res, "Demasiadas peticiones. Intenta de nuevo más tarde.", http.StatusTooManyRequests)
			return
		}

		// Paso 2: leer la clave del header y compararla en tiempo constante.
		// SecureCompare evita que un atacante mida el tiempo de respuesta para
		// adivinar cuántos caracteres de la clave ya acertó (timing attack).
		providedKey := req.Header.Get("x-api-key")
		if !SecureCompare(providedKey, authKey) {
			s.Logger.Warn(requestID, "Petición no autorizada", map[string]interface{}{
				"ip": ip,
			})
			sendJSONError(res, "No autorizado", http.StatusUnauthorized)
			return
		}

		// Todo ok: pasamos el contexto original de Huma al siguiente middleware u handler.
		next(ctx)
	}
}
