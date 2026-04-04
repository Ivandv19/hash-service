// Paquete api: capa HTTP del servicio.
// Este archivo tiene funciones auxiliares: respuestas JSON, lectura de contexto
// y validaciones de seguridad reutilizables por handlers y middleware.
package api

import (
	"context"
	"encoding/json"
	"mime"
	"net"
	"net/http"
	"strings"
)

// sendJSONError escribe una respuesta de error en formato JSON estándar del servicio.
func sendJSONError(w http.ResponseWriter, message string, code int) {
	// El Content-Type hay que setearlo antes de WriteHeader; después ya no se puede.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	// Usamos http.StatusText para el campo "error" (ej: "Not Found") y el mensaje
	// personalizado para "message", así el cliente tiene contexto en ambos campos.
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:   http.StatusText(code),
		Message: message,
		Code:    code,
	})
}

// getRequestID extrae el ID de trazabilidad que el middleware inyectó en el contexto.
// Si no existe (por ejemplo en tests), regresa "unknown" para no romper los logs.
func getRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(requestIDContextKey).(string); ok && requestID != "" {
		return requestID
	}
	return "unknown"
}

// getClientIP extrae la IP del cliente que el middleware guardó en el contexto.
func getClientIP(ctx context.Context) string {
	if ip, ok := ctx.Value(clientIPContextKey).(string); ok && ip != "" {
		return ip
	}
	return "unknown"
}

// SecureCompare compara dos strings en tiempo constante para evitar timing attacks.
// Usa XOR bit a bit: si algún byte difiere, result queda distinto de cero.
func SecureCompare(a, b string) bool {
	// Si los largos difieren podemos salir rápido; no hay riesgo de timing
	// attack en este check porque el largo de la clave configurada no es secreto.
	if len(a) != len(b) {
		return false
	}
	result := 0
	// XOR entre cada byte: resultado es 0 solo si todos los bytes son iguales.
	// Usamos OR acumulativo para que el loop siempre corra el mismo número de
	// iteraciones sin importar en qué posición difieren las claves.
	for index := 0; index < len(a); index++ {
		result |= int(a[index]) ^ int(b[index])
	}
	return result == 0
}

// IsJSONContentType valida que el Content-Type sea application/json,
// ignorando parámetros adicionales como charset=utf-8.
func IsJSONContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return strings.EqualFold(mediaType, "application/json")
}

// ExtractClientIP obtiene la IP real del cliente considerando que puede venir
// detrás de un proxy o load balancer que agrega X-Forwarded-For.
func ExtractClientIP(r *http.Request) string {
	// X-Forwarded-For puede contener una cadena de IPs separadas por coma:
	// "clientIP, proxy1, proxy2". Nos quedamos con la primera (el origen real).
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}

	// Sin proxy: RemoteAddr tiene formato "host:puerto", separamos solo el host.
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return ip
	}

	// Fallback: si SplitHostPort falla (formato raro), devolvemos RemoteAddr tal cual.
	return r.RemoteAddr
}
