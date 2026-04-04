// Paquete api: capa HTTP del servicio.
// Este archivo tiene los tres handlers principales (hash, verify, health) y
// RegisterOpenAPI que los registra en Huma con su metadata para el spec OpenAPI.
package api

import (
	"context"
	"net/http"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/danielgtaylor/huma/v2"
)

// HashOperation valida la contraseña (mínimo 6 caracteres), llama a Argon2id
// para generar el hash y devuelve el resultado si todo sale bien.
func (s *Service) HashOperation(ctx context.Context, input *HashInput) (*HashOutput, error) {
	// Sacamos el ID de trazabilidad y la IP del contexto para los logs.
	requestID := getRequestID(ctx)
	clientIP := getClientIP(ctx)

	// Validación 1: campo presente. Huma ya valida el JSON pero una contraseña
	// con solo espacios podría pasar ese check, así que la revisamos explícitamente.
	if input.Body.Password == "" {
		s.Logger.Warn(requestID, "Contraseña vacía", nil)
		return nil, huma.Error400BadRequest("La contraseña no puede estar vacía")
	}

	// Validación 2: longitud mínima para evitar hashes triviales.
	if len(input.Body.Password) < 6 {
		s.Logger.Warn(requestID, "Contraseña muy corta", map[string]interface{}{
			"length": len(input.Body.Password),
		})
		return nil, huma.Error400BadRequest("La contraseña debe tener al menos 6 caracteres")
	}

	// Medimos el tiempo que tarda Argon2id; es deliberadamente lento (~300ms)
	// y queremos registrarlo para detectar si algo va mal en el hardware.
	startTime := time.Now()
	hash, err := argon2id.CreateHash(input.Body.Password, argon2id.DefaultParams)
	duration := time.Since(startTime)
	if err != nil {
		s.Logger.Error(requestID, "Error creando hash", err, map[string]interface{}{
			"duration_ms": duration.Milliseconds(),
		})
		return nil, huma.Error500InternalServerError("Error interno al generar el hash")
	}

	// Construimos la respuesta con el hash generado y la devolvemos.
	// Huma la serializa a JSON automáticamente con el schema definido en HashOutput.
	resp := &HashOutput{}
	resp.Body.Data.Hash = hash

	s.Logger.Info(requestID, "Hash creado exitosamente", map[string]interface{}{
		"duration_ms": duration.Milliseconds(),
		"ip":          clientIP,
	})

	return resp, nil
}

// VerifyOperation valida que los campos no estén vacíos y que el hash tenga
// formato mínimo, luego usa Argon2id para comparar contraseña y hash.
func (s *Service) VerifyOperation(ctx context.Context, input *VerifyInput) (*VerifyOutput, error) {
	requestID := getRequestID(ctx)
	clientIP := getClientIP(ctx)

	// Validación 1: ambos campos deben venir; registramos cuál específicamente falta
	// para facilitar el debugging sin exponer datos sensibles en el log.
	if input.Body.Password == "" || input.Body.Hash == "" {
		s.Logger.Warn(requestID, "Campos vacíos", map[string]interface{}{
			"password_empty": input.Body.Password == "",
			"hash_empty":     input.Body.Hash == "",
		})
		return nil, huma.Error400BadRequest("La contraseña y el hash no pueden estar vacíos")
	}

	// Validación 2: sanity check mínimo del formato del hash antes de pasarlo a Argon2id.
	// Un hash Argon2id real tiene ~100 caracteres; menos de 10 implica que el cliente
	// mandó cualquier cosa y evitamos un panic interno en la librería.
	if len(input.Body.Hash) < 10 {
		s.Logger.Warn(requestID, "Formato de hash inválido (muy corto)", map[string]interface{}{
			"hash_length": len(input.Body.Hash),
		})
		return nil, huma.Error400BadRequest("Formato de hash inválido")
	}

	// Comparamos la contraseña con el hash en tiempo constante usando Argon2id.
	// La función internamente extrae los parámetros (memory, tiempo, hilos) del
	// propio hash para rehashear y comparar byte a byte.
	startTime := time.Now()
	match, err := argon2id.ComparePasswordAndHash(input.Body.Password, input.Body.Hash)
	duration := time.Since(startTime)
	if err != nil {
		s.Logger.Error(requestID, "Error verificando hash", err, map[string]interface{}{
			"duration_ms": duration.Milliseconds(),
		})
		return nil, huma.Error500InternalServerError("Error interno al verificar el hash")
	}

	// Construimos la respuesta; match=true significa que la contraseña es correcta.
	resp := &VerifyOutput{}
	resp.Body.Data.Match = match

	s.Logger.Info(requestID, "Verificación completada", map[string]interface{}{
		"duration_ms": duration.Milliseconds(),
		"ip":          clientIP,
		"match":       match,
	})

	return resp, nil
}

// HealthOperation responde con el estado del servicio, útil para liveness probes
// en Docker/K8s o para verificar que el deploy funcionó.
func (s *Service) HealthOperation(ctx context.Context, input *struct{}) (*HealthOutput, error) {
	requestID := getRequestID(ctx)

	// Llenamos la respuesta con datos estáticos del servicio.
	// El timestamp en RFC3339 sirve para detectar si el contenedor tiene el reloj correcto.
	resp := &HealthOutput{}
	resp.Body.Status = "saludable"
	resp.Body.Service = "argon2id-hash-service"
	resp.Body.Timestamp = time.Now().Format(time.RFC3339)
	resp.Body.Version = "1.1.0"

	s.Logger.Info(requestID, "Health check", map[string]interface{}{
		"status": "saludable",
	})

	return resp, nil
}

// RegisterOpenAPI registra los tres endpoints en Huma con su operationId, tags,
// descripciones y errores posibles para generar el spec OpenAPI completo.
func (s *Service) RegisterOpenAPI(api huma.API, authKey string) {
	// Preparamos el slice de middlewares de Huma que incluye auth+rate limit.
	// Solo /hash y /verify lo necesitan; /health es público.
	secured := huma.Middlewares{s.authAndRateLimitMiddleware(authKey)}

	huma.Register(api, huma.Operation{
		OperationID: "healthCheck",
		Method:      http.MethodGet,
		Path:        "/health",
		Tags:        []string{"Health"},
		Summary:     "Verifica el estado del servicio",
		Description: "Endpoint simple para comprobar que el microservicio esta arriba y respondiendo.",
		Errors:      []int{500},
	}, s.HealthOperation)

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
	}, s.HashOperation)

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
	}, s.VerifyOperation)
}
