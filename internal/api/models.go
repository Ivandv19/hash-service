// Paquete api: capa HTTP del servicio.
// Este archivo define todos los tipos de entrada/salida que usan los handlers
// y que Huma convierte automáticamente en esquemas OpenAPI.
package api

// ErrorResponse es la forma estándar de todos los errores del servicio.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// SuccessResponse envuelve datos de éxito cuando se usa la capa HTTP manual.
type SuccessResponse struct {
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}

// contextKey es un tipo privado para evitar colisiones de llaves en el contexto HTTP.
type contextKey string

// Llaves usadas para guardar y leer request ID e IP del cliente desde el contexto.
const (
	requestIDContextKey contextKey = "request_id"
	clientIPContextKey  contextKey = "client_ip"
)

// HashRequestBody es el cuerpo JSON que espera el endpoint POST /hash.
type HashRequestBody struct {
	Password string `json:"password" doc:"Contrasena en texto plano" example:"mi_password_seguro" minLength:"6"`
}

// HashInput combina el header x-api-key y el body para que Huma los valide juntos.
type HashInput struct {
	APIKey string          `header:"x-api-key" doc:"API key del servicio"`
	Body   HashRequestBody `body:""`
}

// HashData contiene el hash Argon2id resultante que se devuelve al cliente.
type HashData struct {
	Hash string `json:"hash" example:"$argon2id$v=19$m=65536,t=1,p=24$..."`
}

// HashResponseBody envuelve HashData para que Huma genere el schema con nombre
// único y no colisione con otros tipos anistados en el spec de OpenAPI.
type HashResponseBody struct {
	Data HashData `json:"data" nameHint:"HashData"`
}

// HashOutput es lo que retorna HashOperation; Huma lo serializa como respuesta 200.
type HashOutput struct {
	Body HashResponseBody `json:"body" nameHint:"HashResponse"`
}

// VerifyRequestBody es el cuerpo JSON que espera el endpoint POST /verify.
type VerifyRequestBody struct {
	Password string `json:"password" doc:"Contrasena en texto plano" example:"mi_password_seguro"`
	Hash     string `json:"hash" doc:"Hash Argon2id generado previamente" example:"$argon2id$v=19$m=65536,t=1,p=24$..."`
}

// VerifyInput combina el header x-api-key y el body para el endpoint /verify.
type VerifyInput struct {
	APIKey string            `header:"x-api-key" doc:"API key del servicio"`
	Body   VerifyRequestBody `body:""`
}

// VerifyData contiene el resultado booleano: true si la contraseña coincide con el hash.
type VerifyData struct {
	Match bool `json:"match" example:"true"`
}

// VerifyResponseBody envuelve VerifyData con nameHint para evitar colisión de schemas.
type VerifyResponseBody struct {
	Data VerifyData `json:"data" nameHint:"VerifyData"`
}

// VerifyOutput is the full OpenAPI response type for /verify.
type VerifyOutput struct {
	Body VerifyResponseBody `json:"body" nameHint:"VerifyResponse"`
}

// HealthOutput is the health check response shape.
type HealthOutput struct {
	Body struct {
		Status    string `json:"status" example:"saludable"`
		Service   string `json:"service" example:"argon2id-hash-service"`
		Timestamp string `json:"timestamp" example:"2026-04-04T19:00:00Z"`
		Version   string `json:"version" example:"1.1.0"`
	} `json:"body" nameHint:"HealthResponse"`
}
