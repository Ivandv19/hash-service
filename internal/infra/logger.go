// Paquete infra: primitivas de bajo nivel reutilizables por toda la app.
// Este archivo define el logger estructurado que emite JSON a stdout.
package infra

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

// Logger envuelve el logger estándar de Go para agregar nivel y campos JSON.
type Logger struct {
	*log.Logger
}

// NewLogger crea el logger compartido que escribirá a stdout sin prefijos.
func NewLogger() *Logger {
	return &Logger{
		Logger: log.New(os.Stdout, "", 0),
	}
}

// Info registra un evento informativo. Agrega timestamp, nivel y request_id
// al mapa de campos antes de serializarlo como JSON en una sola línea.
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

// Error registra un fallo. Si se pasa un error, agrega su mensaje al JSON para
// que sea fácil de buscar en los logs sin tener que parsear texto libre.
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

// Warn registra eventos sospechosos que no son errores pero merecen atención,
// como intentos con API key incorrecta o peticiones que exceden el rate limit.
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
