// Paquete config: lee las variables de entorno y define los valores por defecto
// que necesita el servicio para arrancar (puerto, clave, CORS, rate limiting).
package config

import (
	"fmt"
	"os"
	"time"
)

// AppConfig agrupa todo lo que el servicio necesita en tiempo de ejecución.
type AppConfig struct {
	AuthKey        string
	Port           string
	AllowedOrigins map[string]bool
	RateLimit      int
	RateWindow     time.Duration
}

// Load lee AUTH_KEY (obligatoria) y PORT (opcional, default 3010) del entorno.
// Los orígenes CORS y límites de rate son estáticos por ahora.
func Load() (AppConfig, error) {
	// AUTH_KEY es obligatoria: si no existe el servicio no puede proteger ningún endpoint.
	// Fallamos rápido en el arranque en lugar de dejar endpoints desprotegidos.
	authKey := os.Getenv("AUTH_KEY")
	if authKey == "" {
		return AppConfig{}, fmt.Errorf("AUTH_KEY environment variable is required")
	}

	// PORT es opcional; 3010 es el default para desarrollo local y Docker.
	port := os.Getenv("PORT")
	if port == "" {
		port = "3010"
	}

	// Los orígenes CORS y los parámetros de rate limit son estáticos por ahora.
	// Si en el futuro se necesitan dinámicos, este es el único lugar a cambiar.
	return AppConfig{
		AuthKey: authKey,
		Port:    port,
		AllowedOrigins: map[string]bool{
			"https://sinx-pomodoro.mgdc.site": true,
			"https://gestor.mgdc.site":        true,
		},
		RateLimit:  30,
		RateWindow: time.Minute,
	}, nil
}
