// Punto de entrada del servicio. Carga la configuración, inicializa dependencias
// (logger, rate limiter, capa HTTP) y arranca el servidor en el puerto configurado.
package main

import (
	"hash-service/internal/api"
	appconfig "hash-service/internal/config"
	"hash-service/internal/infra"
	"log"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
)

func main() {
	// Logger compartido para todo el servicio
	appLogger := infra.NewLogger()

	// Lee AUTH_KEY y PORT desde variables de entorno; falla si no están
	cfg, err := appconfig.Load()
	if err != nil {
		appLogger.Error("system", "AUTH_KEY no configurada", err, map[string]interface{}{
			"fatal": true,
		})
		log.Fatal("AUTH_KEY environment variable is required")
	}

	// Limiter en memoria: máx cfg.RateLimit requests por IP en la ventana de tiempo
	limiter := infra.NewRateLimiter(cfg.RateLimit, cfg.RateWindow)
	// Goroutine que limpia visitantes inactivos cada 5 minutos
	limiter.Cleanup()
	// Agrupa logger + limiter + orígenes CORS para pasarlos a handlers y middleware
	service := api.NewService(appLogger, limiter, cfg.AllowedOrigins)

	// Configuración de Huma: define las rutas de OpenAPI, Scalar docs y esquemas JSON
	humaConfig := huma.DefaultConfig("Hash Service API", "1.1.0")
	humaConfig.OpenAPIPath = "/openapi"
	humaConfig.DocsPath = "/docs"
	humaConfig.DocsRenderer = huma.DocsRendererScalar
	humaConfig.SchemasPath = "/schemas"
	// Registra el esquema de seguridad para que aparezca en la UI de docs
	humaConfig.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"apiKey": {
			Type:        "apiKey",
			Name:        "x-api-key",
			In:          "header",
			Description: "API key requerida para los endpoints protegidos del servicio.",
		},
	}

	// Mux estándar de Go; Huma lo envuelve para manejar los endpoints documentados
	mux := http.NewServeMux()
	humaAPI := humago.New(mux, humaConfig)
	// Registra /hash, /verify y /health con sus esquemas OpenAPI
	service.RegisterOpenAPI(humaAPI, cfg.AuthKey)

	// Cadena de middleware: primero se inyecta el request ID, luego se valida CORS
	handler := service.RequestIDMiddleware(service.CORSMiddleware(mux))

	appLogger.Info("system", "Servicio iniciado", map[string]interface{}{
		"port":         cfg.Port,
		"rate_limit":   limiter.Limit(),
		"rate_window":  limiter.Window().String(),
		"allowed_cors": len(cfg.AllowedOrigins),
		"docs":         "/docs",
		"openapi":      "/openapi.json",
	})

	log.Printf("🚀 Servicio de hash iniciado en puerto %s", cfg.Port)
	log.Printf("✅ Límite de peticiones: %d por %v", limiter.Limit(), limiter.Window())
	log.Printf("✅ CORS habilitado para orígenes configurados")
	log.Printf("📘 Docs disponibles en /docs")

	if err := http.ListenAndServe(":"+cfg.Port, handler); err != nil {
		appLogger.Error("system", "Error fatal del servidor", err, nil)
		log.Fatal(err)
	}
}
