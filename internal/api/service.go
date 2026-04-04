// Paquete api: capa HTTP del servicio.
// Este archivo define Service, el struct que agrupa las dependencias compartidas
// (logger, rate limiter, CORS) y las inyecta en handlers y middleware.
package api

import (
	"hash-service/internal/infra"
)

// Service agrupa las dependencias que necesitan los handlers y los middlewares.
// Usamos inyección de dependencias para facilitar tests y futuros cambios.
type Service struct {
	Logger         *infra.Logger
	Limiter        *infra.RateLimiter
	AllowedOrigins map[string]bool
}

// NewService recibe las dependencias ya inicializadas y las empaqueta en Service.
func NewService(logger *infra.Logger, limiter *infra.RateLimiter, allowedOrigins map[string]bool) *Service {
	return &Service{
		Logger:         logger,
		Limiter:        limiter,
		AllowedOrigins: allowedOrigins,
	}
}
