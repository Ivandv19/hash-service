// Paquete infra: primitivas de bajo nivel reutilizables por toda la app.
// Este archivo implementa un rate limiter en memoria basado en ventana deslizante.
package infra

import (
	"sync"
	"time"
)

// RateLimiter lleva el conteo de peticiones por IP usando una ventana deslizante.
// Usa un mutex de lectura/escritura para soportar acceso concurrente sin cuellos.
type RateLimiter struct {
	visitors map[string]*Visitor
	mu       sync.RWMutex
	limit    int
	window   time.Duration
}

// Visitor guarda los timestamps de cada petición de un cliente para filtrar
// cuáles siguen dentro de la ventana de tiempo activa.
type Visitor struct {
	requests []time.Time
	mu       sync.Mutex
}

// NewRateLimiter crea un limiter con el máximo de peticiones y la ventana de tiempo
// que se leen desde la configuración del servicio.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		visitors: make(map[string]*Visitor),
		limit:    limit,
		window:   window,
	}
}

// Limit returns the configured request quota.
func (rl *RateLimiter) Limit() int {
	return rl.limit
}

// Window returns the configured time window.
func (rl *RateLimiter) Window() time.Duration {
	return rl.window
}

// Allow devuelve true si la IP tiene cuota disponible, false si ya la superó.
// Primero obtiene (o crea) la entrada del visitante con lock global, luego
// filtra peticiones viejas fuera de la ventana y verifica si cabe una más.
func (rl *RateLimiter) Allow(ip string) bool {
	// Paso 1: con el lock global obtenemos (o creamos) la entrada del visitante.
	// Usamos Lock y no RLock porque podríamos insertar un visitante nuevo.
	rl.mu.Lock()
	visitor, exists := rl.visitors[ip]
	if !exists {
		// Primera vez que vemos esta IP: inicializamos su lista de timestamps vacía.
		visitor = &Visitor{requests: []time.Time{}}
		rl.visitors[ip] = visitor
	}
	// Soltamos el lock global lo antes posible para no bloquear otras IPs.
	rl.mu.Unlock()

	// Paso 2: bloqueamos solo el mutex del visitante para no bloquear a otras IPs
	// mientras calculamos si esta tiene cuota disponible.
	visitor.mu.Lock()
	defer visitor.mu.Unlock()

	now := time.Now()
	validRequests := []time.Time{}

	// Paso 3: reconstruimos la lista descartando timestamps que ya salieron
	// de la ventana de tiempo; así implementamos la ventana deslizante.
	for _, requestTime := range visitor.requests {
		if now.Sub(requestTime) < rl.window {
			validRequests = append(validRequests, requestTime)
		}
	}
	visitor.requests = validRequests

	// Paso 4: si ya llegó al límite, rechazamos sin agregar un timestamp nuevo.
	if len(visitor.requests) >= rl.limit {
		return false
	}

	// Paso 5: hay cuota disponible; registramos este momento y dejamos pasar.
	visitor.requests = append(visitor.requests, now)
	return true
}

// Cleanup lanza una goroutine que cada 5 minutos elimina visitantes sin peticiones
// recientes para evitar que el mapa crezca indefinidamente en memoria.
func (rl *RateLimiter) Cleanup() {
	// El ticker dispara cada 5 minutos en una goroutine separada para no bloquear
	// el arranque del servicio; el loop corre indefinidamente mientras el proceso viva.
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			rl.mu.Lock()
			for ip, visitor := range rl.visitors {
				visitor.mu.Lock()
				// Eliminamos al visitante si no tiene requests registradas o si la última
				// quedó fuera de la ventana, lo que significa que ya está inactivo.
				if len(visitor.requests) == 0 || time.Since(visitor.requests[len(visitor.requests)-1]) > rl.window {
					delete(rl.visitors, ip)
				}
				visitor.mu.Unlock()
			}
			rl.mu.Unlock()
		}
	}()
}
