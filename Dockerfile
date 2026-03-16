# ── ETAPA 1: Builder ─────────────────────────────────────────────────────────
# Usamos la imagen oficial de Go con Alpine (ligera). Esta imagen solo existe
# durante la compilación, NO llega a producción.
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copiamos primero solo los archivos de dependencias para aprovechar el caché
# de Docker: si el código cambia pero las deps no, no las vuelve a descargar.
COPY go.mod go.sum ./
RUN go mod download

# Ahora copiamos el resto del código fuente
COPY . .

# Compilamos el binario. CGO_ENABLED=0 desactiva las dependencias de C para
# que el binario sea 100% estático y funcione en cualquier Linux sin librerías.
RUN CGO_ENABLED=0 GOOS=linux go build -o hash-service main.go

# ── ETAPA 2: Imagen final ─────────────────────────────────────────────────────
# Solo usamos Alpine (sin Go). Copiamos únicamente el binario compilado.
# Resultado: imagen final de ~10MB en vez de ~300MB.
FROM alpine:latest

# Se crea un usuario sin privilegios para correr la app (buena práctica de seguridad).
RUN adduser -D -u 1000 appuser
USER appuser

WORKDIR /app

# Copiamos el binario desde la etapa anterior (builder)
COPY --from=builder /app/hash-service .

# Puerto por defecto del servicio
ENV PORT=3010
EXPOSE ${PORT}

# Comando de arranque
CMD ["./hash-service"]
