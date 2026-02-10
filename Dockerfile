# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy dependency files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o hash-service main.go

# Final stage
FROM alpine:latest

# Security: Add a non-root user
RUN adduser -D -u 1000 appuser
USER appuser

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/hash-service .

# Default port
ENV PORT=3010

EXPOSE ${PORT}

# Run the app
CMD ["./hash-service"]
