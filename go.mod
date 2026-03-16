// Nombre del módulo (identificador único del proyecto en Go)
module hash-service

// Versión mínima de Go requerida para compilar este módulo
go 1.25.0

// Dependencia directa: librería para hashing con el algoritmo Argon2id
require github.com/alexedwards/argon2id v1.0.0

// Dependencias indirectas (requeridas por argon2id internamente)
require (
	golang.org/x/crypto v0.49.0 // indirect; indirect — primitivas criptográficas (AES, SHA, etc.)
	golang.org/x/sys v0.42.0 // indirect; indirect — interfaz de bajo nivel con el SO
)
