// Nombre del módulo (identificador único del proyecto en Go)
module hash-service

// Versión mínima de Go requerida para compilar este módulo
go 1.24.0

// Dependencia directa: librería para hashing con el algoritmo Argon2id
require github.com/alexedwards/argon2id v1.0.0

// Dependencias indirectas (requeridas por argon2id internamente)
require (
	golang.org/x/crypto v0.48.0 // indirect — primitivas criptográficas (AES, SHA, etc.)
	golang.org/x/sys v0.41.0 // indirect — interfaz de bajo nivel con el SO
)
