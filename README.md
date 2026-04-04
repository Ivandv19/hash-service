# Hash Service

## Descripcion

Hash Service es un microservicio pequeno hecho en Go para manejar una sola tarea muy concreta: generar y verificar hashes de contrasenas usando Argon2id.

La idea es mantener esta logica separada, simple y reutilizable para otros proyectos donde no tenga sentido mezclar autenticacion sensible con el resto de la aplicacion.

## Caracteristicas

- **Hash Seguro**: Genera hashes de contrasenas usando Argon2id.
- **Verificacion Rapida**: Permite comprobar si una contrasena coincide con un hash existente.
- **Proteccion Basica**: Incluye validacion de API key y rate limit por IP.
- **Documentacion Profesional**: Expone documentacion OpenAPI y UI interactiva dentro del propio servicio.

## Secciones del Servicio

1. **Health Check**: Endpoint simple para revisar si el servicio esta funcionando correctamente.
2. **Hash**: Endpoint para generar hashes seguros.
3. **Verify**: Endpoint para validar contrasena contra hash.
4. **Docs**: Vista web de la documentacion de la API.

## Uso

- **Levantar Localmente**: Corre el servicio en tu maquina para integrarlo con otros proyectos.
- **Generar Hashes**: Manda una contrasena y recibe un hash seguro.
- **Verificar Hashes**: Comprueba si una contrasena corresponde con un hash generado previamente.
- **Consultar la Documentacion**: Explora la API desde el navegador en la ruta `/docs`.

## Tecnologias Utilizadas

- Go
- Argon2id
- Huma
- OpenAPI 3.1
- Docker

## Instalacion

1. **Entrar al Proyecto**: Abre la carpeta del microservicio.

2. **Crear Variables de Entorno**: Toma como base el archivo `.env.example` y define tu `AUTH_KEY`.

3. **Instalar Dependencias**: Si hace falta actualizar dependencias, puedes ejecutar:

```bash
go mod tidy
```

4. **Iniciar el Servicio**: Levantalo localmente con:

```bash
go run .
```

El servicio corre por default en `http://localhost:3010`.

## Documentacion de la API

La documentacion formal del microservicio ya esta integrada dentro del proyecto:

- **Docs Web**: `http://localhost:3010/docs`
- **OpenAPI JSON**: `http://localhost:3010/openapi.json`
- **OpenAPI YAML**: `http://localhost:3010/openapi.yaml`

De esta forma el README queda ligero y la documentacion tecnica sale directamente del codigo.

## Docker

Si quieres levantarlo con contenedor:

```bash
docker compose up --build
```

## Testing

Para correr las pruebas:

```bash
go test ./...
```

## Creditos

Este microservicio forma parte de tu ecosistema de proyectos y esta pensado como pieza reutilizable para tareas de seguridad muy puntuales.

## Nota

Los endpoints protegidos (`/hash` y `/verify`) necesitan `x-api-key`, mientras que `/health` y la documentacion pueden consultarse directamente.
