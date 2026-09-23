# authlib

Librería de autenticación en Go: usuarios, access tokens, refresh tokens y
middleware HTTP con renovación automática. No es una aplicación: no tiene
`main`, se importa como dependencia en tu propio proyecto.

## Primer paso tras descomprimir

El proyecto no incluye `go.sum` (se genera en tu máquina, con tu acceso normal
a internet). Al entrar a la carpeta, corre:

```bash
go mod tidy
```

Esto descarga `github.com/golang-jwt/jwt/v5` y `golang.org/x/crypto`, y crea
`go.sum`. Ya con eso, `go build ./...` y `go test ./...` funcionan sin más.

## Instalación

```bash
go get github.com/Alexmv87/authlib
```

## Componentes

- **`User`, `UserStore`**: modelo de usuario e interfaz de persistencia.
  Implementa `UserStore` sobre tu propia base de datos, o usa
  `MemoryUserStore` para pruebas.
- **`CreateUser`, `FindUser`**: crear usuarios (con hash bcrypt) y buscarlos.
- **`Config`**: secretos y TTLs de los tokens.
- **`GenerateToken` / `ParseToken`**: access token JWT (por defecto 15 min).
- **`GenerateRefreshToken` / `ParseRefreshToken`**: refresh token JWT (por
  defecto 1 semana), con revocación opcional vía `RefreshStore`.
- **`Middleware`**: middleware `net/http` que valida el access token y, si
  expiró, lo renueva automáticamente usando el refresh token.

## Uso básico

```go
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/Alexmv87/authlib"
)

func main() {
	cfg := authlib.Config{
		AccessSecret:  []byte("cambia-esto-por-variable-de-entorno"),
		RefreshSecret: []byte("otro-secreto-distinto"),
		AccessTTL:     15 * time.Minute,
		RefreshTTL:    7 * 24 * time.Hour, // 1 semana (valor por defecto si se omite)
	}

	users := authlib.NewMemoryUserStore()
	refreshTokens := authlib.NewMemoryRefreshStore()

	// Crear un usuario
	user, err := authlib.CreateUser(users, "1", "jose", "clave123", "admin")
	if err != nil {
		log.Fatal(err)
	}

	// Login: generar access + refresh token
	access, _ := authlib.GenerateToken(cfg, user)
	refresh, _ := authlib.GenerateRefreshToken(cfg, user, refreshTokens)
	log.Println("access:", access)
	log.Println("refresh:", refresh)

	// Middleware protegiendo rutas
	mux := http.NewServeMux()
	mux.Handle("/perfil", authlib.Middleware(cfg, users, refreshTokens)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, _ := authlib.ClaimsFromContext(r.Context())
			w.Write([]byte("hola " + claims.Name))
		}),
	))

	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## Flujo del middleware

1. Lee el access token del header `Authorization: Bearer <token>`.
2. Si es válido, deja pasar la petición y guarda los claims en el contexto
   (recuperables con `ClaimsFromContext`).
3. Si expiró, busca un refresh token en el header `X-Refresh-Token`.
   - Si es válido (firma, expiración y no revocado), genera un access token
     nuevo, lo agrega en el header de respuesta `X-New-Access-Token`, y deja
     pasar la petición con normalidad.
   - Si no hay refresh token o también es inválido/expiró, responde `401`.

El cliente (frontend, app móvil, etc.) debe revisar si la respuesta trae el
header `X-New-Access-Token` y, si es así, reemplazar el access token que
tenía guardado por ese nuevo valor.

## Revocar un refresh token (logout)

```go
refreshClaims, _ := authlib.ParseRefreshToken(cfg, refreshTokenDelUsuario, refreshTokens)
refreshTokens.Revoke(refreshClaims.Subject, refreshClaims.TokenID)
```

## Implementar tu propio UserStore

```go
type PostgresUserStore struct {
	db *sql.DB
}

func (s *PostgresUserStore) Create(u authlib.User) error { /* INSERT ... */ }
func (s *PostgresUserStore) FindByUsername(username string) (authlib.User, error) { /* SELECT ... */ }
func (s *PostgresUserStore) FindByID(id string) (authlib.User, error) { /* SELECT ... */ }
```

Lo mismo aplica para `RefreshStore` si quieres persistir la revocación en
base de datos o Redis en vez de memoria.

## Tests

```bash
go test ./...
```
