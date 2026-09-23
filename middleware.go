package authlib

import (
	"context"
	"net/http"
)

type contextKey string

const claimsContextKey contextKey = "authlib_claims"

// Middleware valida el access token en cada petición (header
// "Authorization: Bearer <token>"). Si el access token expiró pero se envía
// un refresh token válido y no revocado en el header "X-Refresh-Token",
// genera un access token nuevo automáticamente, lo agrega a la respuesta en
// el header "X-New-Access-Token", y deja continuar la petición con
// normalidad usando los datos actuales del usuario.
//
// userStore se usa para recuperar los datos vigentes del usuario (nombre,
// rol) al regenerar el token desde el refresh token — así, si el rol
// cambió mientras tanto, el nuevo access token refleja el valor actual.
// refreshStore es opcional: si es nil, no se verifica revocación de
// refresh tokens (solo su firma y expiración).
func Middleware(cfg Config, userStore UserStore, refreshStore RefreshStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := bearerToken(r)
			if raw == "" {
				http.Error(w, "falta el token de autenticación", http.StatusUnauthorized)
				return
			}

			claims, err := ParseToken(cfg, raw)
			if err != nil {
				if err != ErrExpiredToken {
					http.Error(w, "token inválido", http.StatusUnauthorized)
					return
				}

				// El access token expiró: intentamos renovar con el refresh token.
				refreshRaw := r.Header.Get("X-Refresh-Token")
				if refreshRaw == "" {
					http.Error(w, "token expirado", http.StatusUnauthorized)
					return
				}

				refreshClaims, err := ParseRefreshToken(cfg, refreshRaw, refreshStore)
				if err != nil {
					http.Error(w, "refresh token inválido o expirado", http.StatusUnauthorized)
					return
				}

				user, err := userStore.FindByID(refreshClaims.Subject)
				if err != nil {
					http.Error(w, "usuario no encontrado", http.StatusUnauthorized)
					return
				}

				newAccess, err := GenerateToken(cfg, user)
				if err != nil {
					http.Error(w, "no se pudo generar un nuevo token", http.StatusInternalServerError)
					return
				}
				w.Header().Set("X-New-Access-Token", newAccess)

				claims = &Claims{Name: user.Username, Role: user.Role}
				claims.Subject = user.ID
			}

			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// bearerToken extrae el token del header "Authorization: Bearer <token>".
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && h[:len(prefix)] == prefix {
		return h[len(prefix):]
	}
	return ""
}

// ClaimsFromContext recupera los claims del access token que el Middleware
// guardó en el contexto de la petición.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*Claims)
	return claims, ok
}
