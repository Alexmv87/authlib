package authlib

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Errores devueltos al validar tokens.
var (
	ErrInvalidToken = errors.New("token inválido")
	ErrExpiredToken = errors.New("token expirado")
)

// Config agrupa la configuración necesaria para firmar y validar tokens.
//
// Se recomienda usar secretos distintos para access y refresh, así una
// fuga de uno no compromete al otro. Ambos deben venir de variables de
// entorno, nunca hardcodeados.
type Config struct {
	AccessSecret  []byte
	RefreshSecret []byte
	AccessTTL     time.Duration // por defecto 15 minutos si se deja en 0
	RefreshTTL    time.Duration // por defecto 7 días (1 semana) si se deja en 0
}

func (c Config) accessTTL() time.Duration {
	if c.AccessTTL <= 0 {
		return 15 * time.Minute
	}
	return c.AccessTTL
}

func (c Config) refreshTTL() time.Duration {
	if c.RefreshTTL <= 0 {
		return 7 * 24 * time.Hour
	}
	return c.RefreshTTL
}

// Claims son los claims incluidos en el access token.
type Claims struct {
	Name string `json:"name"`
	Role string `json:"role"`
	jwt.RegisteredClaims
}

// RefreshClaims son los claims del refresh token. Se mantienen mínimos a
// propósito: el refresh token solo sirve para obtener un access token
// nuevo, no debe usarse para autorizar acciones directamente.
type RefreshClaims struct {
	TokenID string `json:"tid"`
	jwt.RegisteredClaims
}

// GenerateToken firma un access token JWT (HS256) para el usuario dado.
func GenerateToken(cfg Config, user User) (string, error) {
	now := time.Now()
	claims := Claims{
		Name: user.Username,
		Role: user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(cfg.accessTTL())),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(cfg.AccessSecret)
}

// GenerateRefreshToken firma un refresh token JWT (HS256) de larga duración
// (por defecto una semana). Si store no es nil, el token se registra ahí
// para poder revocarlo después (p. ej. en un logout).
func GenerateRefreshToken(cfg Config, user User, store RefreshStore) (string, error) {
	now := time.Now()
	expiresAt := now.Add(cfg.refreshTTL())
	tokenID, err := newTokenID()
	if err != nil {
		return "", err
	}

	claims := RefreshClaims{
		TokenID: tokenID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(cfg.RefreshSecret)
	if err != nil {
		return "", err
	}

	if store != nil {
		if err := store.Save(user.ID, tokenID, expiresAt); err != nil {
			return "", err
		}
	}

	return signed, nil
}

// ParseToken valida la firma y expiración de un access token y devuelve sus
// claims si es válido.
func ParseToken(cfg Config, raw string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("método de firma inesperado")
		}
		return cfg.AccessSecret, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, err
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// ParseRefreshToken valida la firma y expiración de un refresh token. Si
// store no es nil, también verifica que el token no haya sido revocado.
func ParseRefreshToken(cfg Config, raw string, store RefreshStore) (*RefreshClaims, error) {
	claims := &RefreshClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("método de firma inesperado")
		}
		return cfg.RefreshSecret, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, err
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}
	if store != nil && !store.IsValid(claims.Subject, claims.TokenID) {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

func newTokenID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
