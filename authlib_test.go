package authlib

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{
		AccessSecret:  []byte("access-secret-de-prueba"),
		RefreshSecret: []byte("refresh-secret-de-prueba"),
		AccessTTL:     2 * time.Second,
		RefreshTTL:    time.Hour,
	}
}

func TestCreateAndFindUser(t *testing.T) {
	store := NewMemoryUserStore()

	user, err := CreateUser(store, "1", "jose", "clave123", "admin")
	if err != nil {
		t.Fatalf("CreateUser falló: %v", err)
	}
	if !user.CheckPassword("clave123") {
		t.Fatal("CheckPassword debería validar la contraseña correcta")
	}
	if user.CheckPassword("otra-clave") {
		t.Fatal("CheckPassword no debería validar una contraseña incorrecta")
	}

	found, err := FindUser(store, "jose")
	if err != nil {
		t.Fatalf("FindUser falló: %v", err)
	}
	if found.ID != user.ID {
		t.Fatalf("esperaba ID %s, obtuve %s", user.ID, found.ID)
	}

	if _, err := CreateUser(store, "2", "jose", "otra", "user"); err != ErrUserExists {
		t.Fatalf("esperaba ErrUserExists, obtuve %v", err)
	}
}

func TestGenerateAndParseToken(t *testing.T) {
	cfg := testConfig()
	user := User{ID: "1", Username: "jose", Role: "admin"}

	token, err := GenerateToken(cfg, user)
	if err != nil {
		t.Fatalf("GenerateToken falló: %v", err)
	}

	claims, err := ParseToken(cfg, token)
	if err != nil {
		t.Fatalf("ParseToken falló: %v", err)
	}
	if claims.Subject != "1" || claims.Role != "admin" {
		t.Fatalf("claims inesperados: %+v", claims)
	}

	time.Sleep(2500 * time.Millisecond)
	if _, err := ParseToken(cfg, token); err != ErrExpiredToken {
		t.Fatalf("esperaba ErrExpiredToken, obtuve %v", err)
	}
}

func TestRefreshTokenRevocation(t *testing.T) {
	cfg := testConfig()
	refreshStore := NewMemoryRefreshStore()
	user := User{ID: "1", Username: "jose", Role: "admin"}

	refresh, err := GenerateRefreshToken(cfg, user, refreshStore)
	if err != nil {
		t.Fatalf("GenerateRefreshToken falló: %v", err)
	}

	claims, err := ParseRefreshToken(cfg, refresh, refreshStore)
	if err != nil {
		t.Fatalf("ParseRefreshToken falló: %v", err)
	}

	if err := refreshStore.Revoke(user.ID, claims.TokenID); err != nil {
		t.Fatalf("Revoke falló: %v", err)
	}

	if _, err := ParseRefreshToken(cfg, refresh, refreshStore); err != ErrInvalidToken {
		t.Fatalf("esperaba ErrInvalidToken tras revocar, obtuve %v", err)
	}
}

func TestMiddlewareRenewsAccessTokenWithValidRefreshToken(t *testing.T) {
	cfg := testConfig()
	userStore := NewMemoryUserStore()
	refreshStore := NewMemoryRefreshStore()

	user, _ := CreateUser(userStore, "1", "jose", "clave123", "admin")

	access, _ := GenerateToken(cfg, user)
	refresh, _ := GenerateRefreshToken(cfg, user, refreshStore)

	time.Sleep(2500 * time.Millisecond) // dejamos que el access token expire

	handler := Middleware(cfg, userStore, refreshStore)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok || claims.Role != "admin" {
			t.Fatal("esperaba encontrar claims del usuario en el contexto")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protegido", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("X-Refresh-Token", refresh)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("esperaba 200, obtuve %d", rec.Code)
	}
	if rec.Header().Get("X-New-Access-Token") == "" {
		t.Fatal("esperaba un nuevo access token en el header X-New-Access-Token")
	}
}
