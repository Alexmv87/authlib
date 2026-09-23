package authlib

import (
	"sync"
	"time"
)

// RefreshStore permite registrar y revocar refresh tokens emitidos. Es
// opcional: si no se pasa (nil) a las funciones que lo aceptan, los refresh
// tokens siguen siendo válidos hasta su expiración natural y no pueden
// revocarse individualmente (por ejemplo, en un logout).
type RefreshStore interface {
	// Save registra un refresh token recién emitido para un usuario.
	Save(userID, tokenID string, expiresAt time.Time) error
	// IsValid indica si el refresh token sigue vigente y no fue revocado.
	IsValid(userID, tokenID string) bool
	// Revoke invalida un refresh token específico (p. ej. logout).
	Revoke(userID, tokenID string) error
}

// MemoryRefreshStore es una implementación en memoria de RefreshStore.
// Igual que MemoryUserStore, no persiste entre reinicios ni sirve para
// múltiples instancias; para producción implementa RefreshStore sobre tu
// base de datos o Redis.
type MemoryRefreshStore struct {
	mu     sync.RWMutex
	tokens map[string]time.Time // clave: userID + ":" + tokenID
}

// NewMemoryRefreshStore crea un RefreshStore en memoria vacío.
func NewMemoryRefreshStore() *MemoryRefreshStore {
	return &MemoryRefreshStore{tokens: make(map[string]time.Time)}
}

func refreshKey(userID, tokenID string) string {
	return userID + ":" + tokenID
}

func (s *MemoryRefreshStore) Save(userID, tokenID string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[refreshKey(userID, tokenID)] = expiresAt
	return nil
}

func (s *MemoryRefreshStore) IsValid(userID, tokenID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	exp, ok := s.tokens[refreshKey(userID, tokenID)]
	if !ok {
		return false
	}
	return time.Now().Before(exp)
}

func (s *MemoryRefreshStore) Revoke(userID, tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, refreshKey(userID, tokenID))
	return nil
}
