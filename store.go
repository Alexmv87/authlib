package authlib

import (
	"errors"
	"sync"
)

// Errores comunes al operar sobre usuarios.
var (
	ErrUserNotFound = errors.New("usuario no encontrado")
	ErrUserExists   = errors.New("el usuario ya existe")
)

// User representa un usuario del sistema. PasswordHash siempre contiene el
// hash bcrypt, nunca la contraseña en texto plano.
type User struct {
	ID           string
	Username     string
	PasswordHash string
	Role         string
}

// UserStore es la interfaz que debe implementar cualquier fuente de datos
// de usuarios (Postgres, MySQL, Mongo, etc). La librería no impone una base
// de datos concreta: implementa esta interfaz sobre la tuya.
type UserStore interface {
	Create(user User) error
	FindByUsername(username string) (User, error)
	FindByID(id string) (User, error)
}

// MemoryUserStore es una implementación en memoria de UserStore. Útil para
// pruebas, ejemplos o proyectos pequeños de un solo proceso. No persiste
// datos entre reinicios ni es segura para múltiples instancias.
type MemoryUserStore struct {
	mu     sync.RWMutex
	byID   map[string]User
	byName map[string]User
}

// NewMemoryUserStore crea un UserStore en memoria vacío.
func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		byID:   make(map[string]User),
		byName: make(map[string]User),
	}
}

func (s *MemoryUserStore) Create(user User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byName[user.Username]; ok {
		return ErrUserExists
	}
	s.byID[user.ID] = user
	s.byName[user.Username] = user
	return nil
}

func (s *MemoryUserStore) FindByUsername(username string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byName[username]
	if !ok {
		return User{}, ErrUserNotFound
	}
	return u, nil
}

func (s *MemoryUserStore) FindByID(id string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[id]
	if !ok {
		return User{}, ErrUserNotFound
	}
	return u, nil
}
