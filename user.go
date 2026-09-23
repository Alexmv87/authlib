package authlib

import (
	"golang.org/x/crypto/bcrypt"
)

// CreateUser crea un usuario nuevo en el store dado, hasheando la
// contraseña con bcrypt antes de guardarla. id normalmente lo genera quien
// llama (UUID, autoincremental de tu BD, etc).
func CreateUser(store UserStore, id, username, password, role string) (User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	user := User{
		ID:           id,
		Username:     username,
		PasswordHash: string(hash),
		Role:         role,
	}
	if err := store.Create(user); err != nil {
		return User{}, err
	}
	return user, nil
}

// FindUser busca un usuario por su nombre de usuario.
func FindUser(store UserStore, username string) (User, error) {
	return store.FindByUsername(username)
}

// CheckPassword compara una contraseña en texto plano contra el hash
// guardado del usuario. Devuelve true si coincide.
func (u User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	return err == nil
}
