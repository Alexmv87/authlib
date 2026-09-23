// Package authlib es una librería reutilizable de autenticación para
// aplicaciones Go. Provee:
//
//   - Creación y búsqueda de usuarios (CreateUser, FindUser) sobre una
//     interfaz UserStore que tú implementas con tu propia base de datos.
//   - Generación y validación de access tokens JWT (GenerateToken, ParseToken).
//   - Generación y validación de refresh tokens JWT de larga duración
//     (GenerateRefreshToken, ParseRefreshToken), con revocación opcional
//     mediante RefreshStore.
//   - Un middleware HTTP (Middleware) que valida el access token en cada
//     petición y, si expiró, lo renueva automáticamente usando el refresh
//     token si sigue vigente.
//
// La librería no impone ninguna base de datos ni framework HTTP: solo
// requiere http.Handler estándar y las interfaces UserStore / RefreshStore.
package authlib
