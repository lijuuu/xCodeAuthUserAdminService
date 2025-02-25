package utils

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims matches the middleware Claims structure
type Claims struct {
	ID   string `json:"id"`
	Role string `json:"role"`
	jwt.RegisteredClaims
}

// GenerateJWT creates a new JWT
func GenerateJWT(userID, role, secret string, tokenDuration time.Duration) (string, int32, error) {
	expirationTime := time.Now().Add(tokenDuration)
	claims := &Claims{
		ID:   userID,
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", 0, err
	}
	// Return expiration in seconds based on actual duration
	expiresIn := int32(tokenDuration / time.Second)
	return tokenString, expiresIn, nil
}