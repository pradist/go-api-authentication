package middleware

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// GenerateToken generates a JWT token with the user ID as part of the claims
func GenerateToken(userID uint) (string, error) {

	secretKey := []byte(os.Getenv("SECRET_KEY"))

	claims := jwt.MapClaims{}
	claims["user_id"] = userID
	claims["exp"] = time.Now().Add(time.Hour).Unix() // Token valid for 1 hour

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}
