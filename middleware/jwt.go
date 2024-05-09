package middleware

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var secretKey = []byte(os.Getenv("SECRET_KEY"))

func CreateToken(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"user_name": username,
			"exp":       time.Now().Add(time.Hour * 1).Unix(),
		})
	return token.SignedString(secretKey)
}
