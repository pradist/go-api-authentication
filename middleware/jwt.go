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
			"exp":       time.Now().Add(time.Minute * 1).Unix(),
		})
	return token.SignedString(secretKey)
}

type UserClaims struct {
	UserName string `json:"user_name"`
	jwt.RegisteredClaims
}

func VerifyToken(tokenString string) (*UserClaims, error) {

	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	return token.Claims.(*UserClaims), nil
}
