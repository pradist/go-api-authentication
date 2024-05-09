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

type CustomClaimsExample struct {
	UserName string `json:"user_name"`
	jwt.StandardClaims
}

func VerifyToken(tokenString string) (*CustomClaimsExample, error) {

	token, err := jwt.ParseWithClaims(tokenString, &CustomClaimsExample{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims := token.Claims.(*CustomClaimsExample)
	return claims, nil
}
