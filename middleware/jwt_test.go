package middleware_test

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/pradist/go-api-authentication/middleware"
)

func TestCreateTokenShouldBeParsedPass(t *testing.T) {
	testSecretKey := []byte(os.Getenv("SECRET_KEY"))
	userName := "Test"
	tokenString, err := middleware.CreateToken(userName)

	if err != nil {
		t.Errorf("Unexpected error: got %v, want %v", err, nil)
	}

	if err == nil {
		// Parse the token to verify its correctness
		token, parseErr := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return testSecretKey, nil
		})

		if parseErr != nil {
			t.Errorf("Error parsing token: %v", parseErr)
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			t.Errorf("Invalid token: %v", tokenString)
		}

		userNameClaim, ok := claims["user_name"].(string)
		if !ok || userName != userNameClaim {
			t.Errorf("Invalid user ID claim in token: got %v, want %v", userNameClaim, userName)
		}

		expClaim, ok := claims["exp"].(float64)
		if !ok {
			t.Errorf("Invalid expiration claim in token: expiration claim is not float64")
		}

		expTime := time.Unix(int64(expClaim), 0)
		expectedExpTime := time.Now().Add(time.Hour)
		if expTime.Before(expectedExpTime.Add(-time.Second)) || expTime.After(expectedExpTime.Add(time.Second)) {
			t.Errorf("Invalid expiration claim in token: got %v, want expiration time 1 hour from now", expTime)
		}
	}
}

func TestVerifyTokenShouldBeParsedPass(t *testing.T) {
	userName := "Test"
	tokenString, _ := middleware.CreateToken(userName)

	_, err := middleware.VerifyToken(tokenString)
	if err != nil {
		t.Errorf("Unexpected error: got %v, want %v", err, nil)
	}
}

func TestVerifyToken_WhenTokenIsEmpty_ShouldVerifyFail(t *testing.T) {
	_, err := middleware.VerifyToken("")
	fmt.Println(err.Error())
	if err == nil {
		t.Errorf("Expected error: got %v, want %v", nil, errors.New("invalid token"))
	}
}

func TestVerifyToken_WhenTokenIsInvalid_ShouldVerifyFail(t *testing.T) {
	_, err := middleware.VerifyToken("invalid_token")
	fmt.Println(err.Error())
	if err == nil {
		t.Errorf("Expected error: got %v, want %v", nil, errors.New("invalid token"))
	}
}
