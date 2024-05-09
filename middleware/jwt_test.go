package middleware_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pradist/go-api-authentication/middleware"
)

func TestGenerateToken(t *testing.T) {
	testSecretKey := []byte(os.Getenv("SECRET_KEY"))

	testCases := []struct {
		name     string
		userID   uint
		expected error
	}{
		{
			name:     "ValidUserID",
			userID:   123,
			expected: nil,
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenString, err := middleware.GenerateToken(tc.userID)

			if err != tc.expected {
				t.Errorf("Unexpected error: got %v, want %v", err, tc.expected)
			}

			if err == nil {
				// Parse the token to verify its correctness
				token, parseErr := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
					return testSecretKey, nil
				})

				if parseErr != nil {
					t.Errorf("Error parsing token: %v", parseErr)
				}

				// Check if token is valid and contains expected claims
				claims, ok := token.Claims.(jwt.MapClaims)
				if !ok || !token.Valid {
					t.Errorf("Invalid token: %v", tokenString)
				}

				userIDClaim, ok := claims["user_id"].(float64)
				if !ok || uint(userIDClaim) != tc.userID {
					t.Errorf("Invalid user ID claim in token: got %v, want %v", userIDClaim, tc.userID)
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
		})
	}
}

func TestVerifyTokenWithValidToken(t *testing.T) {
	validTokenString, _ := middleware.GenerateToken(123)
	claims, err := middleware.VerifyToken(validTokenString)

	if err == nil && claims == nil {
		t.Error("Expected non-nil claims, but got nil")
	}
}

func TestVerifyTokenWithInvalidMethodToken(t *testing.T) {
	testSecretKey := []byte("test_secret_key")
	invalidMethodToken := jwt.New(jwt.SigningMethodHS256)
	invalidMethodTokenString, _ := invalidMethodToken.SignedString(testSecretKey)

	expectedError := fmt.Errorf("signature is invalid")

	_, err := middleware.VerifyToken(invalidMethodTokenString)

	if err == nil || err.Error() != expectedError.Error() {
		t.Errorf("Unexpected error: got %v, want %v", err, expectedError)
	}
}

func TestVerifyTokenWithInvalidClaimsToken(t *testing.T) {
	testSecretKey := []byte("test_secret_key")
	invalidClaimsToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"foo": "bar"})
	invalidClaimsTokenString, _ := invalidClaimsToken.SignedString(testSecretKey)

	expectedError := "token contains an invalid number of segments"

	_, err := middleware.VerifyToken(invalidClaimsTokenString)

	if err == nil || err.Error() != expectedError {
		t.Errorf("Unexpected error: got %v, want %v", err, expectedError)
	}
}
