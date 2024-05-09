package middleware_test

import (
	"os"
	"testing"
	"time"

	"github.com/pradist/go-api-authentication/middleware"

	"github.com/golang-jwt/jwt/v4"
)

func TestGenerateToken(t *testing.T) {

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
					return []byte(os.Getenv("SECRET_KEY")), nil
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
