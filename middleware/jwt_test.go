package middleware_test

import (
	"os"
	"testing"

	"github.com/pradist/go-api-authentication/middleware"
)

func TestCreateToken(t *testing.T) {
	os.Setenv("SECRET_KEY", "secret")
	_, err := middleware.CreateToken("pradist")
	if err != nil {
		t.Errorf("Expect no error, but got %v", err)
	}
}
