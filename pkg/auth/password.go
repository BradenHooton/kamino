package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

const (
	BcryptCost      = 14  // OWASP 2026 recommendation - stronger than cost 12 (Feb 2026)
	TokenKeyLength  = 32  // 256 bits
	MinPasswordLen  = 8
	MaxPasswordLen  = 128
)

// PasswordValidationError holds validation error details (internal use only)
type PasswordValidationError struct {
	Errors []string
}

func (e *PasswordValidationError) Error() string {
	if len(e.Errors) == 0 {
		return "password validation failed"
	}
	// Return generic error to users - never expose specific requirements to prevent enumeration attacks
	return "invalid password"
}

// Common weak passwords to reject
var commonPasswords = map[string]bool{
	"password":       true,
	"12345678":       true,
	"qwerty":         true,
	"abc123":         true,
	"password123":    true,
	"password123!":   true,
	"123456":         true,
	"admin":          true,
	"letmein":        true,
	"welcome":        true,
	"monkey":         true,
	"dragon":         true,
	"master":         true,
	"123123":         true,
	"passw0rd":       true,
	"shadow":         true,
	"sunshine":       true,
	"princess":       true,
	"starwars":       true,
	"football":       true,
	"trustno1":       true,
}

func HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hashedBytes), nil
}

func ComparePassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func GenerateTokenKey() (string, error) {
	bytes := make([]byte, TokenKeyLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate token key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// ValidatePassword enforces strong password requirements
func ValidatePassword(password string) error {
	errors := make([]string, 0)

	// Check length
	if len(password) < MinPasswordLen {
		errors = append(errors, fmt.Sprintf("must be at least %d characters", MinPasswordLen))
	}
	if len(password) > MaxPasswordLen {
		errors = append(errors, fmt.Sprintf("must be at most %d characters", MaxPasswordLen))
	}

	// Check character requirements
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	if !hasUpper {
		errors = append(errors, "must contain at least one uppercase letter")
	}
	if !hasLower {
		errors = append(errors, "must contain at least one lowercase letter")
	}
	if !hasDigit {
		errors = append(errors, "must contain at least one digit")
	}
	if !hasSpecial {
		errors = append(errors, "must contain at least one special character")
	}

	// Check against common passwords (case-insensitive)
	if commonPasswords[strings.ToLower(password)] {
		errors = append(errors, "is too common, please choose a more unique password")
	}

	if len(errors) > 0 {
		return &PasswordValidationError{Errors: errors}
	}

	return nil
}
