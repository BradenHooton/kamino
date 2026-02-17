package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenManager struct {
    secrets TokenSecrets
}

type TokenSecrets struct {
    AuthSecret          string
    VerificationSecret  string
    PasswordResetSecret string
    EmailChangeSecret   string
}

type TokenClaims struct {
    Type        string `json:"type"`
    UserID      string `json:"user_id"`
    Email       string `json:"email,omitempty"`
    Refreshable bool   `json:"refreshable,omitempty"`
    jwt.RegisteredClaims
}

type OTP struct {
    ID        string
    UserID    string
    SentTo    string // Email/phone where code was sent
    CodeHash  string // Bcrypt hash of the code
    CreatedAt time.Time
    ExpiresAt time.Time
}

type ExternalAuth struct {
    ID         string
    UserID     string
    Provider   string // "google", "github", "apple"
    ProviderID string // User ID from provider
    CreatedAt  time.Time
}

const (
    MFAMethodPassword = "password"
    MFAMethodOAuth2   = "oauth2"
    MFAMethodOTP      = "otp"
)

type MFA struct {
    ID        string
    UserID    string
    Method    string // First auth method used
    CreatedAt time.Time
    ExpiresAt time.Time
}