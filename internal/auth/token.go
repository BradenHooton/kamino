package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/BradenHooton/kamino/internal/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// UserTokenKeyFetcher defines interface for retrieving user's TokenKey
type UserTokenKeyFetcher interface {
	GetByID(ctx context.Context, id string) (*models.User, error)
}

// TokenManager handles JWT token generation and validation
type TokenManager struct {
	secret              string
	accessTokenExpiry   time.Duration
	refreshTokenExpiry  time.Duration
	userRepo            UserTokenKeyFetcher
}

// NewTokenManager creates a new TokenManager
func NewTokenManager(secret string, accessExpiry, refreshExpiry time.Duration) *TokenManager {
	return &TokenManager{
		secret:              secret,
		accessTokenExpiry:   accessExpiry,
		refreshTokenExpiry:  refreshExpiry,
	}
}

// SetUserRepo enables composite signing with per-user TokenKey
// Call after TokenManager is created to enable the feature
func (tm *TokenManager) SetUserRepo(repo UserTokenKeyFetcher) {
	tm.userRepo = repo
}

// getSigningKey returns composite key (global_secret + user.TokenKey) or global secret
func (tm *TokenManager) getSigningKey(userID string) ([]byte, error) {
	// Fall back to global secret if no userRepo (backward compatibility)
	if tm.userRepo == nil {
		return []byte(tm.secret), nil
	}

	// Fetch user's TokenKey
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	user, err := tm.userRepo.GetByID(ctx, userID)
	if err != nil {
		// Graceful degradation: use global secret if user not found
		return []byte(tm.secret), nil
	}

	// Composite key: global_secret + user.TokenKey
	composite := tm.secret + user.TokenKey
	return []byte(composite), nil
}

// GenerateAccessToken creates a short-lived access token with JTI
func (tm *TokenManager) GenerateAccessToken(userID, email string) (string, error) {
	jti := uuid.New().String() // Generate unique token ID

	claims := &models.TokenClaims{
		Type:   "access",
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti, // Add JTI claim
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tm.accessTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Use composite signing key
	signingKey, err := tm.getSigningKey(userID)
	if err != nil {
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}

	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return tokenString, nil
}

// GenerateRefreshToken creates a long-lived refresh token with JTI
func (tm *TokenManager) GenerateRefreshToken(userID, email string) (string, error) {
	jti := uuid.New().String() // Generate unique token ID

	claims := &models.TokenClaims{
		Type:   "refresh",
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti, // Add JTI claim
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tm.refreshTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Use composite signing key
	signingKey, err := tm.getSigningKey(userID)
	if err != nil {
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}

	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken verifies a token and returns its claims
func (tm *TokenManager) ValidateToken(tokenString string) (*models.TokenClaims, error) {
	claims := &models.TokenClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Extract userID from claims for composite key lookup
		if tmpClaims, ok := token.Claims.(*models.TokenClaims); ok && tmpClaims.UserID != "" {
			signingKey, err := tm.getSigningKey(tmpClaims.UserID)
			if err != nil {
				// Fall back to global secret
				return []byte(tm.secret), nil
			}
			return signingKey, nil
		}

		// Default to global secret
		return []byte(tm.secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, models.ErrUnauthorized
	}

	// Validate token type
	if claims.Type == "" {
		return nil, fmt.Errorf("invalid token: missing type")
	}

	return claims, nil
}
