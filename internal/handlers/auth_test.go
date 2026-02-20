package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/BradenHooton/kamino/internal/handlers"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/internal/services"
	pkghttp "github.com/BradenHooton/kamino/pkg/http"
	"github.com/stretchr/testify/assert"
)

func TestLogin_Success(t *testing.T) {
	mockAuth := &handlers.MockAuthService{
		LoginFunc: func(ctx context.Context, email, password, ipAddress, userAgent string) (*services.AuthResponse, error) {
			return &services.AuthResponse{
				AccessToken:  "access_token_123",
				RefreshToken: "refresh_token_123",
			}, nil
		},
	}

	handler := handlers.NewAuthHandler(mockAuth, nil, nil)
	req := handlers.NewTestRequest(t, "POST", "/auth/login", handlers.LoginRequest{
		Email:    "user@example.com",
		Password: "password123",
	})

	w := httptest.NewRecorder()
	handler.Login(w, req)

	var resp services.AuthResponse
	handlers.AssertJSONResponse(t, w, 200, &resp)
	assert.Equal(t, "access_token_123", resp.AccessToken)
	assert.Equal(t, "refresh_token_123", resp.RefreshToken)
}

func TestLogin_AuthenticationFailed(t *testing.T) {
	mockAuth := &handlers.MockAuthService{
		LoginFunc: func(ctx context.Context, email, password, ipAddress, userAgent string) (*services.AuthResponse, error) {
			return nil, models.ErrUnauthorized
		},
	}

	handler := handlers.NewAuthHandler(mockAuth, nil, nil)
	req := handlers.NewTestRequest(t, "POST", "/auth/login", handlers.LoginRequest{
		Email:    "user@example.com",
		Password: "wrongpassword",
	})

	w := httptest.NewRecorder()
	handler.Login(w, req)

	handlers.AssertErrorResponse(t, w, 401, "unauthorized")
}

func TestLogin_RateLimitExceeded(t *testing.T) {
	mockAuth := &handlers.MockAuthService{
		LoginFunc: func(ctx context.Context, email, password, ipAddress, userAgent string) (*services.AuthResponse, error) {
			return nil, models.ErrRateLimitExceeded
		},
	}

	handler := handlers.NewAuthHandler(mockAuth, nil, nil)
	req := handlers.NewTestRequest(t, "POST", "/auth/login", handlers.LoginRequest{
		Email:    "user@example.com",
		Password: "password123",
	})

	w := httptest.NewRecorder()
	handler.Login(w, req)

	handlers.AssertErrorResponse(t, w, 429, "rate_limit_exceeded")
}

func TestLogin_AccountStatusErrors_AntiEnumeration(t *testing.T) {
	// Test anti-enumeration: all account status issues return same generic message
	accountErrors := []error{
		models.ErrAccountDisabled,
		models.ErrAccountSuspended,
		models.ErrAccountLocked,
		models.ErrEmailNotVerified,
	}

	for _, accountErr := range accountErrors {
		t.Run("account error: "+accountErr.Error(), func(t *testing.T) {
			mockAuth := &handlers.MockAuthService{
				LoginFunc: func(ctx context.Context, email, password, ipAddress, userAgent string) (*services.AuthResponse, error) {
					return nil, accountErr
				},
			}

			handler := handlers.NewAuthHandler(mockAuth, nil, nil)
			req := handlers.NewTestRequest(t, "POST", "/auth/login", handlers.LoginRequest{
				Email:    "user@example.com",
				Password: "password123",
			})

			w := httptest.NewRecorder()
			handler.Login(w, req)

			handlers.AssertErrorResponse(t, w, 401, "unauthorized")

			var resp pkghttp.ErrorResponse
			json.Unmarshal(w.Body.Bytes(), &resp)
			assert.Equal(t, "Authentication failed", resp.Message)
		})
	}
}

func TestRegister_Success(t *testing.T) {
	mockAuth := &handlers.MockAuthService{
		RegisterFunc: func(ctx context.Context, email, password, name string) (*services.AuthResponse, error) {
			return &services.AuthResponse{
				AccessToken:  "access_token_new",
				RefreshToken: "refresh_token_new",
			}, nil
		},
	}

	handler := handlers.NewAuthHandler(mockAuth, nil, nil)
	req := handlers.NewTestRequest(t, "POST", "/auth/register", handlers.RegisterRequest{
		Email:    "newuser@example.com",
		Password: "securePassword123!",
		Name:     "New User",
	})

	w := httptest.NewRecorder()
	handler.Register(w, req)

	// Should return 202 Accepted with generic message
	assert.Equal(t, 202, w.Code)
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "Registration received")
}

func TestRegister_DuplicateEmail_AntiEnumeration(t *testing.T) {
	// Anti-enumeration: duplicate email returns same response as success
	mockAuth := &handlers.MockAuthService{
		RegisterFunc: func(ctx context.Context, email, password, name string) (*services.AuthResponse, error) {
			return nil, models.ErrConflict
		},
	}

	handler := handlers.NewAuthHandler(mockAuth, nil, nil)
	req := handlers.NewTestRequest(t, "POST", "/auth/register", handlers.RegisterRequest{
		Email:    "existing@example.com",
		Password: "securePassword123!",
		Name:     "User",
	})

	w := httptest.NewRecorder()
	handler.Register(w, req)

	// Should return same 202 Accepted response as success
	assert.Equal(t, 202, w.Code)
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "Registration received")
}

func TestRefreshToken_Success(t *testing.T) {
	mockAuth := &handlers.MockAuthService{
		RefreshTokenFunc: func(ctx context.Context, refreshToken string) (*services.AuthResponse, error) {
			return &services.AuthResponse{
				AccessToken:  "new_access_token",
				RefreshToken: "new_refresh_token",
			}, nil
		},
	}

	handler := handlers.NewAuthHandler(mockAuth, nil, nil)
	req := handlers.NewTestRequest(t, "POST", "/auth/refresh", handlers.RefreshTokenRequest{
		RefreshToken: "refresh_token_123",
	})

	w := httptest.NewRecorder()
	handler.RefreshToken(w, req)

	var resp services.AuthResponse
	handlers.AssertJSONResponse(t, w, 200, &resp)
	assert.Equal(t, "new_access_token", resp.AccessToken)
	assert.Equal(t, "new_refresh_token", resp.RefreshToken)
}

func TestRefreshToken_InvalidToken(t *testing.T) {
	mockAuth := &handlers.MockAuthService{
		RefreshTokenFunc: func(ctx context.Context, refreshToken string) (*services.AuthResponse, error) {
			return nil, models.ErrUnauthorized
		},
	}

	handler := handlers.NewAuthHandler(mockAuth, nil, nil)
	req := handlers.NewTestRequest(t, "POST", "/auth/refresh", handlers.RefreshTokenRequest{
		RefreshToken: "invalid_token",
	})

	w := httptest.NewRecorder()
	handler.RefreshToken(w, req)

	handlers.AssertErrorResponse(t, w, 401, "unauthorized")
}

func TestLogout_Success(t *testing.T) {
	mockAuth := &handlers.MockAuthService{
		LogoutFunc: func(ctx context.Context, accessToken string) error {
			assert.Equal(t, "access_token_123", accessToken)
			return nil
		},
	}

	handler := handlers.NewAuthHandler(mockAuth, nil, nil)
	req := handlers.NewTestRequest(t, "POST", "/auth/logout", nil)
	// Add user claims and token to context (simulates middleware behavior)
	req = addTokenToContext(req, "access_token_123", "user123", "user@example.com")

	w := httptest.NewRecorder()
	handler.Logout(w, req)

	assert.Equal(t, 204, w.Code)
}

// addTokenToContext adds user claims and token to the request context (simulates AuthMiddleware)
func addTokenToContext(r *http.Request, token, userID, email string) *http.Request {
	claims := &models.TokenClaims{
		UserID: userID,
		Email:  email,
		Type:   "access",
	}
	ctx := context.WithValue(r.Context(), auth.UserContextKey, claims)
	ctx = context.WithValue(ctx, auth.TokenContextKey, token)
	return r.WithContext(ctx)
}

func TestLogoutAll_Success(t *testing.T) {
	mockAuth := &handlers.MockAuthService{
		LogoutAllFunc: func(ctx context.Context, userID string) error {
			return nil
		},
	}

	handler := handlers.NewAuthHandler(mockAuth, nil, nil)
	req := handlers.NewTestRequest(t, "POST", "/auth/logout-all", nil)
	req = handlers.WithAuthContext(req, "user123", "user@example.com")

	w := httptest.NewRecorder()
	handler.LogoutAll(w, req)

	assert.Equal(t, 204, w.Code)
}

func TestLogoutAll_Unauthorized(t *testing.T) {
	mockAuth := &handlers.MockAuthService{}
	handler := handlers.NewAuthHandler(mockAuth, nil, nil)
	req := handlers.NewTestRequest(t, "POST", "/auth/logout-all", nil)
	// No auth context

	w := httptest.NewRecorder()
	handler.LogoutAll(w, req)

	handlers.AssertErrorResponse(t, w, 401, "unauthorized")
}

func TestVerifyEmail_Success(t *testing.T) {
	mockAuth := &handlers.MockAuthService{}
	mockEmailVerif := &handlers.MockEmailVerificationService{
		VerifyEmailFunc: func(ctx context.Context, plainToken string) (string, error) {
			return "user123", nil
		},
	}

	handler := handlers.NewAuthHandlerWithEmailVerification(mockAuth, mockEmailVerif, nil, nil)
	req := handlers.NewTestRequest(t, "POST", "/auth/verify-email", handlers.VerifyEmailRequest{
		Token: "verification_token_123",
	})

	w := httptest.NewRecorder()
	handler.VerifyEmail(w, req)

	assert.Equal(t, 200, w.Code)
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "user123", resp["user_id"])
	assert.Contains(t, resp["message"], "Email verified successfully")
}

func TestVerifyEmail_InvalidToken(t *testing.T) {
	mockAuth := &handlers.MockAuthService{}
	mockEmailVerif := &handlers.MockEmailVerificationService{
		VerifyEmailFunc: func(ctx context.Context, plainToken string) (string, error) {
			return "", models.ErrUnauthorized
		},
	}

	handler := handlers.NewAuthHandlerWithEmailVerification(mockAuth, mockEmailVerif, nil, nil)
	req := handlers.NewTestRequest(t, "POST", "/auth/verify-email", handlers.VerifyEmailRequest{
		Token: "invalid_token",
	})

	w := httptest.NewRecorder()
	handler.VerifyEmail(w, req)

	handlers.AssertErrorResponse(t, w, 401, "unauthorized")
}

func TestResendVerification_GenericResponse_AntiEnumeration(t *testing.T) {
	// Anti-enumeration: both valid and invalid emails return same response
	tests := []struct {
		name  string
		email string
		err   error
	}{
		{
			name:  "valid email (exists)",
			email: "existing@example.com",
			err:   nil,
		},
		{
			name:  "invalid email (not found)",
			email: "nonexistent@example.com",
			err:   models.ErrNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockAuth := &handlers.MockAuthService{}
			mockEmailVerif := &handlers.MockEmailVerificationService{
				ResendVerificationFunc: func(ctx context.Context, email string) error {
					return tc.err
				},
			}

			handler := handlers.NewAuthHandlerWithEmailVerification(mockAuth, mockEmailVerif, nil, nil)
			req := handlers.NewTestRequest(t, "POST", "/auth/resend-verification", handlers.ResendVerificationRequest{
				Email: tc.email,
			})

			w := httptest.NewRecorder()
			handler.ResendVerification(w, req)

			// Should always return 202 Accepted with generic message
			assert.Equal(t, 202, w.Code)
			var resp map[string]string
			json.Unmarshal(w.Body.Bytes(), &resp)
			assert.Contains(t, resp["message"], "If an account exists")
		})
	}
}

func TestVerificationStatus_Verified(t *testing.T) {
	mockAuth := &handlers.MockAuthService{}
	mockEmailVerif := &handlers.MockEmailVerificationService{
		GetStatusFunc: func(ctx context.Context, userID string) (bool, error) {
			return true, nil
		},
	}

	handler := handlers.NewAuthHandlerWithEmailVerification(mockAuth, mockEmailVerif, nil, nil)
	req := handlers.NewTestRequest(t, "GET", "/auth/verification-status", nil)
	req = handlers.WithAuthContext(req, "user123", "user@example.com")

	w := httptest.NewRecorder()
	handler.VerificationStatus(w, req)

	var resp handlers.VerificationStatusResponse
	handlers.AssertJSONResponse(t, w, 200, &resp)
	assert.True(t, resp.EmailVerified)
	assert.False(t, resp.VerificationRequired)
}

func TestVerificationStatus_NotVerified(t *testing.T) {
	mockAuth := &handlers.MockAuthService{}
	mockEmailVerif := &handlers.MockEmailVerificationService{
		GetStatusFunc: func(ctx context.Context, userID string) (bool, error) {
			return false, nil
		},
	}

	handler := handlers.NewAuthHandlerWithEmailVerification(mockAuth, mockEmailVerif, nil, nil)
	req := handlers.NewTestRequest(t, "GET", "/auth/verification-status", nil)
	req = handlers.WithAuthContext(req, "user123", "user@example.com")

	w := httptest.NewRecorder()
	handler.VerificationStatus(w, req)

	var resp handlers.VerificationStatusResponse
	handlers.AssertJSONResponse(t, w, 200, &resp)
	assert.False(t, resp.EmailVerified)
	assert.True(t, resp.VerificationRequired)
}

func TestVerificationStatus_Unauthorized(t *testing.T) {
	mockAuth := &handlers.MockAuthService{}
	mockEmailVerif := &handlers.MockEmailVerificationService{}

	handler := handlers.NewAuthHandlerWithEmailVerification(mockAuth, mockEmailVerif, nil, nil)
	req := handlers.NewTestRequest(t, "GET", "/auth/verification-status", nil)
	// No auth context

	w := httptest.NewRecorder()
	handler.VerificationStatus(w, req)

	handlers.AssertErrorResponse(t, w, 401, "unauthorized")
}

// Type assertions to ensure implementations satisfy interfaces
var (
	_ handlers.AuthServiceInterface             = (*handlers.MockAuthService)(nil)
	_ handlers.EmailVerificationServiceInterface = (*handlers.MockEmailVerificationService)(nil)
	_ handlers.UserService                      = (*handlers.MockUserService)(nil)
)
