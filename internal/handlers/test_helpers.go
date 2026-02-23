package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/internal/services"
	pkghttp "github.com/BradenHooton/kamino/pkg/http"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

// NewTestRequest creates an HTTP request with JSON body for testing
func NewTestRequest(t *testing.T, method, url string, body interface{}) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("failed to encode request body: %v", err)
		}
	}
	req := httptest.NewRequest(method, url, &buf)
	req.Header.Set("Content-Type", "application/json")
	return req
}

// WithAuthContext adds user claims to request context for testing authenticated endpoints
func WithAuthContext(req *http.Request, userID, email string) *http.Request {
	claims := &models.TokenClaims{
		UserID: userID,
		Email:  email,
		Type:   "access",
	}
	ctx := context.WithValue(req.Context(), auth.UserContextKey, claims)
	return req.WithContext(ctx)
}

// WithAdminContext adds admin user claims to request context
func WithAdminContext(req *http.Request, userID, email string) *http.Request {
	claims := &models.TokenClaims{
		UserID: userID,
		Email:  email,
		Type:   "access",
	}
	ctx := context.WithValue(req.Context(), auth.UserContextKey, claims)
	return req.WithContext(ctx)
}

// AssertJSONResponse checks that response has correct status and decodes JSON body
func AssertJSONResponse(t *testing.T, w *httptest.ResponseRecorder, expectedStatus int, target interface{}) {
	assert.Equal(t, expectedStatus, w.Code, "Response status mismatch")

	contentType := w.Header().Get("Content-Type")
	assert.Equal(t, "application/json", contentType, "Content-Type should be application/json")

	if target != nil {
		err := json.Unmarshal(w.Body.Bytes(), target)
		assert.NoError(t, err, "Failed to decode response JSON")
	}
}

// AssertErrorResponse checks that response is a valid error response
func AssertErrorResponse(t *testing.T, w *httptest.ResponseRecorder, expectedStatus int, expectedError string) {
	assert.Equal(t, expectedStatus, w.Code, "Response status mismatch")

	var resp pkghttp.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err, "Failed to decode error response")
	assert.Equal(t, expectedError, resp.Error, "Error code mismatch")
	assert.NotEmpty(t, resp.Message, "Error message should not be empty")
}

// MockAuthService implements AuthServiceInterface for testing
type MockAuthService struct {
	LoginFunc        func(ctx context.Context, email, password, ipAddress, userAgent string) (*services.AuthResponse, error)
	RegisterFunc     func(ctx context.Context, email, password, name string) (*services.AuthResponse, error)
	RefreshTokenFunc func(ctx context.Context, refreshToken string) (*services.AuthResponse, error)
	LogoutFunc       func(ctx context.Context, accessToken string) error
	LogoutAllFunc    func(ctx context.Context, userID string) error
}

// Implement interface methods
func (m *MockAuthService) Login(ctx context.Context, email, password, ipAddress, userAgent string) (*services.AuthResponse, error) {
	if m.LoginFunc == nil {
		return nil, models.ErrUnauthorized
	}
	return m.LoginFunc(ctx, email, password, ipAddress, userAgent)
}

func (m *MockAuthService) Register(ctx context.Context, email, password, name string) (*services.AuthResponse, error) {
	if m.RegisterFunc == nil {
		return nil, models.ErrConflict
	}
	return m.RegisterFunc(ctx, email, password, name)
}

func (m *MockAuthService) RefreshToken(ctx context.Context, refreshToken string) (*services.AuthResponse, error) {
	if m.RefreshTokenFunc == nil {
		return nil, models.ErrUnauthorized
	}
	return m.RefreshTokenFunc(ctx, refreshToken)
}

func (m *MockAuthService) Logout(ctx context.Context, accessToken string) error {
	if m.LogoutFunc == nil {
		return nil
	}
	return m.LogoutFunc(ctx, accessToken)
}

func (m *MockAuthService) LogoutAll(ctx context.Context, userID string) error {
	if m.LogoutAllFunc == nil {
		return nil
	}
	return m.LogoutAllFunc(ctx, userID)
}

// MockEmailVerificationService for testing
type MockEmailVerificationService struct {
	SendVerificationEmailFunc func(ctx context.Context, userID, email string) error
	VerifyEmailFunc           func(ctx context.Context, plainToken string) (string, error)
	ResendVerificationFunc    func(ctx context.Context, email string) error
	GetStatusFunc             func(ctx context.Context, userID string) (bool, error)
}

func (m *MockEmailVerificationService) SendVerificationEmail(ctx context.Context, userID, email string) error {
	if m.SendVerificationEmailFunc == nil {
		return nil
	}
	return m.SendVerificationEmailFunc(ctx, userID, email)
}

func (m *MockEmailVerificationService) VerifyEmail(ctx context.Context, plainToken string) (string, error) {
	if m.VerifyEmailFunc == nil {
		return "", models.ErrUnauthorized
	}
	return m.VerifyEmailFunc(ctx, plainToken)
}

func (m *MockEmailVerificationService) ResendVerification(ctx context.Context, email string) error {
	if m.ResendVerificationFunc == nil {
		return nil
	}
	return m.ResendVerificationFunc(ctx, email)
}

func (m *MockEmailVerificationService) GetStatus(ctx context.Context, userID string) (bool, error) {
	if m.GetStatusFunc == nil {
		return false, nil
	}
	return m.GetStatusFunc(ctx, userID)
}

// MockUserService implements UserService for testing
type MockUserService struct {
	GetUserByIDFunc      func(id string) (*models.User, error)
	ListUsersFunc        func(limit, offset int) ([]*models.User, error)
	CreateUserFunc       func(user *models.User, password string) (*models.User, error)
	UpdateUserFunc       func(id string, user *models.User) (*models.User, error)
	DeleteUserFunc       func(id string) error
	UpdateUserStatusFunc func(id, status, reason, actorID string) error
	LockUserFunc         func(id string, duration time.Duration, reason, actorID string) error
	SearchUsersFunc      func(criteria models.SearchCriteria) ([]*models.User, int64, error)
}

func (m *MockUserService) GetUserByID(id string) (*models.User, error) {
	if m.GetUserByIDFunc == nil {
		return nil, models.ErrNotFound
	}
	return m.GetUserByIDFunc(id)
}

func (m *MockUserService) ListUsers(limit, offset int) ([]*models.User, error) {
	if m.ListUsersFunc == nil {
		return []*models.User{}, nil
	}
	return m.ListUsersFunc(limit, offset)
}

func (m *MockUserService) CreateUser(user *models.User, password string) (*models.User, error) {
	if m.CreateUserFunc == nil {
		return nil, models.ErrConflict
	}
	return m.CreateUserFunc(user, password)
}

func (m *MockUserService) UpdateUser(id string, user *models.User) (*models.User, error) {
	if m.UpdateUserFunc == nil {
		return nil, models.ErrNotFound
	}
	return m.UpdateUserFunc(id, user)
}

func (m *MockUserService) DeleteUser(id string) error {
	if m.DeleteUserFunc == nil {
		return nil
	}
	return m.DeleteUserFunc(id)
}

func (m *MockUserService) UpdateUserStatus(id, status, reason, actorID string) error {
	if m.UpdateUserStatusFunc == nil {
		return nil
	}
	return m.UpdateUserStatusFunc(id, status, reason, actorID)
}

func (m *MockUserService) LockUser(id string, duration time.Duration, reason, actorID string) error {
	if m.LockUserFunc == nil {
		return nil
	}
	return m.LockUserFunc(id, duration, reason, actorID)
}

func (m *MockUserService) SearchUsers(criteria models.SearchCriteria) ([]*models.User, int64, error) {
	if m.SearchUsersFunc == nil {
		return []*models.User{}, 0, nil
	}
	return m.SearchUsersFunc(criteria)
}

// WithChiRouteContext adds chi URL parameters to request context for testing
// This helper allows tests to set URL parameters that would normally be extracted
// by the Chi router from the URL path.
//
// Example usage:
//
//	req := httptest.NewRequest("PUT", "/users/user123", body)
//	req = WithChiRouteContext(req, map[string]string{
//	    "id": "user123",
//	})
func WithChiRouteContext(r *http.Request, params map[string]string) *http.Request {
	rctx := chi.NewRouteContext()
	for key, value := range params {
		rctx.URLParams.Add(key, value)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// WithChiIDFromURL extracts the ID from a URL path and sets it as a chi route parameter
// This is useful for testing endpoints like /users/{id} without manually parsing the URL
//
// Example usage:
//
//	req := httptest.NewRequest("GET", "/users/user123", nil)
//	req = WithChiIDFromURL(req)  // Automatically extracts "user123" and sets as "id" param
func WithChiIDFromURL(r *http.Request) *http.Request {
	// Extract ID from URL path (e.g., /users/user123 -> "user123")
	path := r.URL.Path
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")

	// If path has at least 2 parts (e.g., ["users", "user123"]), use the last part as ID
	if len(parts) >= 2 {
		id := parts[len(parts)-1]
		return WithChiRouteContext(r, map[string]string{
			"id": id,
		})
	}

	return r
}
