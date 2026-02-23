package handlers_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BradenHooton/kamino/internal/handlers"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── UpdateUserStatus tests ────────────────────────────────────────────────────

func TestUpdateUserStatus_Suspend_Success(t *testing.T) {
	called := false
	mock := &handlers.MockUserService{
		UpdateUserStatusFunc: func(id, status, reason, actorID string) error {
			called = true
			assert.Equal(t, "user123", id)
			assert.Equal(t, "suspended", status)
			assert.Equal(t, "admin001", actorID)
			return nil
		},
	}
	h := handlers.NewUserHandler(mock)

	req := handlers.NewTestRequest(t, "PATCH", "/users/user123/status", handlers.UpdateUserStatusRequest{
		Status: "suspended",
		Reason: "Violated terms of service",
	})
	req = handlers.WithAuthContext(req, "admin001", "admin@example.com")
	req = handlers.WithChiRouteContext(req, map[string]string{"id": "user123"})

	w := httptest.NewRecorder()
	h.UpdateUserStatus(w, req)

	assert.Equal(t, 204, w.Code)
	assert.True(t, called, "UpdateUserStatus service method should be called")
}

func TestUpdateUserStatus_Activate_Success(t *testing.T) {
	mock := &handlers.MockUserService{
		UpdateUserStatusFunc: func(id, status, reason, actorID string) error {
			assert.Equal(t, "active", status)
			return nil
		},
	}
	h := handlers.NewUserHandler(mock)

	req := handlers.NewTestRequest(t, "PATCH", "/users/user123/status", handlers.UpdateUserStatusRequest{
		Status: "active",
		Reason: "Account review completed successfully",
	})
	req = handlers.WithAuthContext(req, "admin001", "admin@example.com")
	req = handlers.WithChiRouteContext(req, map[string]string{"id": "user123"})

	w := httptest.NewRecorder()
	h.UpdateUserStatus(w, req)

	assert.Equal(t, 204, w.Code)
}

func TestUpdateUserStatus_Disable_Success(t *testing.T) {
	mock := &handlers.MockUserService{
		UpdateUserStatusFunc: func(id, status, reason, actorID string) error {
			assert.Equal(t, "disabled", status)
			return nil
		},
	}
	h := handlers.NewUserHandler(mock)

	req := handlers.NewTestRequest(t, "PATCH", "/users/user123/status", handlers.UpdateUserStatusRequest{
		Status: "disabled",
		Reason: "Account permanently disabled by policy",
	})
	req = handlers.WithAuthContext(req, "admin001", "admin@example.com")
	req = handlers.WithChiRouteContext(req, map[string]string{"id": "user123"})

	w := httptest.NewRecorder()
	h.UpdateUserStatus(w, req)

	assert.Equal(t, 204, w.Code)
}

func TestUpdateUserStatus_SelfModification_Returns403(t *testing.T) {
	mock := &handlers.MockUserService{
		UpdateUserStatusFunc: func(id, status, reason, actorID string) error {
			return models.ErrForbidden
		},
	}
	h := handlers.NewUserHandler(mock)

	req := handlers.NewTestRequest(t, "PATCH", "/users/admin001/status", handlers.UpdateUserStatusRequest{
		Status: "suspended",
		Reason: "Trying to suspend myself",
	})
	req = handlers.WithAuthContext(req, "admin001", "admin@example.com")
	req = handlers.WithChiRouteContext(req, map[string]string{"id": "admin001"})

	w := httptest.NewRecorder()
	h.UpdateUserStatus(w, req)

	handlers.AssertErrorResponse(t, w, 403, "forbidden")
}

func TestUpdateUserStatus_UserNotFound_Returns404(t *testing.T) {
	mock := &handlers.MockUserService{
		UpdateUserStatusFunc: func(id, status, reason, actorID string) error {
			return models.ErrNotFound
		},
	}
	h := handlers.NewUserHandler(mock)

	req := handlers.NewTestRequest(t, "PATCH", "/users/nonexistent/status", handlers.UpdateUserStatusRequest{
		Status: "suspended",
		Reason: "User does not exist in the system",
	})
	req = handlers.WithAuthContext(req, "admin001", "admin@example.com")
	req = handlers.WithChiRouteContext(req, map[string]string{"id": "nonexistent"})

	w := httptest.NewRecorder()
	h.UpdateUserStatus(w, req)

	handlers.AssertErrorResponse(t, w, 404, "not_found")
}

func TestUpdateUserStatus_InvalidStatus_Returns400(t *testing.T) {
	h := handlers.NewUserHandler(&handlers.MockUserService{})

	req := handlers.NewTestRequest(t, "PATCH", "/users/user123/status", handlers.UpdateUserStatusRequest{
		Status: "banned", // not in oneof=active suspended disabled
		Reason: "Invalid status value test",
	})
	req = handlers.WithAuthContext(req, "admin001", "admin@example.com")
	req = handlers.WithChiRouteContext(req, map[string]string{"id": "user123"})

	w := httptest.NewRecorder()
	h.UpdateUserStatus(w, req)

	handlers.AssertErrorResponse(t, w, 400, "bad_request")
}

func TestUpdateUserStatus_ReasonTooShort_Returns400(t *testing.T) {
	h := handlers.NewUserHandler(&handlers.MockUserService{})

	req := handlers.NewTestRequest(t, "PATCH", "/users/user123/status", handlers.UpdateUserStatusRequest{
		Status: "suspended",
		Reason: "short", // less than 10 chars
	})
	req = handlers.WithAuthContext(req, "admin001", "admin@example.com")
	req = handlers.WithChiRouteContext(req, map[string]string{"id": "user123"})

	w := httptest.NewRecorder()
	h.UpdateUserStatus(w, req)

	handlers.AssertErrorResponse(t, w, 400, "bad_request")
}

func TestUpdateUserStatus_NoAuthContext_Returns401(t *testing.T) {
	h := handlers.NewUserHandler(&handlers.MockUserService{})

	req := handlers.NewTestRequest(t, "PATCH", "/users/user123/status", handlers.UpdateUserStatusRequest{
		Status: "suspended",
		Reason: "No auth context provided here",
	})
	req = handlers.WithChiRouteContext(req, map[string]string{"id": "user123"})
	// Deliberately no WithAuthContext call

	w := httptest.NewRecorder()
	h.UpdateUserStatus(w, req)

	handlers.AssertErrorResponse(t, w, 401, "unauthorized")
}

// ── LockUser tests ────────────────────────────────────────────────────────────

func TestLockUser_Success(t *testing.T) {
	called := false
	mock := &handlers.MockUserService{
		LockUserFunc: func(id string, duration time.Duration, reason, actorID string) error {
			called = true
			assert.Equal(t, "user123", id)
			assert.Equal(t, 3600*time.Second, duration)
			assert.Equal(t, "admin001", actorID)
			return nil
		},
	}
	h := handlers.NewUserHandler(mock)

	req := handlers.NewTestRequest(t, "PATCH", "/users/user123/lock", handlers.LockUserRequest{
		DurationSeconds: 3600,
		Reason:          "Suspicious login activity detected",
	})
	req = handlers.WithAuthContext(req, "admin001", "admin@example.com")
	req = handlers.WithChiRouteContext(req, map[string]string{"id": "user123"})

	w := httptest.NewRecorder()
	h.LockUser(w, req)

	assert.Equal(t, 204, w.Code)
	assert.True(t, called)
}

func TestLockUser_DurationTooShort_Returns400(t *testing.T) {
	h := handlers.NewUserHandler(&handlers.MockUserService{})

	req := handlers.NewTestRequest(t, "PATCH", "/users/user123/lock", handlers.LockUserRequest{
		DurationSeconds: 60, // less than 300
		Reason:          "Duration too short for lock operation",
	})
	req = handlers.WithAuthContext(req, "admin001", "admin@example.com")
	req = handlers.WithChiRouteContext(req, map[string]string{"id": "user123"})

	w := httptest.NewRecorder()
	h.LockUser(w, req)

	handlers.AssertErrorResponse(t, w, 400, "bad_request")
}

func TestLockUser_DurationTooLong_Returns400(t *testing.T) {
	h := handlers.NewUserHandler(&handlers.MockUserService{})

	req := handlers.NewTestRequest(t, "PATCH", "/users/user123/lock", handlers.LockUserRequest{
		DurationSeconds: 90000, // greater than 86400
		Reason:          "Duration too long for lock operation test",
	})
	req = handlers.WithAuthContext(req, "admin001", "admin@example.com")
	req = handlers.WithChiRouteContext(req, map[string]string{"id": "user123"})

	w := httptest.NewRecorder()
	h.LockUser(w, req)

	handlers.AssertErrorResponse(t, w, 400, "bad_request")
}

func TestLockUser_SelfLock_Returns403(t *testing.T) {
	mock := &handlers.MockUserService{
		LockUserFunc: func(id string, duration time.Duration, reason, actorID string) error {
			return models.ErrForbidden
		},
	}
	h := handlers.NewUserHandler(mock)

	req := handlers.NewTestRequest(t, "PATCH", "/users/admin001/lock", handlers.LockUserRequest{
		DurationSeconds: 3600,
		Reason:          "Attempting to lock own account",
	})
	req = handlers.WithAuthContext(req, "admin001", "admin@example.com")
	req = handlers.WithChiRouteContext(req, map[string]string{"id": "admin001"})

	w := httptest.NewRecorder()
	h.LockUser(w, req)

	handlers.AssertErrorResponse(t, w, 403, "forbidden")
}

// ── SearchUsers tests ─────────────────────────────────────────────────────────

func TestSearchUsers_ByEmail_Returns200(t *testing.T) {
	email := "alice"
	mock := &handlers.MockUserService{
		SearchUsersFunc: func(criteria models.SearchCriteria) ([]*models.User, int64, error) {
			require.NotNil(t, criteria.Email)
			assert.Equal(t, "alice", *criteria.Email)
			return []*models.User{
				{ID: "u1", Email: "alice@example.com", Name: "Alice"},
			}, 1, nil
		},
	}
	h := handlers.NewUserHandler(mock)

	req := handlers.NewTestRequest(t, "POST", "/users/search", handlers.SearchUsersRequest{
		Email: &email,
	})
	req = handlers.WithAuthContext(req, "admin001", "admin@example.com")

	w := httptest.NewRecorder()
	h.SearchUsers(w, req)

	assert.Equal(t, 200, w.Code)
	var resp handlers.SearchUsersResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(1), resp.Total)
	assert.Len(t, resp.Users, 1)
}

func TestSearchUsers_EmptyBody_ReturnsAll(t *testing.T) {
	mock := &handlers.MockUserService{
		SearchUsersFunc: func(criteria models.SearchCriteria) ([]*models.User, int64, error) {
			// No filters applied
			assert.Nil(t, criteria.Email)
			assert.Nil(t, criteria.Role)
			return []*models.User{}, 0, nil
		},
	}
	h := handlers.NewUserHandler(mock)

	req := handlers.NewTestRequest(t, "POST", "/users/search", handlers.SearchUsersRequest{})
	req = handlers.WithAuthContext(req, "admin001", "admin@example.com")

	w := httptest.NewRecorder()
	h.SearchUsers(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestSearchUsers_InvalidRole_Returns400(t *testing.T) {
	role := "superuser" // not in oneof=user admin
	h := handlers.NewUserHandler(&handlers.MockUserService{})

	req := handlers.NewTestRequest(t, "POST", "/users/search", handlers.SearchUsersRequest{
		Role: &role,
	})
	req = handlers.WithAuthContext(req, "admin001", "admin@example.com")

	w := httptest.NewRecorder()
	h.SearchUsers(w, req)

	handlers.AssertErrorResponse(t, w, 400, "bad_request")
}

func TestSearchUsers_LimitExceeded_Returns400(t *testing.T) {
	h := handlers.NewUserHandler(&handlers.MockUserService{})

	req := handlers.NewTestRequest(t, "POST", "/users/search", handlers.SearchUsersRequest{
		Limit: 200, // exceeds max of 100
	})
	req = handlers.WithAuthContext(req, "admin001", "admin@example.com")

	w := httptest.NewRecorder()
	h.SearchUsers(w, req)

	handlers.AssertErrorResponse(t, w, 400, "bad_request")
}

func TestSearchUsers_Pagination_Returns200(t *testing.T) {
	mock := &handlers.MockUserService{
		SearchUsersFunc: func(criteria models.SearchCriteria) ([]*models.User, int64, error) {
			assert.Equal(t, 10, criteria.Limit)
			assert.Equal(t, 20, criteria.Offset)
			return []*models.User{}, 50, nil
		},
	}
	h := handlers.NewUserHandler(mock)

	req := handlers.NewTestRequest(t, "POST", "/users/search", handlers.SearchUsersRequest{
		Limit:  10,
		Offset: 20,
	})
	req = handlers.WithAuthContext(req, "admin001", "admin@example.com")

	w := httptest.NewRecorder()
	h.SearchUsers(w, req)

	assert.Equal(t, 200, w.Code)
	var resp handlers.SearchUsersResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(50), resp.Total)
	assert.Equal(t, 10, resp.Limit)
	assert.Equal(t, 20, resp.Offset)
}
