package handlers_test

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/BradenHooton/kamino/internal/handlers"
	"github.com/BradenHooton/kamino/internal/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAdminService implements handlers.AdminServiceInterface for testing
type mockAdminService struct {
	GetDashboardStatsFunc func() (*services.DashboardStatsResponse, error)
	GetRecentActivityFunc func(limit int) (*services.DashboardActivityResponse, error)
}

func (m *mockAdminService) GetDashboardStats() (*services.DashboardStatsResponse, error) {
	if m.GetDashboardStatsFunc == nil {
		return &services.DashboardStatsResponse{}, nil
	}
	return m.GetDashboardStatsFunc()
}

func (m *mockAdminService) GetRecentActivity(limit int) (*services.DashboardActivityResponse, error) {
	if m.GetRecentActivityFunc == nil {
		return &services.DashboardActivityResponse{
			RecentLogins:        []services.ActivityEntry{},
			RecentRegistrations: []services.ActivityEntry{},
			FailedLogins:        []services.ActivityEntry{},
		}, nil
	}
	return m.GetRecentActivityFunc(limit)
}

// ── GetDashboardStats ─────────────────────────────────────────────────────────

func TestGetDashboardStats_Success_Returns200(t *testing.T) {
	mock := &mockAdminService{
		GetDashboardStatsFunc: func() (*services.DashboardStatsResponse, error) {
			return &services.DashboardStatsResponse{
				TotalUsers:      100,
				ActiveUsers:     80,
				SuspendedUsers:  15,
				DisabledUsers:   5,
				AdminCount:      3,
				MFAEnabledCount: 60,
				NewUsersToday:   7,
				RoleBreakdown:   map[string]int64{"admin": 3, "user": 97},
			}, nil
		},
	}
	h := handlers.NewAdminHandler(mock)

	req := httptest.NewRequest("GET", "/admin/dashboard/stats", nil)
	w := httptest.NewRecorder()
	h.GetDashboardStats(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp services.DashboardStatsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(100), resp.TotalUsers)
	assert.Equal(t, int64(80), resp.ActiveUsers)
	assert.Equal(t, int64(3), resp.AdminCount)
}

func TestGetDashboardStats_ServiceError_Returns500(t *testing.T) {
	mock := &mockAdminService{
		GetDashboardStatsFunc: func() (*services.DashboardStatsResponse, error) {
			return nil, errors.New("database connection lost")
		},
	}
	h := handlers.NewAdminHandler(mock)

	req := httptest.NewRequest("GET", "/admin/dashboard/stats", nil)
	w := httptest.NewRecorder()
	h.GetDashboardStats(w, req)

	handlers.AssertErrorResponse(t, w, 500, "internal_error")
}

// ── GetRecentActivity ─────────────────────────────────────────────────────────

func TestGetRecentActivity_Success_Returns200(t *testing.T) {
	mock := &mockAdminService{
		GetRecentActivityFunc: func(limit int) (*services.DashboardActivityResponse, error) {
			assert.Equal(t, 20, limit) // default
			return &services.DashboardActivityResponse{
				RecentLogins:        []services.ActivityEntry{{Timestamp: "2026-02-22T10:00:00Z", EventType: "login", Success: true}},
				RecentRegistrations: []services.ActivityEntry{},
				FailedLogins:        []services.ActivityEntry{},
			}, nil
		},
	}
	h := handlers.NewAdminHandler(mock)

	req := httptest.NewRequest("GET", "/admin/dashboard/activity", nil)
	w := httptest.NewRecorder()
	h.GetRecentActivity(w, req)

	assert.Equal(t, 200, w.Code)
	var resp services.DashboardActivityResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.RecentLogins, 1)
}

func TestGetRecentActivity_CustomLimit_Returns200(t *testing.T) {
	mock := &mockAdminService{
		GetRecentActivityFunc: func(limit int) (*services.DashboardActivityResponse, error) {
			assert.Equal(t, 5, limit)
			return &services.DashboardActivityResponse{
				RecentLogins:        []services.ActivityEntry{},
				RecentRegistrations: []services.ActivityEntry{},
				FailedLogins:        []services.ActivityEntry{},
			}, nil
		},
	}
	h := handlers.NewAdminHandler(mock)

	req := httptest.NewRequest("GET", "/admin/dashboard/activity?limit=5", nil)
	w := httptest.NewRecorder()
	h.GetRecentActivity(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestGetRecentActivity_ServiceError_Returns500(t *testing.T) {
	mock := &mockAdminService{
		GetRecentActivityFunc: func(limit int) (*services.DashboardActivityResponse, error) {
			return nil, errors.New("query timeout")
		},
	}
	h := handlers.NewAdminHandler(mock)

	req := httptest.NewRequest("GET", "/admin/dashboard/activity", nil)
	w := httptest.NewRecorder()
	h.GetRecentActivity(w, req)

	handlers.AssertErrorResponse(t, w, 500, "internal_error")
}
