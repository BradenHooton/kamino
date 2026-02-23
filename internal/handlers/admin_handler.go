package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/BradenHooton/kamino/internal/services"
	pkghttp "github.com/BradenHooton/kamino/pkg/http"
)

// AdminServiceInterface defines the dashboard service contract.
type AdminServiceInterface interface {
	GetDashboardStats() (*services.DashboardStatsResponse, error)
	GetRecentActivity(limit int) (*services.DashboardActivityResponse, error)
}

// AdminHandler handles admin dashboard HTTP requests.
type AdminHandler struct {
	service AdminServiceInterface
}

// NewAdminHandler creates a new AdminHandler.
func NewAdminHandler(service AdminServiceInterface) *AdminHandler {
	return &AdminHandler{service: service}
}

// GetDashboardStats handles GET /admin/dashboard/stats
func (h *AdminHandler) GetDashboardStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.service.GetDashboardStats()
	if err != nil {
		pkghttp.WriteInternalError(w, "Failed to retrieve dashboard stats")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// GetRecentActivity handles GET /admin/dashboard/activity
// Accepts optional query param ?limit=N (1–20, default 20).
func (h *AdminHandler) GetRecentActivity(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 20 {
			limit = n
		}
	}

	activity, err := h.service.GetRecentActivity(limit)
	if err != nil {
		pkghttp.WriteInternalError(w, "Failed to retrieve recent activity")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(activity)
}
