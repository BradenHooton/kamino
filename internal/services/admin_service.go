package services

import (
	"context"
	"log/slog"
	"time"

	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/internal/repositories"
)

// AdminUserRepository is the subset of UserRepository methods needed by AdminService.
type AdminUserRepository interface {
	CountTotal(ctx context.Context) (int64, error)
	CountByStatus(ctx context.Context, status string) (int64, error)
	CountByRole(ctx context.Context, role string) (int64, error)
	CountMFAEnabled(ctx context.Context) (int64, error)
	CountNewSince(ctx context.Context, since time.Time) (int64, error)
}

// AdminAuditRepository is the subset of AuditLogRepository methods needed by AdminService.
type AdminAuditRepository interface {
	GetRecentByEventType(ctx context.Context, eventType string, limit int) ([]*models.AuditLog, error)
	CountTodayByEventType(ctx context.Context, eventType string) (int64, error)
}

// DashboardStatsResponse contains aggregate admin metrics.
type DashboardStatsResponse struct {
	TotalUsers      int64            `json:"total_users"`
	ActiveUsers     int64            `json:"active_users"`
	SuspendedUsers  int64            `json:"suspended_users"`
	DisabledUsers   int64            `json:"disabled_users"`
	AdminCount      int64            `json:"admin_count"`
	MFAEnabledCount int64            `json:"mfa_enabled_count"`
	NewUsersToday   int64            `json:"new_users_today"`
	RoleBreakdown   map[string]int64 `json:"role_breakdown"`
}

// ActivityEntry is a single item in a recent-activity feed.
type ActivityEntry struct {
	Timestamp string  `json:"timestamp"`
	ActorID   *string `json:"actor_id,omitempty"`
	EventType string  `json:"event_type"`
	Success   bool    `json:"success"`
}

// DashboardActivityResponse contains recent event feeds.
type DashboardActivityResponse struct {
	RecentLogins        []ActivityEntry `json:"recent_logins"`
	RecentRegistrations []ActivityEntry `json:"recent_registrations"`
	FailedLogins        []ActivityEntry `json:"failed_logins"`
}

// AdminService aggregates data for admin dashboard endpoints.
type AdminService struct {
	userRepo  AdminUserRepository
	auditRepo AdminAuditRepository
	logger    *slog.Logger
}

// NewAdminService creates a new AdminService.
func NewAdminService(
	userRepo *repositories.UserRepository,
	auditRepo *repositories.AuditLogRepository,
	logger *slog.Logger,
) *AdminService {
	return &AdminService{
		userRepo:  userRepo,
		auditRepo: auditRepo,
		logger:    logger,
	}
}

// GetDashboardStats returns aggregate user and activity counts.
func (s *AdminService) GetDashboardStats() (*DashboardStatsResponse, error) {
	ctx := context.Background()

	total, err := s.userRepo.CountTotal(ctx)
	if err != nil {
		s.logger.Error("dashboard: failed to count total users", slog.Any("error", err))
		return nil, err
	}

	active, err := s.userRepo.CountByStatus(ctx, "active")
	if err != nil {
		s.logger.Error("dashboard: failed to count active users", slog.Any("error", err))
		return nil, err
	}

	suspended, err := s.userRepo.CountByStatus(ctx, "suspended")
	if err != nil {
		s.logger.Error("dashboard: failed to count suspended users", slog.Any("error", err))
		return nil, err
	}

	disabled, err := s.userRepo.CountByStatus(ctx, "disabled")
	if err != nil {
		s.logger.Error("dashboard: failed to count disabled users", slog.Any("error", err))
		return nil, err
	}

	adminCount, err := s.userRepo.CountByRole(ctx, "admin")
	if err != nil {
		s.logger.Error("dashboard: failed to count admins", slog.Any("error", err))
		return nil, err
	}

	userCount, err := s.userRepo.CountByRole(ctx, "user")
	if err != nil {
		s.logger.Error("dashboard: failed to count regular users", slog.Any("error", err))
		return nil, err
	}

	mfaEnabled, err := s.userRepo.CountMFAEnabled(ctx)
	if err != nil {
		s.logger.Error("dashboard: failed to count mfa-enabled users", slog.Any("error", err))
		return nil, err
	}

	today := time.Now().UTC().Truncate(24 * time.Hour)
	newToday, err := s.userRepo.CountNewSince(ctx, today)
	if err != nil {
		s.logger.Error("dashboard: failed to count new users today", slog.Any("error", err))
		return nil, err
	}

	return &DashboardStatsResponse{
		TotalUsers:      total,
		ActiveUsers:     active,
		SuspendedUsers:  suspended,
		DisabledUsers:   disabled,
		AdminCount:      adminCount,
		MFAEnabledCount: mfaEnabled,
		NewUsersToday:   newToday,
		RoleBreakdown: map[string]int64{
			"admin": adminCount,
			"user":  userCount,
		},
	}, nil
}

// GetRecentActivity returns recent auth event feeds for the activity dashboard.
// limit is clamped to a maximum of 20.
func (s *AdminService) GetRecentActivity(limit int) (*DashboardActivityResponse, error) {
	ctx := context.Background()
	if limit <= 0 || limit > 20 {
		limit = 20
	}

	logins, err := s.auditRepo.GetRecentByEventType(ctx, models.AuditEventTypeLogin, limit)
	if err != nil {
		s.logger.Error("dashboard: failed to fetch recent logins", slog.Any("error", err))
		return nil, err
	}

	registrations, err := s.auditRepo.GetRecentByEventType(ctx, models.AuditEventTypeRegister, limit)
	if err != nil {
		s.logger.Error("dashboard: failed to fetch recent registrations", slog.Any("error", err))
		return nil, err
	}

	// Failed logins: query all recent login entries and filter by success=false
	// We re-use GetRecentByEventType with a larger limit then filter, to avoid a new repo method.
	allLogins, err := s.auditRepo.GetRecentByEventType(ctx, models.AuditEventTypeLogin, limit*3)
	if err != nil {
		s.logger.Error("dashboard: failed to fetch failed logins", slog.Any("error", err))
		return nil, err
	}

	toEntry := func(log *models.AuditLog) ActivityEntry {
		e := ActivityEntry{
			Timestamp: log.CreatedAt.UTC().Format(time.RFC3339),
			EventType: log.EventType,
			Success:   log.Success,
		}
		if log.ActorID != nil {
			id := log.ActorID.String()
			e.ActorID = &id
		}
		return e
	}

	recentLogins := make([]ActivityEntry, 0, len(logins))
	for _, l := range logins {
		recentLogins = append(recentLogins, toEntry(l))
	}

	recentRegistrations := make([]ActivityEntry, 0, len(registrations))
	for _, r := range registrations {
		recentRegistrations = append(recentRegistrations, toEntry(r))
	}

	failedLogins := make([]ActivityEntry, 0, limit)
	for _, l := range allLogins {
		if !l.Success {
			failedLogins = append(failedLogins, toEntry(l))
			if len(failedLogins) >= limit {
				break
			}
		}
	}

	return &DashboardActivityResponse{
		RecentLogins:        recentLogins,
		RecentRegistrations: recentRegistrations,
		FailedLogins:        failedLogins,
	}, nil
}
