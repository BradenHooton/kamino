
Kamino Admin Panel - Implementation Plan                                                        │                                                                                        Context                                                                                         │
│                                                                                               │
│ The Kamino backend currently has foundational admin capabilities (user CRUD, audit logging, MFA │
│  recovery, API key management) but lacks a comprehensive admin panel for day-to-day operations. │
│  Key gaps include:                                                                              │
│                                                                                                 │
│ - No user suspension/lock capabilities - fields exist in DB but no handlers                     │
│ - No dashboard metrics - total users, active sessions, failed logins, MFA adoption              │
│ - No session management - admins cannot view/revoke user sessions                               │
│ - No search/filter - ListUsers only supports pagination, not email/name search                  │
│ - No bulk operations - manual one-by-one user management                                        │
│ - No export functionality - audit logs trapped in database                                      │
│                                                                                                 │
│ This plan outlines a phased approach to build a production-ready admin panel that follows       │
│ existing Kamino patterns (clean architecture, interface-based dependencies, Chi router,         │
│ scope-based RBAC, comprehensive audit logging).                                                 │
│                                                                                                 │
│ ---                                                                                             │
│ Architecture Decision: Integrated API (Not Separate Service)                                    │
│                                                                                                 │
│ Recommendation: Extend the existing API with dedicated admin endpoints rather than creating a   │
│ separate microservice.                                                                          │
│                                                                                                 │
│ Rationale:                                                                                      │
│ - Existing RBAC infrastructure (RequireRole(userRepo, "admin") middleware)                      │
│ - Shared database, authentication, audit logging                                                │
│ - Simpler deployment (single binary, consistent with cmd/api/main.go)                           │
│ - Easier testing and development                                                                │
│ - Existing scope system already supports admin-only scopes (users.delete, audit.read,           │
│ mfa.admin)                                                                                      │
│                                                                                                 │
│ Pattern:                                                                                        │
│ internal/                                                                                       │
│ ├── handlers/                                                                                   │
│ │   ├── admin_handler.go     # NEW: Dashboard metrics, bulk operations                          │
│ │   ├── users.go             # EXTEND: Suspension, lock, search handlers                        │
│ │   ├── audit.go             # EXTEND: Export functionality                                     │
│ │   └── session_handler.go   # NEW: Session management                                          │
│ ├── services/                                                                                   │
│ │   ├── admin_service.go     # NEW: Metrics aggregation, bulk ops                               │
│ │   ├── user_service.go      # EXTEND: Suspension, search, filters                              │
│ │   └── session_service.go   # NEW: Session management                                          │
│ ├── repositories/                                                                               │
│ │   └── user_repo.go         # EXTEND: Search queries, bulk ops, stats                          │
│                                                                                                 │
│ ---                                                                                             │
│ Frontend Strategy                                                                               │
│                                                                                                 │
│ Phase 1 (MVP): Headless REST API only                                                           │
│ - Validates API design before UI investment                                                     │
│ - Enables automation (scripts, CI/CD)                                                           │
│ - Admin operations via API clients (Postman, curl)                                              │
│                                                                                                 │
│ Phase 2 (Optional): React SPA (separate repository)                                             │
│ - Modern dashboard with TanStack Query                                                          │
│ - CORS-protected API access                                                                     │
│ - Deploy to CDN (S3 + CloudFront)                                                               │
│                                                                                                 │
│ Phase 3 (Alternative): Server-side templates (html/template or templ)                           │
│ - Lighter than SPA                                                                              │
│ - Serve from /admin/* routes in Chi                                                             │
│ - Session-based auth (cookies)                                                                  │
│                                                                                                 │
│ Recommendation: Start with Phase 1 (headless API), defer UI decision until API is validated.    │
│                                                                                                 │
│ ---                                                                                             │
│ Phased Implementation                                                                           │
│                                                                                                 │
│ Phase 1: User Management Extensions (Week 1-2)                                                  │
│                                                                                                 │
│ Goal: Complete user suspension/lock/search functionality                                        │
│                                                                                                 │
│ New Endpoints:                                                                                  │
│ PATCH /users/{id}/status         # Suspend/activate account                                     │
│ PATCH /users/{id}/lock           # Temporary account lock                                       │
│ POST  /users/search              # Advanced search (email, name, role, status)                  │
│ GET   /users?status=suspended    # Filter by status                                             │
│                                                                                                 │
│ Request/Response DTOs:                                                                          │
│ type UpdateUserStatusRequest struct {                                                           │
│     Status string `json:"status" validate:"required,oneof=active suspended disabled"`           │
│     Reason string `json:"reason" validate:"required,min=10,max=500"` // For audit trail         │
│ }                                                                                               │
│                                                                                                 │
│ type LockUserRequest struct {                                                                   │
│     Duration time.Duration `json:"duration" validate:"required,min=5m,max=24h"`                 │
│     Reason   string        `json:"reason" validate:"required,min=10,max=500"`                   │
│ }                                                                                               │
│                                                                                                 │
│ type SearchUsersRequest struct {                                                                │
│     Email  *string `json:"email"`                                                               │
│     Name   *string `json:"name"`                                                                │
│     Role   *string `json:"role"`                                                                │
│     Status *string `json:"status"`                                                              │
│     Limit  int     `json:"limit" validate:"min=1,max=100"`                                      │
│     Offset int     `json:"offset" validate:"min=0"`                                             │
│ }                                                                                               │
│                                                                                                 │
│ Service Layer Changes:                                                                          │
│ // internal/services/user_service.go - EXTEND                                                   │
│ func (s *UserService) SuspendUser(id string, reason string) error                               │
│ func (s *UserService) ActivateUser(id string, reason string) error                              │
│ func (s *UserService) LockUser(id string, duration time.Duration, reason string) error          │
│ func (s *UserService) SearchUsers(criteria SearchCriteria) ([]*models.User, int64, error)       │
│                                                                                                 │
│ Repository Layer Changes:                                                                       │
│ // internal/repositories/user_repo.go - EXTEND interface                                        │
│ UpdateStatus(ctx context.Context, id string, status string) error                               │
│ LockAccount(ctx context.Context, id string, lockedUntil time.Time) error                        │
│ Search(ctx context.Context, criteria SearchCriteria) ([]*models.User, int64, error)             │
│                                                                                                 │
│ Database Migration:                                                                             │
│ -- migrations/013_user_search_indexes.sql                                                       │
│ CREATE EXTENSION IF NOT EXISTS pg_trgm;                                                         │
│ CREATE INDEX idx_users_email_trgm ON users USING gin(email gin_trgm_ops);                       │
│ CREATE INDEX idx_users_name_trgm ON users USING gin(name gin_trgm_ops);                         │
│ CREATE INDEX idx_users_status_role_created ON users(status, role, created_at DESC);             │
│                                                                                                 │
│ Audit Logging:                                                                                  │
│ - Log all operations to audit_logs table                                                        │
│ - Event types: user_suspended, user_activated, user_locked                                      │
│ - Include: actor_id, target_id, reason in metadata                                              │
│                                                                                                 │
│ Files to Modify:                                                                                │
│ - internal/services/user_service.go (add 4 methods)                                             │
│ - internal/repositories/user_repo.go (extend interface + impl)                                  │
│ - internal/handlers/users.go (add 3 handlers)                                                   │
│ - internal/routes/routes.go (register new routes in admin group)                                │
│ - migrations/013_user_search_indexes.sql (NEW)                                                  │
│ - migrations/014_audit_user_actions.sql (NEW - add event types)                                 │
│                                                                                                 │
│ Deliverables:                                                                                   │
│ - 4 new endpoints                                                                               │
│ - Full audit trail for all operations                                                           │
│ - 15+ integration tests                                                                         │
│                                                                                                 │
│ ---                                                                                             │
│ Phase 2: Dashboard Metrics (Week 3)                                                             │
│                                                                                                 │
│ Goal: Real-time admin dashboard metrics                                                         │
│                                                                                                 │
│ New Endpoints:                                                                                  │
│ GET /admin/dashboard/stats       # High-level metrics                                           │
│ GET /admin/dashboard/activity    # Recent activity (logins, registrations)                      │
│                                                                                                 │
│ Response DTOs:                                                                                  │
│ type DashboardStatsResponse struct {                                                            │
│     TotalUsers        int64            `json:"total_users"`                                     │
│     ActiveUsers       int64            `json:"active_users"`        // Last 30 days             │
│     SuspendedUsers    int64            `json:"suspended_users"`                                 │
│     NewUsersToday     int64            `json:"new_users_today"`                                 │
│     NewUsersThisWeek  int64            `json:"new_users_this_week"`                             │
│     ActiveSessions    int64            `json:"active_sessions"`     // Non-revoked tokens       │
│     FailedLoginsToday int64            `json:"failed_logins_today"`                             │
│     APIKeysActive     int64            `json:"api_keys_active"`                                 │
│     MFAEnabledCount   int64            `json:"mfa_enabled_count"`                               │
│     RoleBreakdown     map[string]int64 `json:"role_breakdown"`                                  │
│ }                                                                                               │
│                                                                                                 │
│ type ActivityLogEntry struct {                                                                  │
│     Timestamp time.Time `json:"timestamp"`                                                      │
│     EventType string    `json:"event_type"`                                                     │
│     UserEmail string    `json:"user_email"`                                                     │
│     IPAddress string    `json:"ip_address"`                                                     │
│     Success   bool      `json:"success"`                                                        │
│ }                                                                                               │
│                                                                                                 │
│ type DashboardActivityResponse struct {                                                         │
│     RecentLogins        []ActivityLogEntry `json:"recent_logins"`                               │
│     RecentRegistrations []ActivityLogEntry `json:"recent_registrations"`                        │
│     FailedAttempts      []ActivityLogEntry `json:"failed_attempts"`                             │
│ }                                                                                               │
│                                                                                                 │
│ Service Layer:                                                                                  │
│ // internal/services/admin_service.go - NEW FILE                                                │
│ type AdminService struct {                                                                      │
│     userRepo          UserRepository                                                            │
│     auditRepo         AuditLogRepository                                                        │
│     apiKeyRepo        APIKeyRepository                                                          │
│     tokenRevokeRepo   TokenRevocationRepository                                                 │
│     logger            *slog.Logger                                                              │
│ }                                                                                               │
│                                                                                                 │
│ func (s *AdminService) GetDashboardStats() (*DashboardStatsResponse, error)                     │
│ func (s *AdminService) GetRecentActivity(limit int) (*DashboardActivityResponse, error)         │
│                                                                                                 │
│ Repository Extensions:                                                                          │
│ // internal/repositories/user_repo.go - EXTEND                                                  │
│ CountByStatus(ctx context.Context, status string) (int64, error)                                │
│ CountByRole(ctx context.Context, role string) (int64, error)                                    │
│ CountActiveUsers(ctx context.Context, sinceDays int) (int64, error)                             │
│ CountMFAEnabled(ctx context.Context) (int64, error)                                             │
│                                                                                                 │
│ // internal/repositories/audit_log_repo.go - EXTEND                                             │
│ GetRecentByEventType(ctx context.Context, eventType string, limit int) ([]*models.AuditLog,     │
│ error)                                                                                          │
│ CountTodayByEventType(ctx context.Context, eventType string) (int64, error)                     │
│                                                                                                 │
│ Performance Optimization:                                                                       │
│ - Add database indexes for count queries                                                        │
│ - Optional: In-memory caching (60-second TTL for metrics)                                       │
│ - Target: < 500ms response time for dashboard stats                                             │
│                                                                                                 │
│ Files to Create:                                                                                │
│ - internal/services/admin_service.go (NEW - ~400 lines)                                         │
│ - internal/handlers/admin_handler.go (NEW - ~300 lines)                                         │
│                                                                                                 │
│ Files to Modify:                                                                                │
│ - internal/repositories/user_repo.go (add count/stats methods)                                  │
│ - internal/repositories/audit_log_repo.go (add activity queries)                                │
│ - internal/routes/routes.go (register admin routes)                                             │
│ - cmd/api/main.go (wire admin service/handler)                                                  │
│                                                                                                 │
│ Deliverables:                                                                                   │
│ - 2 new endpoints                                                                               │
│ - Sub-second response times                                                                     │
│ - 10+ unit tests                                                                                │
│                                                                                                 │
│ ---                                                                                             │
│ Phase 3: Session Management (Week 4)                                                            │
│                                                                                                 │
│ Goal: Admin visibility and control over user sessions                                           │
│                                                                                                 │
│ New Endpoints:                                                                                  │
│ GET    /admin/users/{id}/sessions      # List active sessions for user                          │
│ DELETE /admin/users/{id}/sessions      # Revoke all sessions for user                           │
│ DELETE /admin/users/{id}/sessions/{jti} # Revoke specific session                               │
│                                                                                                 │
│ Response DTOs:                                                                                  │
│ type UserSessionResponse struct {                                                               │
│     JTI       string    `json:"jti"`           // Token ID                                      │
│     TokenType string    `json:"token_type"`    // "access" or "refresh"                         │
│     IssuedAt  time.Time `json:"issued_at"`                                                      │
│     ExpiresAt time.Time `json:"expires_at"`                                                     │
│     IPAddress *string   `json:"ip_address"`    // From audit logs                               │
│     UserAgent *string   `json:"user_agent"`                                                     │
│     LastUsed  time.Time `json:"last_used"`                                                      │
│ }                                                                                               │
│                                                                                                 │
│ type UserSessionsResponse struct {                                                              │
│     Sessions []*UserSessionResponse `json:"sessions"`                                           │
│     Total    int                    `json:"total"`                                              │
│ }                                                                                               │
│                                                                                                 │
│ Service Layer:                                                                                  │
│ // internal/services/session_service.go - NEW FILE                                              │
│ type SessionService struct {                                                                    │
│     tokenManager    *auth.TokenManager                                                          │
│     revokeRepo      TokenRevocationRepository                                                   │
│     auditRepo       AuditLogRepository                                                          │
│     logger          *slog.Logger                                                                │
│ }                                                                                               │
│                                                                                                 │
│ func (s *SessionService) GetUserSessions(userID string) ([]*UserSessionResponse, error)         │
│ func (s *SessionService) RevokeAllUserSessions(adminID, userID string, reason string) error     │
│ func (s *SessionService) RevokeSession(adminID, userID, jti string, reason string) error        │
│                                                                                                 │
│ Implementation Notes:                                                                           │
│ - Query revoked_tokens table for non-revoked tokens by user_id                                  │
│ - Correlate with audit_logs for IP/user agent metadata (from login events)                      │
│ - All revocations trigger audit logs with admin as actor, user as target                        │
│ - Reason required for audit trail                                                               │
│                                                                                                 │
│ Files to Create:                                                                                │
│ - internal/services/session_service.go (NEW)                                                    │
│ - internal/handlers/session_handler.go (NEW)                                                    │
│                                                                                                 │
│ Files to Modify:                                                                                │
│ - internal/repositories/token_revocation_repo.go (add GetByUserID method)                       │
│ - internal/routes/routes.go (register session routes)                                           │
│ - cmd/api/main.go (wire session service/handler)                                                │
│                                                                                                 │
│ Deliverables:                                                                                   │
│ - 3 new endpoints                                                                               │
│ - 8+ integration tests                                                                          │
│                                                                                                 │
│ ---                                                                                             │
│ Phase 4: Bulk Operations (Week 5)                                                               │
│                                                                                                 │
│ Goal: Efficient bulk user management                                                            │
│                                                                                                 │
│ New Endpoints:                                                                                  │
│ POST /admin/users/bulk/delete     # Soft delete recommended                                     │
│ POST /admin/users/bulk/suspend    # Bulk suspension                                             │
│ POST /admin/users/bulk/role       # Bulk role changes                                           │
│                                                                                                 │
│ Request/Response DTOs:                                                                          │
│ type BulkOperationRequest struct {                                                              │
│     UserIDs []string `json:"user_ids" validate:"required,min=1,max=100"`                        │
│     Reason  string   `json:"reason" validate:"required,min=10,max=500"`                         │
│ }                                                                                               │
│                                                                                                 │
│ type BulkDeleteRequest struct {                                                                 │
│     BulkOperationRequest                                                                        │
│     SoftDelete bool `json:"soft_delete"` // true = disable, false = hard delete                 │
│ }                                                                                               │
│                                                                                                 │
│ type BulkRoleChangeRequest struct {                                                             │
│     BulkOperationRequest                                                                        │
│     NewRole string `json:"new_role" validate:"required,oneof=user admin"`                       │
│ }                                                                                               │
│                                                                                                 │
│ type BulkOperationResponse struct {                                                             │
│     SuccessCount int      `json:"success_count"`                                                │
│     FailureCount int      `json:"failure_count"`                                                │
│     Errors       []string `json:"errors,omitempty"` // Per-user errors                          │
│ }                                                                                               │
│                                                                                                 │
│ Service Layer:                                                                                  │
│ // internal/services/user_service.go - EXTEND                                                   │
│ func (s *UserService) BulkDelete(userIDs []string, softDelete bool, reason string, adminID      │
│ string) (*BulkOperationResponse, error)                                                         │
│ func (s *UserService) BulkSuspend(userIDs []string, reason string, adminID string)              │
│ (*BulkOperationResponse, error)                                                                 │
│ func (s *UserService) BulkRoleChange(userIDs []string, newRole string, reason string, adminID   │
│ string) (*BulkOperationResponse, error)                                                         │
│                                                                                                 │
│ Implementation Notes:                                                                           │
│ - Transaction Safety: Use database transactions (all-or-nothing)                                │
│ - Error Handling: Collect per-user errors, continue on failure                                  │
│ - Audit Logging: Log each operation individually (event type: bulk_delete, bulk_suspend,        │
│ bulk_role_change)                                                                               │
│ - Rate Limiting: Strict limits (e.g., max 10 bulk ops per hour per admin)                       │
│ - Self-Protection: Prevent admin from bulk-deleting themselves                                  │
│                                                                                                 │
│ Configuration:                                                                                  │
│ // internal/config/config.go - EXTEND                                                           │
│ type AdminConfig struct {                                                                       │
│     BulkOpsPerHour int  // Default: 10                                                          │
│ }                                                                                               │
│                                                                                                 │
│ Files to Modify:                                                                                │
│ - internal/services/user_service.go (add 3 bulk methods)                                        │
│ - internal/repositories/user_repo.go (add transactional bulk methods)                           │
│ - internal/handlers/admin_handler.go (add bulk handlers)                                        │
│ - internal/routes/routes.go (register bulk routes)                                              │
│ - internal/config/config.go (add AdminConfig)                                                   │
│                                                                                                 │
│ Deliverables:                                                                                   │
│ - 3 new endpoints                                                                               │
│ - Transaction safety                                                                            │
│ - 12+ integration tests                                                                         │
│                                                                                                 │
│ ---                                                                                             │
│ Phase 5: Audit Export (Week 6)                                                                  │
│                                                                                                 │
│ Goal: CSV/JSON export for compliance and reporting                                              │
│                                                                                                 │
│ New Endpoint:                                                                                   │
│ GET /admin/audit/export?format=csv&start=2026-01-01&end=2026-02-01&user_id={uuid}               │
│                                                                                                 │
│ Query Parameters:                                                                               │
│ - format: csv or json                                                                           │
│ - start: Start date (ISO 8601)                                                                  │
│ - end: End date (ISO 8601)                                                                      │
│ - user_id: Optional filter by user                                                              │
│ - event_type: Optional filter by event type                                                     │
│                                                                                                 │
│ Service Layer:                                                                                  │
│ // internal/services/audit_service.go - EXTEND                                                  │
│ func (s *AuditService) ExportAuditLogs(format string, startDate, endDate time.Time, filters     │
│ ExportFilters) (io.Reader, error)                                                               │
│                                                                                                 │
│ Implementation Notes:                                                                           │
│ - CSV Format: Standard spreadsheet import with headers                                          │
│ - JSON Format: Newline-delimited JSON (ndjson) for streaming                                    │
│ - Streaming: Use io.Pipe() for large datasets (chunked responses)                               │
│ - Rate Limiting: Expensive queries, limit to 5 exports per hour per admin                       │
│ - Max Rows: Default 100,000 rows per export (configurable via AUDIT_EXPORT_MAX_ROWS)            │
│                                                                                                 │
│ Configuration:                                                                                  │
│ // internal/config/config.go - EXTEND                                                           │
│ type AdminConfig struct {                                                                       │
│     BulkOpsPerHour     int                                                                      │
│     ExportOpsPerHour   int  // Default: 5                                                       │
│     AuditExportMaxRows int  // Default: 100000                                                  │
│ }                                                                                               │
│                                                                                                 │
│ Files to Modify:                                                                                │
│ - internal/services/audit_service.go (add ExportAuditLogs method)                               │
│ - internal/handlers/audit.go (add ExportAuditLogs handler)                                      │
│ - internal/routes/routes.go (register export route)                                             │
│ - internal/config/config.go (add export config)                                                 │
│                                                                                                 │
│ Deliverables:                                                                                   │
│ - 1 new endpoint with 2 formats                                                                 │
│ - Streaming support                                                                             │
│ - 6+ integration tests                                                                          │
│                                                                                                 │
│ ---                                                                                             │
│ Phase 6 (Optional): React SPA Frontend (Week 7-10)                                              │
│                                                                                                 │
│ Goal: Modern admin dashboard UI                                                                 │
│                                                                                                 │
│ Tech Stack:                                                                                     │
│ - React + TypeScript + Vite                                                                     │
│ - TanStack Query for API state management                                                       │
│ - Recharts for metrics visualization                                                            │
│ - shadcn/ui or Radix for components                                                             │
│                                                                                                 │
│ Key Features:                                                                                   │
│ 1. Authentication flow (JWT + refresh tokens)                                                   │
│ 2. Dashboard with live metrics                                                                  │
│ 3. User management UI (search, filter, suspend, bulk ops)                                       │
│ 4. Session management viewer                                                                    │
│ 5. Audit log viewer with export                                                                 │
│                                                                                                 │
│ Deployment:                                                                                     │
│ - Separate repository                                                                           │
│ - Build → S3 + CloudFront (CDN)                                                                 │
│ - CORS-protected API access                                                                     │
│                                                                                                 │
│ Estimated Timeline: 4 weeks                                                                     │
│                                                                                                 │
│ ---                                                                                             │
│ Security Considerations                                                                         │
│                                                                                                 │
│ Authorization Strategy                                                                          │
│                                                                                                 │
│ Existing Pattern (Reuse):                                                                       │
│ // Apply to all admin endpoints                                                                 │
│ router.Group(func(r chi.Router) {                                                               │
│     r.Use(auth.RequireRole(userRepo, "admin"))                                                  │
│     r.Use(middleware.RateLimitByUserID(authRateLimitConfig, "admin"))                           │
│                                                                                                 │
│     // Admin endpoints here                                                                     │
│ })                                                                                              │
│                                                                                                 │
│ New Admin Scopes:                                                                               │
│ // internal/models/scopes.go - EXTEND                                                           │
│ const (                                                                                         │
│     // Existing scopes...                                                                       │
│     ScopeUsersRead   = "users.read"                                                             │
│     ScopeUsersWrite  = "users.write"                                                            │
│     ScopeUsersDelete = "users.delete"                                                           │
│                                                                                                 │
│     // NEW admin scopes                                                                         │
│     ScopeUsersSuspend      = "users.suspend"      // Suspend/activate users                     │
│     ScopeUsersLock         = "users.lock"         // Temporary account locks                    │
│     ScopeUsersBulk         = "users.bulk"         // Bulk operations                            │
│     ScopeAdminDashboard    = "admin.dashboard"    // View metrics                               │
│     ScopeAdminSessions     = "admin.sessions"     // Manage user sessions                       │
│     ScopeAuditExport       = "audit.export"       // Export audit logs                          │
│ )                                                                                               │
│                                                                                                 │
│ Audit Logging Requirements                                                                      │
│                                                                                                 │
│ ALL admin operations MUST be audited:                                                           │
│ - User suspension/activation → user_suspended, user_activated                                   │
│ - Account locks → user_locked                                                                   │
│ - Password resets → password_reset_admin                                                        │
│ - Email verification overrides → email_verify_override                                          │
│ - Bulk operations → bulk_delete, bulk_suspend, bulk_role_change                                 │
│ - Session revocations → session_revoked                                                         │
│                                                                                                 │
│ Audit Pattern:                                                                                  │
│ auditService.LogUserAction(ctx,                                                                 │
│     adminUserID,      // Actor (admin)                                                          │
│     targetUserID,     // Target (user being modified)                                           │
│     "user_suspended", // Action                                                                 │
│     "user",           // Resource type                                                          │
│     &userID,          // Resource ID                                                            │
│     true,             // Success                                                                │
│     nil,              // Failure reason (if failed)                                             │
│     models.AuditMetadata{                                                                       │
│         "reason": "Violating TOS",                                                              │
│         "admin_email": adminEmail,                                                              │
│     },                                                                                          │
│ )                                                                                               │
│                                                                                                 │
│ Input Validation                                                                                │
│                                                                                                 │
│ Validate ALL admin inputs:                                                                      │
│ type SuspendUserRequest struct {                                                                │
│     Status string `json:"status" validate:"required,oneof=active suspended disabled"`           │
│     Reason string `json:"reason" validate:"required,min=10,max=500"`                            │
│ }                                                                                               │
│                                                                                                 │
│ if err := handlers.ValidateRequest(req); err != nil {                                           │
│     pkghttp.WriteBadRequest(w, err.Error())                                                     │
│     return                                                                                      │
│ }                                                                                               │
│                                                                                                 │
│ Prevent Self-Modification:                                                                      │
│ // Admin cannot suspend themselves                                                              │
│ if adminUserID == targetUserID {                                                                │
│     pkghttp.WriteForbidden(w, "Admins cannot modify their own status")                          │
│     return                                                                                      │
│ }                                                                                               │
│                                                                                                 │
│ Rate Limiting                                                                                   │
│                                                                                                 │
│ Admin operations get dedicated rate limits:                                                     │
│ // internal/config/config.go - EXTEND                                                           │
│ type AuthConfig struct {                                                                        │
│     // Existing...                                                                              │
│     AuthenticatedAdminOpsPerMin int // Default: 60                                              │
│ }                                                                                               │
│                                                                                                 │
│ type AdminConfig struct {                                                                       │
│     BulkOpsPerHour   int // Default: 10                                                         │
│     ExportOpsPerHour int // Default: 5                                                          │
│ }                                                                                               │
│                                                                                                 │
│ CSRF Protection                                                                                 │
│                                                                                                 │
│ All state-changing endpoints require CSRF:                                                      │
│ // Already applied to protected routes in routes.go                                             │
│ r.Use(middleware.CSRFProtection(csrfManager, logger))                                           │
│                                                                                                 │
│ ---                                                                                             │
│ Testing Strategy                                                                                │
│                                                                                                 │
│ Unit Tests (Service Layer)                                                                      │
│                                                                                                 │
│ Pattern:                                                                                        │
│ // internal/services/admin_service_test.go - NEW                                                │
│ func TestAdminService_GetDashboardStats(t *testing.T) {                                         │
│     mockRepo := &mockUserRepository{                                                            │
│         countByStatusFunc: func(ctx context.Context, status string) (int64, error) {            │
│             return 42, nil                                                                      │
│         },                                                                                      │
│     }                                                                                           │
│                                                                                                 │
│     service := NewAdminService(mockRepo, slog.Default())                                        │
│     stats, err := service.GetDashboardStats()                                                   │
│                                                                                                 │
│     assert.NoError(t, err)                                                                      │
│     assert.Equal(t, int64(42), stats.ActiveUsers)                                               │
│ }                                                                                               │
│                                                                                                 │
│ Coverage Goals:                                                                                 │
│ - AdminService: 90%+                                                                            │
│ - UserService extensions: 85%+                                                                  │
│ - Bulk operations: 100% (critical path)                                                         │
│                                                                                                 │
│ Integration Tests                                                                               │
│                                                                                                 │
│ Pattern (follow existing tests in tests/integration/):                                          │
│ func TestSuspendUser(t *testing.T) {                                                            │
│     ts := setupTestServer(t)                                                                    │
│     defer ts.cleanup()                                                                          │
│                                                                                                 │
│     userID := ts.createTestUser("test@example.com", "password123")                              │
│                                                                                                 │
│     req := SuspendUserRequest{                                                                  │
│         Status: "suspended",                                                                    │
│         Reason: "Violating terms of service",                                                   │
│     }                                                                                           │
│                                                                                                 │
│     resp := ts.patchJSON("/users/"+userID+"/status", req, ts.adminToken)                        │
│     assert.Equal(t, http.StatusOK, resp.StatusCode)                                             │
│                                                                                                 │
│     user := ts.getUser(userID, ts.adminToken)                                                   │
│     assert.Equal(t, "suspended", user.Status)                                                   │
│                                                                                                 │
│     auditLogs := ts.getUserAuditTrail(userID, ts.adminToken)                                    │
│     assert.Contains(t, auditLogs, "user_suspended")                                             │
│ }                                                                                               │
│                                                                                                 │
│ Coverage:                                                                                       │
│ - All new endpoints: 100%                                                                       │
│ - Edge cases: Authorization failures, validation errors                                         │
│ - Audit logging: Verify all operations are logged                                               │
│                                                                                                 │
│ Security Tests                                                                                  │
│                                                                                                 │
│ Required Test Cases:                                                                            │
│ - Non-admin users cannot access admin endpoints (403 Forbidden)                                 │
│ - Admins cannot suspend/delete themselves (403 Forbidden)                                       │
│ - Malformed requests return 400 Bad Request                                                     │
│ - CSRF protection blocks requests without token                                                 │
│ - Rate limiting enforced on bulk operations                                                     │
│ - All admin actions appear in audit logs                                                        │
│                                                                                                 │
│ Performance Tests                                                                               │
│                                                                                                 │
│ Benchmarks:                                                                                     │
│ func BenchmarkSearchUsers(b *testing.B) {                                                       │
│     // Test with 10k users                                                                      │
│     for i := 0; i < b.N; i++ {                                                                  │
│         service.SearchUsers(ctx, SearchCriteria{Email: "test@"})                                │
│     }                                                                                           │
│ }                                                                                               │
│                                                                                                 │
│ Performance Goals:                                                                              │
│ - Dashboard metrics: < 500ms                                                                    │
│ - User search: < 200ms (10k users)                                                              │
│ - Bulk operations: < 5s (100 users)                                                             │
│ - Audit export: Streaming starts within 1s                                                      │
│                                                                                                 │
│ ---                                                                                             │
│ Database Migrations                                                                             │
│                                                                                                 │
│ Migration 013: User Search Indexes                                                              │
│                                                                                                 │
│ -- +goose Up                                                                                    │
│ CREATE EXTENSION IF NOT EXISTS pg_trgm;                                                         │
│ CREATE INDEX idx_users_email_trgm ON users USING gin(email gin_trgm_ops);                       │
│ CREATE INDEX idx_users_name_trgm ON users USING gin(name gin_trgm_ops);                         │
│ CREATE INDEX idx_users_status_role_created ON users(status, role, created_at DESC);             │
│                                                                                                 │
│ -- +goose Down                                                                                  │
│ DROP INDEX IF EXISTS idx_users_status_role_created;                                             │
│ DROP INDEX IF EXISTS idx_users_name_trgm;                                                       │
│ DROP INDEX IF EXISTS idx_users_email_trgm;                                                      │
│                                                                                                 │
│ Migration 014: Audit Log Event Types                                                            │
│                                                                                                 │
│ -- +goose Up                                                                                    │
│ -- Add new event types for admin operations                                                     │
│ ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS chk_event_type_valid;                          │
│ ALTER TABLE audit_logs ADD CONSTRAINT chk_event_type_valid CHECK (                              │
│     event_type IN (                                                                             │
│         'login', 'logout', 'register', 'role_change',                                           │
│         'mfa_setup', 'mfa_disable', 'api_key_operation',                                        │
│         'user_suspended', 'user_activated', 'user_locked',                                      │
│         'bulk_delete', 'bulk_suspend', 'bulk_role_change',                                      │
│         'password_reset_admin', 'email_verify_override',                                        │
│         'session_revoked'                                                                       │
│     )                                                                                           │
│ );                                                                                              │
│                                                                                                 │
│ CREATE INDEX idx_audit_logs_event_type_created ON audit_logs(event_type, created_at DESC);      │
│                                                                                                 │
│ -- +goose Down                                                                                  │
│ DROP INDEX IF EXISTS idx_audit_logs_event_type_created;                                         │
│ ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS chk_event_type_valid;                          │
│                                                                                                 │
│ Optional Migration 015: Soft Delete Support                                                     │
│                                                                                                 │
│ -- +goose Up                                                                                    │
│ ALTER TABLE users ADD COLUMN deleted_at TIMESTAMP WITH TIME ZONE;                               │
│ CREATE INDEX idx_users_deleted_at ON users(deleted_at) WHERE deleted_at IS NOT NULL;            │
│                                                                                                 │
│ -- +goose Down                                                                                  │
│ DROP INDEX IF EXISTS idx_users_deleted_at;                                                      │
│ ALTER TABLE users DROP COLUMN IF EXISTS deleted_at;                                             │
│                                                                                                 │
│ ---                                                                                             │
│ Configuration                                                                                   │
│                                                                                                 │
│ Environment Variables                                                                           │
│                                                                                                 │
│ # Admin Rate Limits                                                                             │
│ RATE_LIMIT_ADMIN_BULK_OPS=10        # Bulk ops per hour                                         │
│ RATE_LIMIT_ADMIN_EXPORT_OPS=5       # Audit exports per hour                                    │
│                                                                                                 │
│ # Dashboard Caching (optional)                                                                  │
│ ADMIN_METRICS_CACHE_TTL=60s         # Cache metrics for 60s                                     │
│                                                                                                 │
│ # Export Limits                                                                                 │
│ AUDIT_EXPORT_MAX_ROWS=100000        # Max rows per export                                       │
│                                                                                                 │
│ Config Struct Extension                                                                         │
│                                                                                                 │
│ // internal/config/config.go - EXTEND                                                           │
│ type AdminConfig struct {                                                                       │
│     BulkOpsPerHour      int                                                                     │
│     ExportOpsPerHour    int                                                                     │
│     MetricsCacheTTL     time.Duration                                                           │
│     AuditExportMaxRows  int                                                                     │
│ }                                                                                               │
│                                                                                                 │
│ type Config struct {                                                                            │
│     // Existing fields...                                                                       │
│     Admin AdminConfig // NEW                                                                    │
│ }                                                                                               │
│                                                                                                 │
│ ---                                                                                             │
│ Critical Files for Implementation                                                               │
│                                                                                                 │
│ Phase 1 (User Management):                                                                      │
│                                                                                                 │
│ - internal/services/user_service.go - Add suspension/lock/search methods (~200 lines)           │
│ - internal/repositories/user_repo.go - Add search queries, status updates (~150 lines)          │
│ - internal/handlers/users.go - Add 3 new handlers (~200 lines)                                  │
│ - internal/routes/routes.go - Register new admin routes (~20 lines)                             │
│ - migrations/013_user_search_indexes.sql - Database indexes (NEW)                               │
│ - migrations/014_audit_user_actions.sql - Event types (NEW)                                     │
│                                                                                                 │
│ Phase 2 (Dashboard):                                                                            │
│                                                                                                 │
│ - internal/services/admin_service.go - Metrics aggregation (NEW ~400 lines)                     │
│ - internal/handlers/admin_handler.go - Dashboard handlers (NEW ~300 lines)                      │
│ - internal/repositories/user_repo.go - Add count/stats methods (~100 lines)                     │
│ - cmd/api/main.go - Wire admin service/handler (~20 lines)                                      │
│                                                                                                 │
│ Phase 3 (Sessions):                                                                             │
│                                                                                                 │
│ - internal/services/session_service.go - Session management (NEW ~300 lines)                    │
│ - internal/handlers/session_handler.go - Session handlers (NEW ~200 lines)                      │
│ - internal/repositories/token_revocation_repo.go - GetByUserID method (~50 lines)               │
│                                                                                                 │
│ Phase 4 (Bulk Operations):                                                                      │
│                                                                                                 │
│ - internal/services/user_service.go - Add bulk methods (~300 lines)                             │
│ - internal/repositories/user_repo.go - Transactional bulk ops (~200 lines)                      │
│ - internal/handlers/admin_handler.go - Bulk handlers (~200 lines)                               │
│                                                                                                 │
│ Phase 5 (Audit Export):                                                                         │
│                                                                                                 │
│ - internal/services/audit_service.go - Export method (~200 lines)                               │
│ - internal/handlers/audit.go - Export handler (~150 lines)                                      │
│                                                                                                 │
│ ---                                                                                             │
│ Verification                                                                                    │
│                                                                                                 │
│ After Phase 1 (User Management):                                                                │
│                                                                                                 │
│ Build & Test:                                                                                   │
│ go build -o kamino ./cmd/api                                                                    │
│ go test ./internal/services -v                                                                  │
│ go test ./internal/handlers -v                                                                  │
│ go test ./tests/integration -v                                                                  │
│                                                                                                 │
│ Manual Testing:                                                                                 │
│ # Suspend user                                                                                  │
│ curl -X PATCH http://localhost:8080/users/{id}/status \                                         │
│   -H "Authorization: Bearer $ADMIN_TOKEN" \                                                     │
│   -H "X-CSRF-Token: $CSRF_TOKEN" \                                                              │
│   -d '{"status":"suspended","reason":"Violating TOS"}'                                          │
│                                                                                                 │
│ # Search users                                                                                  │
│ curl -X POST http://localhost:8080/users/search \                                               │
│   -H "Authorization: Bearer $ADMIN_TOKEN" \                                                     │
│   -d '{"email":"test@","limit":10}'                                                             │
│                                                                                                 │
│ # Verify audit log                                                                              │
│ curl http://localhost:8080/users/{id}/audit \                                                   │
│   -H "Authorization: Bearer $ADMIN_TOKEN"                                                       │
│                                                                                                 │
│ Database Verification:                                                                          │
│ -- Check user status updated                                                                    │
│ SELECT id, email, status, locked_until FROM users WHERE id = '{user_id}';                       │
│                                                                                                 │
│ -- Check audit log created                                                                      │
│ SELECT event_type, actor_id, target_id, success, metadata                                       │
│ FROM audit_logs                                                                                 │
│ WHERE target_id = '{user_id}'                                                                   │
│ ORDER BY created_at DESC;                                                                       │
│                                                                                                 │
│ After Phase 2 (Dashboard):                                                                      │
│                                                                                                 │
│ API Testing:                                                                                    │
│ # Dashboard stats                                                                               │
│ curl http://localhost:8080/admin/dashboard/stats \                                              │
│   -H "Authorization: Bearer $ADMIN_TOKEN"                                                       │
│                                                                                                 │
│ # Recent activity                                                                               │
│ curl http://localhost:8080/admin/dashboard/activity \                                           │
│   -H "Authorization: Bearer $ADMIN_TOKEN"                                                       │
│                                                                                                 │
│ Performance Check:                                                                              │
│ # Response time < 500ms                                                                         │
│ time curl http://localhost:8080/admin/dashboard/stats \                                         │
│   -H "Authorization: Bearer $ADMIN_TOKEN"                                                       │
│                                                                                                 │
│ After Phase 3 (Sessions):                                                                       │
│                                                                                                 │
│ Session Management Testing:                                                                     │
│ # List user sessions                                                                            │
│ curl http://localhost:8080/admin/users/{id}/sessions \                                          │
│   -H "Authorization: Bearer $ADMIN_TOKEN"                                                       │
│                                                                                                 │
│ # Revoke all sessions                                                                           │
│ curl -X DELETE http://localhost:8080/admin/users/{id}/sessions \                                │
│   -H "Authorization: Bearer $ADMIN_TOKEN" \                                                     │
│   -H "X-CSRF-Token: $CSRF_TOKEN"                                                                │
│                                                                                                 │
│ # Verify user logged out                                                                        │
│ curl http://localhost:8080/users/{id} \                                                         │
│   -H "Authorization: Bearer $OLD_USER_TOKEN"                                                    │
│ # Should return 401 Unauthorized                                                                │
│                                                                                                 │
│ After Phase 4 (Bulk Operations):                                                                │
│                                                                                                 │
│ Bulk Testing:                                                                                   │
│ # Bulk suspend                                                                                  │
│ curl -X POST http://localhost:8080/admin/users/bulk/suspend \                                   │
│   -H "Authorization: Bearer $ADMIN_TOKEN" \                                                     │
│   -H "X-CSRF-Token: $CSRF_TOKEN" \                                                              │
│   -d '{"user_ids":["id1","id2"],"reason":"Spam accounts"}'                                      │
│                                                                                                 │
│ # Verify all users suspended                                                                    │
│ SELECT id, email, status FROM users WHERE id IN ('id1', 'id2');                                 │
│                                                                                                 │
│ After Phase 5 (Audit Export):                                                                   │
│                                                                                                 │
│ Export Testing:                                                                                 │
│ # CSV export                                                                                    │
│ curl "http://localhost:8080/admin/audit/export?format=csv&start=2026-01-01&end=2026-02-01" \    │
│   -H "Authorization: Bearer $ADMIN_TOKEN" \                                                     │
│   > audit_logs.csv                                                                              │
│                                                                                                 │
│ # JSON export                                                                                   │
│ curl "http://localhost:8080/admin/audit/export?format=json&user_id={id}" \                      │
│   -H "Authorization: Bearer $ADMIN_TOKEN" \                                                     │
│   > audit_logs.json                                                                             │
│                                                                                                 │
│ ---                                                                                             │
│ Success Criteria                                                                                │
│                                                                                                 │
│ Phase 1:                                                                                        │
│ - ✅ Admins can suspend/activate user accounts                                                  │
│ - ✅ Admins can search users by email/name                                                      │
│ - ✅ All operations logged to audit_logs                                                        │
│ - ✅ 15+ integration tests passing                                                              │
│                                                                                                 │
│ Phase 2:                                                                                        │
│ - ✅ Dashboard shows real-time metrics (users, sessions, MFA)                                   │
│ - ✅ Recent activity feed displays logins/registrations/failures                                │
│ - ✅ Response time < 500ms for all metrics                                                      │
│ - ✅ 10+ unit tests passing                                                                     │
│                                                                                                 │
│ Phase 3:                                                                                        │
│ - ✅ Admins can view active sessions for any user                                               │
│ - ✅ Admins can revoke individual or all user sessions                                          │
│ - ✅ Session revocation immediately logs out user                                               │
│ - ✅ 8+ integration tests passing                                                               │
│                                                                                                 │
│ Phase 4:                                                                                        │
│ - ✅ Bulk operations support 1-100 users per request                                            │
│ - ✅ Transaction safety (all-or-nothing)                                                        │
│ - ✅ Detailed error reporting per user                                                          │
│ - ✅ 12+ integration tests passing                                                              │
│                                                                                                 │
│ Phase 5:                                                                                        │
│ - ✅ Audit logs export to CSV and JSON                                                          │
│ - ✅ Streaming support for large datasets                                                       │
│ - ✅ Date range and filter support                                                              │
│ - ✅ 6+ integration tests passing                                                               │
│                                                                                                 │
│ ---                                                                                             │
│ Timeline & Resource Estimates                                                                   │
│                                                                                                 │
│ Phase 1 (User Management): 2 weeks, 1 backend engineer                                          │
│ Phase 2 (Dashboard): 1 week, 1 backend engineer                                                 │
│ Phase 3 (Sessions): 1 week, 1 backend engineer                                                  │
│ Phase 4 (Bulk Operations): 1 week, 1 backend engineer                                           │
│ Phase 5 (Audit Export): 1 week, 1 backend engineer                                              │
│                                                                                                 │
│ Total Backend API: 6 weeks                                                                      │
│                                                                                                 │
│ Phase 6 (Optional React SPA): 4 weeks, 1 frontend engineer                                      │
│                                                                                                 │
│ Minimum Viable Product: Phases 1-3 (4 weeks) - Provides core admin capabilities without bulk    │
│ operations or export.                                                                           │
│                                                                                                 │
│ ---                                                                                             │
│ Dependencies                                                                                    │
│                                                                                                 │
│ No new Go dependencies required - all features use existing:                                    │
│ - PostgreSQL (database/sql, pgx/v5)                                                             │
│ - Chi router (go-chi/chi/v5)                                                                    │
│ - JWT (golang-jwt/jwt/v5)                                                                       │
│ - Standard library (encoding/csv, encoding/json)                                                │
│                                                                                                 │
│ Optional Phase 6 (Frontend):                                                                    │
│ - React, TypeScript, Vite                                                                       │
│ - TanStack Query, Recharts                                                                      │
│                                                                                                 │
│ ---                                                                                             │
│ Risks & Mitigation                                                                              │
│                                                                                                 │
│ Risk 1: Full-text search performance degrades with 100k+ users                                  │
│ - Mitigation: PostgreSQL pg_trgm indexes + query optimization, consider Elasticsearch for > 1M  │
│ users                                                                                           │
│                                                                                                 │
│ Risk 2: Dashboard metrics queries slow down with large audit logs                               │
│ - Mitigation: Database indexes, optional in-memory caching (60s TTL), archival of old audit     │
│ logs                                                                                            │
│                                                                                                 │
│ Risk 3: Bulk operations timeout with large user sets                                            │
│ - Mitigation: Max 100 users per request, database query timeouts, async job processing for >    │
│ 100 users                                                                                       │
│                                                                                                 │
│ Risk 4: Audit export memory exhaustion with large datasets                                      │
│ - Mitigation: Streaming responses (io.Pipe), max 100k rows per export, pagination for larger    │
│ exports                                                                                         │
│                                                                                                 │
│ Risk 5: Admin privilege escalation via scope bypass                                             │
│ - Mitigation: RequireRole + RequireScope double-check, comprehensive security tests, audit      │
│ logging                                                                                         │
│                                                                                                 │
│ ---                                                                                             │
│ Conclusion                                                                                      │
│                                                                                                 │
│ This plan provides a production-ready admin panel architecture that:                            │
│                                                                                                 │
│ 1. Follows Kamino Patterns: Interface-based dependencies, Chi router, structured errors,        │
│ comprehensive audit logging                                                                     │
│ 2. Security-First: RBAC with scopes, CSRF protection, rate limiting, audit trail for all        │
│ operations                                                                                      │
│ 3. Incremental Implementation: 5 phases (6 with frontend), each independently deliverable       │
│ 4. Testable: Unit, integration, security, and performance tests for all features                │
│ 5. Scalable: Optimized queries, optional caching, streaming exports, transaction safety         │
│ 6. Maintainable: Consistent with existing codebase, clear separation of concerns                │
│                                                                                                 │
│ Estimated Timeline: 6 weeks for full backend API (Phases 1-5), +4 weeks for optional React SPA  │
│ (Phase 6)                                                                                       │
│                                                                                                 │
│ Minimum Viable Product: Phases 1-3 (User management + Dashboard + Sessions) - 4 weeks  