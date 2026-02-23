# User Service

**Package:** `internal/services`, `internal/handlers`, `internal/repositories`  
**Dependencies:** `UserRepository`, `AuditService`, `slog`

---

## Model (`models.User`)

| Field | Type | Notes |
|---|---|---|
| `id` | `string` (UUID) | Generated on create |
| `email` | `string` | Normalized to lowercase; unique |
| `password_hash` | `string` | bcrypt; never returned in responses |
| `name` | `string` | Display name |
| `email_verified` | `bool` | Set by email verification flow |
| `token_key` | `string` | Per-user JWT signing component; generated on create |
| `role` | `string` | `user` \| `admin`; defaults to `user` |
| `status` | `string` | `active` \| `suspended` \| `disabled`; defaults to `active` |
| `locked_until` | `*time.Time` | Non-nil = temporarily locked |
| `password_changed_at` | `*time.Time` | Tracked for security audit |
| `mfa_enabled` | `bool` | Set by MFA enrollment flow |
| `mfa_enrolled_at` | `*time.Time` | Set on TOTP setup completion |
| `created_at` | `time.Time` | Immutable after insert |
| `updated_at` | `time.Time` | Set on every write |

---

## Service Interface

Defined in `internal/handlers/users.go` (`UserService`) and satisfied by `*services.UserService`.

```go
type UserService interface {
    GetUserByID(id string) (*models.User, error)
    ListUsers(limit, offset int) ([]*models.User, error)
    CreateUser(user *models.User, password string) (*models.User, error)
    UpdateUser(id string, user *models.User) (*models.User, error)
    DeleteUser(id string) error
    UpdateUserStatus(id, status, reason, actorID string) error
    LockUser(id string, duration time.Duration, reason, actorID string) error
    SearchUsers(criteria models.SearchCriteria) ([]*models.User, int64, error)
}
```

---

## Service Methods

### `GetUserByID(id) → (*User, error)`

- Fetches by primary key.
- Returns `ErrNotFound` on miss; `ErrInternalServer` on DB error.

### `ListUsers(limit, offset) → ([]*User, error)`

- No filtering; ordered by `created_at DESC`.
- Limit enforced at handler layer (1–100).

### `CreateUser(user, password) → (*User, error)`

1. Checks for email conflict via `GetByEmail`.
2. Validates password requirements via `pkg/auth.ValidatePassword`.
3. Hashes password via `pkg/auth.HashPassword` (bcrypt).
4. Generates UUID and `token_key` in repository layer.
5. Sets default `role=user`, `status=active` if unset.
6. Returns `ErrConflict` on duplicate email; propagates password validation errors as-is.

### `UpdateUser(id, user) → (*User, error)`

- Applies only non-zero fields (`Name`, `Role`) to the existing record.
- Role change authorization is enforced at the **handler layer** (not service).
- Returns `ErrNotFound` if user does not exist.

### `DeleteUser(id) → error`

- Validates existence before deleting.
- Returns `ErrNotFound` if missing.

### `UpdateUserStatus(id, status, reason, actorID) → error`

Dispatcher; routes to:
- `"suspended"` → `SuspendUser`
- `"active"` → `ActivateUser`
- `"disabled"` → `DisableUser`
- Any other value → `ErrBadRequest`

All three helpers enforce `id != actorID` (returns `ErrForbidden` for self-modification), check existence, call `repo.UpdateStatus`, and emit an audit event.

### `LockUser(id, duration, reason, actorID) → error`

- Enforces `id != actorID` (returns `ErrForbidden`).
- Enforces `5m ≤ duration ≤ 24h` (returns `ErrBadRequest`).
- Sets `locked_until = now + duration` via `repo.LockAccount`.
- Emits `user.locked` audit event with `locked_until` and `duration_seconds` in metadata.

### `SearchUsers(criteria) → ([]*User, int64, error)`

- Clamps `criteria.Limit` to range [1, 100]; defaults to 20.
- Delegates to `repo.Search`.
- Returns results + total count for pagination.

---

## Repository Interface (`services.UserRepository`)

Implemented by `*repositories.UserRepository` (PostgreSQL via pgx).

| Method | SQL |
|---|---|
| `GetByID` | `SELECT … FROM users WHERE id = $1` |
| `GetByEmail` | `SELECT … FROM users WHERE email = $1` |
| `List` | `SELECT … ORDER BY created_at DESC LIMIT … OFFSET …` |
| `Create` | `INSERT INTO users … RETURNING …` |
| `Update` | `UPDATE users SET name, role, status, token_key, locked_until, email_verified, updated_at WHERE id` |
| `Delete` | `DELETE FROM users WHERE id = $1` |
| `UpdateStatus` | `UPDATE users SET status = $1, updated_at = NOW() WHERE id = $2` |
| `LockAccount` | `UPDATE users SET locked_until = $1, updated_at = NOW() WHERE id = $2` |
| `Search` | Dynamic `WHERE` with `ILIKE` for email/name, exact match for role/status; runs separate `COUNT(*)` |

`Search` builds parameterized queries dynamically. `ILIKE` is used for email and name (partial, case-insensitive). `RETURNING` is used on `Create` and `Update` to avoid a second read.

---

## HTTP Handler (`handlers.UserHandler`)

### Endpoints

| Method | Path | Auth | Scope | Handler |
|---|---|---|---|---|
| `GET` | `/users/{id}` | JWT or API Key | `users.read` | `GetUser` |
| `PUT` | `/users/{id}` | JWT or API Key | `users.write` | `UpdateUser` |
| `GET` | `/users` | Admin role | `users.read` | `ListUsers` |
| `POST` | `/users` | Admin role | — | `CreateUser` |
| `DELETE` | `/users/{id}` | Admin role | `users.delete` | `DeleteUser` |
| `PATCH` | `/users/{id}/status` | Admin role | `users.suspend` | `UpdateUserStatus` |
| `PATCH` | `/users/{id}/lock` | Admin role | `users.lock` | `LockUser` |
| `POST` | `/users/search` | Admin role | `users.read` | `SearchUsers` |

### Access Control

`GetUser` and `UpdateUser` call `checkUserAccess(r, targetUserID)`:
- Allow if `claims.UserID == targetUserID` (own resource).
- Allow if requesting user's DB role is `admin`.
- Otherwise return `403`.

Role change in `UpdateUser` is additionally guarded:
- Only users with `role=admin` (fetched live from DB) may set a `role` field.
- Admins cannot change their own role.

### Request Validation

All request bodies are decoded with `json.NewDecoder` and validated via `ValidateRequest` (go-validator tags).

| DTO | Key Constraints |
|---|---|
| `CreateUserRequest` | email (valid), name (≥1 char), password (required), role (`user`\|`admin`) |
| `UpdateUserRequest` | name (opt, ≥1 char), role (opt, `user`\|`admin`) |
| `UpdateUserStatusRequest` | status (`active`\|`suspended`\|`disabled`), reason (10–500 chars) |
| `LockUserRequest` | duration_seconds (300–86400), reason (10–500 chars) |
| `SearchUsersRequest` | email/name/role/status (optional filters), limit (0–100), offset (≥0) |

### Response DTOs

`UserResponse` strips sensitive fields:

```go
type UserResponse struct {
    ID            string `json:"id"`
    Email         string `json:"email"`
    Name          string `json:"name"`
    EmailVerified bool   `json:"email_verified"`
    MFAEnabled    bool   `json:"mfa_enabled"`
    Role          string `json:"role"`
    CreatedAt     string `json:"created_at"` // RFC3339
    UpdatedAt     string `json:"updated_at"` // RFC3339
}
```

`password_hash`, `token_key`, `locked_until`, `status` are never exposed in `UserResponse`.

---

## Audit Integration

`UserService` holds a `*services.AuditService` reference. Status and lock operations call `emitStatusChangeAudit`, which:

1. Parses `actorID` and `targetID` as UUIDs (no-ops if invalid).
2. Calls `auditService.LogStatusChange` with event type, actor, target, reason, and metadata.
3. Skips silently if `auditService == nil` (graceful degradation).

| Operation | Event Type |
|---|---|
| Suspend | `user.suspended` |
| Activate | `user.activated` |
| Disable | `user.suspended` (reuses type; `new_status=disabled` in metadata) |
| Lock | `user.locked` |

---

## Admin Service (`services.AdminService`)

Separate service for read-only dashboard aggregations. Does not modify user state.

### Methods

| Method | Returns |
|---|---|
| `GetDashboardStats()` | `DashboardStatsResponse` — total/active/suspended/disabled/admin counts, MFA adoption, new users today |
| `GetRecentActivity(limit)` | `DashboardActivityResponse` — recent logins, registrations, failed logins (limit capped at 20) |

### Endpoints

| Method | Path | Auth | Scope |
|---|---|---|---|
| `GET` | `/admin/dashboard/stats` | Admin role | `audit.read` |
| `GET` | `/admin/dashboard/activity` | Admin role | `audit.read` |

---

## Key Files

| File | Responsibility |
|---|---|
| `internal/services/user_service.go` | Core CRUD + status/lock/search business logic |
| `internal/services/admin_service.go` | Dashboard aggregation queries |
| `internal/handlers/users.go` | HTTP handlers, DTOs, access control |
| `internal/handlers/admin_handler.go` | Dashboard HTTP handlers |
| `internal/repositories/user_repo.go` | PostgreSQL implementation of `UserRepository` |
| `internal/models/user.go` | `User` struct definition |
