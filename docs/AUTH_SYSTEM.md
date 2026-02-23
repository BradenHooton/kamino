# Auth System

**Package:** `internal/auth`, `internal/services`, `internal/middleware`  
**Stack:** JWT (HS256), API Keys (SHA256), CSRF (in-memory), bcrypt, TOTP

---

## Token Architecture

### Token Types

| Type | Claim `type` | Signed With | Purpose |
|---|---|---|---|
| Access | `access` | Composite key | API requests |
| Refresh | `refresh` | Composite key | Token renewal only |
| MFA | `mfa` | Composite key | MFA challenge gating |
| API Key (pseudo) | `api_key` | — | Injected by middleware |

### Composite Signing Key

Every JWT is signed with `global_secret + user.token_key`. The `token_key` is a per-user random value stored in the `users` table. Rotating `token_key` invalidates all of a user's tokens without touching the revocation table.

```
signing_key = HMAC(global_secret || user.token_key)
```

If the user repo is unavailable, falls back to the global secret.

### Token Lifetimes

Configured via `config.Auth.*`. Defaults (see `cmd/api/main.go`):
- Access: short-lived (minutes)
- Refresh: long-lived (days)
- MFA: 5 minutes

### Claims (`models.TokenClaims`)

```go
type TokenClaims struct {
    Type   string   `json:"type"`
    UserID string   `json:"user_id"`
    Email  string   `json:"email,omitempty"`
    Scopes []string `json:"scopes,omitempty"` // API keys only
    jwt.RegisteredClaims                       // Includes JTI, exp, iat, nbf
}
```

---

## Authentication Methods

### 1. JWT Bearer Token

- Header: `Authorization: Bearer <token>`
- Validated by `AuthMiddlewareWithRevocation` or `AuthMiddlewareWithAPIKey`
- Refresh tokens are rejected for API access (type check enforced in middleware)
- Claims injected into context under `UserContextKey`

### 2. API Key

- Header: `X-API-Key: kmn_<64 hex chars>`
- Format: `kmn_` prefix + 256-bit random payload (hex-encoded) = 68 chars total
- Storage: SHA256 hash stored in DB; plaintext shown once at creation
- Lookup: validated by `APIKeyService.ValidateAPIKey` → active + not expired + not revoked check
- Pseudo-claims created with `type=api_key`, user's scopes populated from key record
- API key auth takes precedence over Bearer in `AuthMiddlewareWithAPIKey`
- Every request is audit-logged (deferred, captures final HTTP status code)

---

## Middleware

### Chain (protected routes)

```
AuthMiddlewareWithAPIKey → CSRFProtection → RequireRole (admin routes) → RequireScope
```

### `AuthMiddlewareWithAPIKey`

1. Checks `X-API-Key` header first; if present, validates and injects API key pseudo-claims.
2. Falls back to `Authorization: Bearer` JWT flow.
3. Performs revocation check (`FailClosed: true` — denies access if DB is unreachable).
4. Injects `UserContextKey`, `APIKeyContextKey`, `APIKeyPrefixContextKey`, `EndpointContextKey` into context.

### `RequireRole(repo, role)`

- Reads claims from context, fetches live role from DB (not from token claims).
- Returns `401` if no claims, `404` if user deleted, `403` if role mismatch.

### `RequireScope(scope)`

- Only enforced for `type=api_key` claims. JWT tokens bypass scope checks (role-based access covers them).
- Variants: `RequireScope`, `RequireAnyScope`, `RequireAllScopes`.

---

## Scopes

Defined in `internal/models/scopes.go`. Format: `resource.action`.

| Scope | Purpose |
|---|---|
| `users.read` | Read user records |
| `users.write` | Update user records |
| `users.delete` | Delete users |
| `users.suspend` | Suspend/activate/disable accounts |
| `users.lock` | Temporary account lock |
| `api_keys.read` | List/get API keys |
| `api_keys.create` | Create API keys |
| `api_keys.revoke` | Revoke API keys |
| `audit.read` | Read audit logs |
| `mfa.admin` | Admin MFA recovery operations |
| `*` | All scopes (admin only) |

Scopes are validated against a whitelist on key creation via `models.ValidateScopes`.

---

## Token Revocation

- Table: `revoked_tokens` (indexed on `jti`)
- Revocation is checked on every authenticated request.
- **Fail-closed** (`RevocationConfig{FailClosed: true}`): if the DB is unreachable, the request is rejected with `503 Service Unavailable`.
- Single-session logout: revokes the access token by JTI.
- All-sessions logout: calls `RevokeAllUserTokens` (marks all tokens for the user ID).

---

## CSRF Protection

- Manager: `auth.CSRFTokenManager` (in-memory, `sync.RWMutex`)
- Token: 32 random bytes, hex-encoded (64 chars)
- TTL: 15 minutes; cleanup goroutine runs every 5 minutes
- Generation: per-user, tied to `userID`
- Validation: token must match the authenticated user's ID
- Transport:
  - Set as a readable cookie (`csrf_token`, `HttpOnly=false`) so JS can read it
  - Client sends token in `X-CSRF-Token` header
  - Middleware validates header value against in-memory store
- Applied to all state-changing routes in protected groups

---

## Cookie Strategy

| Cookie | `HttpOnly` | `Secure` | Purpose |
|---|---|---|---|
| `refresh_token` | `true` | env-based | Prevents JS access; used only by `/auth/refresh` |
| `csrf_token` | `false` | env-based | Readable by JS; sent back in header |

`SameSite` and `Secure` are configured via `auth.CookieConfig` (set per-environment).

---

## Rate Limiting

### Public Endpoints (IP-based)

- Applied to: `POST /auth/login`, `/auth/register`, `/auth/refresh`, `/auth/verify-email`, `/auth/resend-verification`, `/auth/mfa/verify`
- Default: 5 requests/minute per IP
- Implementation: `middleware.RateLimitByIP` via `go-chi/httprate`

### Authenticated Endpoints (User-based)

- Keyed on `user_id` from context; falls back to IP if no auth context
- Defaults:
  - `read`: 100 req/min
  - `write`: 30 req/min
  - `admin`: 60 req/min
- Configurable via `config.Auth.Authenticated{Read,Write,Admin}OpsPerMin`

### Application-level Login Rate Limiting

- Tracked in DB via `login_attempts` table (per email + IP)
- Exceeding thresholds triggers a temporary account lock (`locked_until`)
- Lock is applied to the user record and audited

---

## Timing Attack Prevention

`auth.TimingDelay` ensures all failed authentication paths take similar wall-clock time:

```
total_delay = base_delay_ms + random_delay_ms (crypto/rand)
```

- Applied via `defer` at the start of `AuthService.Login`
- Covers: user not found, wrong password, account blocked
- MFA challenge response does **not** trigger delay (not a failure path)
- `WaitFrom(startTime)` subtracts already-elapsed time before sleeping

---

## MFA

- **TOTP** (RFC 6238): 30-second window, ±1 window tolerance
- **Backup codes**: 8 chars, base32 charset (excludes `0`, `1`, `I`, `L`, `O`)
- **Login flow**:
  1. Password verified → MFA token issued (5 min TTL, `type=mfa`)
  2. Client submits MFA token + TOTP code to `POST /auth/mfa/verify`
  3. On success → access/refresh tokens issued
- **Admin recovery**: multi-step flow (initiate → confirm → execute) via `MFARecoveryService`
- Attempt tracking: `mfa_verification_attempts` table; rate-limited

---

## Account State Enforcement

Checked during login via `validateAccountState(user)`:

| State | `status` field | `locked_until` | Error Returned |
|---|---|---|---|
| Active | `active` | `nil` | — |
| Suspended | `suspended` | — | `ErrAccountSuspended` |
| Disabled | `disabled` | — | `ErrAccountDisabled` |
| Locked | `active` | future timestamp | `ErrAccountLocked` |

All account state errors are collapsed to a generic `"Authentication failed"` response in the handler to prevent user enumeration.

---

## Key Files

| File | Responsibility |
|---|---|
| `internal/auth/token.go` | JWT generation, validation, composite key logic |
| `internal/auth/middleware.go` | Auth middleware, role enforcement, context helpers |
| `internal/auth/scope_middleware.go` | Scope enforcement for API keys |
| `internal/auth/api_key_manager.go` | Key generation, SHA256 hashing, constant-time compare |
| `internal/auth/csrf.go` | CSRF token lifecycle |
| `internal/auth/cookies.go` | Cookie set/clear helpers |
| `internal/auth/timing.go` | Timing attack delay |
| `internal/services/auth_service.go` | Login, register, refresh, logout business logic |
| `internal/middleware/rate_limit.go` | IP-based and user-based rate limiting |
| `internal/models/scopes.go` | Scope constants and whitelist |
| `internal/routes/routes.go` | Route registration with middleware application |
