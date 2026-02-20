# KAMINO PRODUCTION READINESS FIX PLAN

**Date Created:** 2026-02-19
**Status:** Ready for Implementation
**Target Completion:** 2026-03-02 (2 weeks)
**Build Target:** go build -o kamino ./cmd/api

---

## OVERVIEW

This document provides a detailed, actionable plan to resolve all critical issues, high-priority items, and blockers preventing Kamino from reaching production readiness. Issues are organized by priority tier with implementation steps, file references, and testing requirements.

**Total Effort:** ~70-90 hours
**Critical Path:** 8-10 hours (blockers must be fixed first)
**Parallel Work:** Some HIGH and LOW priority items can be worked on while tests are being written

---

## TIER 0: CRITICAL BLOCKERS (MUST FIX BEFORE ANY DEPLOYMENT)

These items prevent the application from being considered secure or stable for production use.

---

### BLOCKER #1: Revocation Config is Fail-Open (Token Acceptance During DB Outage)

**Severity:** 🔴 CRITICAL
**Security Impact:** MEDIUM (Revoked tokens stay valid during outages)
**Effort:** 0.5 hours
**Risk:** Very Low (1-line change, well-tested code path)
**Status:** COMPLETED

#### Problem Statement

When the token revocation database is unavailable, the application currently continues to accept revoked tokens because the revocation middleware is configured with `FailClosed: false`.

```go
// CURRENT (INSECURE)
revocationConfig := auth.RevocationConfig{FailClosed: false}
```

This means during a database outage, logged-out users can continue using their tokens (if cached), deleted accounts can still authenticate, and compromised tokens remain valid.

#### Files to Modify

1. **`internal/routes/routes.go`** (2 locations)
   - Line 39: Protected routes revocation config
   - Line 55: Public MFA routes revocation config

#### Current Code

```go
// Line 39 in routes.go
revocationConfig := auth.RevocationConfig{FailClosed: false}
r.Use(auth.AuthMiddlewareWithRevocation(tokenManager, revokeRepo, revocationConfig))
```

#### Change Required

```go
// Line 39 in routes.go (FIXED)
revocationConfig := auth.RevocationConfig{FailClosed: true}
r.Use(auth.AuthMiddlewareWithRevocation(tokenManager, revokeRepo, revocationConfig))

// Line 55 in routes.go (FIXED)
revocationConfig := auth.RevocationConfig{FailClosed: true}
r.Use(auth.AuthMiddlewareWithRevocation(tokenManager, revokeRepo, revocationConfig))
```

#### Implementation Steps

1. Open `internal/routes/routes.go`
2. Find line 39: Change `FailClosed: false` → `FailClosed: true`
3. Find line 55: Change `FailClosed: false` → `FailClosed: true`
4. Run `go build -o kamino ./cmd/api` to verify compilation
5. Run `go test ./internal/routes -v` (if tests exist)
6. Run existing middleware tests: `go test ./internal/auth -v -run TestAuthMiddleware`

#### Testing

No new tests needed. Existing middleware tests should cover this behavior.

**Verification Steps:**
```bash
# Test 1: Verify build succeeds
go build -o kamino ./cmd/api

# Test 2: Run auth middleware tests
go test ./internal/auth -v

# Test 3: Manual verification - check config value is correct
grep -n "FailClosed: true" internal/routes/routes.go
# Should find 2 matches
```

#### Deployment Notes

- **Risk Level:** Minimal - This is a configuration change to fail-safe behavior
- **Rollback:** Simple (revert 1 line in each location)
- **Monitoring:** Add alert if revocation check errors increase (indicates DB problem)
- **Breaking Change:** No - Makes security stricter, doesn't change API contract

#### Documentation

Update `docs/SECURITY.md` to note:
```markdown
### Token Revocation Strategy

- **Fail-Closed:** If revocation database is unavailable, deny all token-based access (deny all > accept all)
- **Rationale:** During DB outages, it's safer to deny legitimate users than accept potentially compromised tokens
- **Alternative:** Implement circuit breaker pattern for graceful degradation (future improvement)
```

---

### BLOCKER #2: Security Test Framework Bypasses Authorization (Privilege Escalation Not Actually Tested)

**Severity:** 🔴 CRITICAL
**Security Impact:** HIGH (Authorization logic not validated)
**Effort:** 2-3 hours
**Risk:** Low (test-only change)
**Status:** COMPLETED

#### Problem Statement

The security test `TestUpdateUser_PrivilegeEscalation_UserCannotChangeOwnRole` does not actually exercise the authorization logic because it calls the handler directly without chi router context. Chi's `URLParam()` extraction returns empty string when not called through router, causing the test to fail with "User ID is required" (400) instead of testing the privilege escalation logic (403).

```
Current Test Result:
❌ TestUpdateUser_PrivilegeEscalation_UserCannotChangeOwnRole
   Expected: 403 Forbidden (authorization check)
   Got: 400 Bad Request (missing user ID)
```

The real authorization code at `internal/handlers/users.go:270-290` is never executed.

#### Files to Modify

1. **`internal/handlers/users_security_test.go`** (complete rewrite)
   - Lines 18-65: Current broken test structure
   - Add: Chi router test wrapper or manually set URL params

2. **`internal/handlers/test_helpers.go`** (new function)
   - Add: `WithChiURLParam()` helper for setting URL parameters

#### Current Code

```go
// BROKEN: Test doesn't use chi router
func TestUpdateUser_PrivilegeEscalation_UserCannotChangeOwnRole(t *testing.T) {
    // ... setup code ...

    req, err := http.NewRequest("PUT", "/users/some-id", bytes.NewReader(body))
    // ❌ Problem: chi.URLParam(r, "id") will return "" because request never passed through chi router

    w := httptest.NewRecorder()
    handler.UpdateUser(w, req)

    // Test expects 403 but gets 400 because URL param is missing
    assert.Equal(t, http.StatusForbidden, w.Code)
}
```

#### Change Required

**Option A: Use Chi Test Router (Recommended)**

```go
// NEW: Proper chi router test
func TestUpdateUser_PrivilegeEscalation_UserCannotChangeOwnRole(t *testing.T) {
    // Setup
    userID := "user-123"
    targetUserID := userID // Same user trying to change own role

    mockUserRepo := &MockUserRepository{
        GetByIDFn: func(ctx context.Context, id string) (*models.User, error) {
            return &models.User{
                ID:   id,
                Role: "user",
            }, nil
        },
    }
    userService := services.NewUserService(mockUserRepo)
    handler := handlers.NewUserHandler(userService, logger)

    requestBody := map[string]string{
        "name": "Updated Name",
        "role": "admin", // Trying to escalate privilege
    }
    body, _ := json.Marshal(requestBody)

    // Create request with auth context (user is authenticated as user-123)
    req := NewTestRequest("PUT", "/users/"+targetUserID, bytes.NewReader(body))
    req = req.WithContext(context.WithValue(req.Context(), auth.UserContextKey, &models.TokenClaims{
        UserID: userID,
        Email:  "user@example.com",
    }))

    // ✅ Set chi URL param explicitly
    rctx := chi.NewRouteContext()
    rctx.URLParams.Add("id", targetUserID)
    req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

    w := httptest.NewRecorder()
    handler.UpdateUser(w, req)

    // Now test expects 403 Forbidden (authorization denied)
    assert.Equal(t, http.StatusForbidden, w.Code)
}
```

**Option B: Create Router Wrapper Helper** (More Scalable)

```go
// In test_helpers.go
// WithChiRouteContext adds chi route context to request
func WithChiRouteContext(r *http.Request, params map[string]string) *http.Request {
    rctx := chi.NewRouteContext()
    for key, value := range params {
        rctx.URLParams.Add(key, value)
    }
    return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// Then in test:
func TestUpdateUser_PrivilegeEscalation_UserCannotChangeOwnRole(t *testing.T) {
    // ... setup ...
    req = WithChiRouteContext(req, map[string]string{
        "id": targetUserID,
    })
    // ... rest of test ...
}
```

#### Implementation Steps

1. **Backup current test file:**
   ```bash
   cp internal/handlers/users_security_test.go internal/handlers/users_security_test.go.bak
   ```

2. **Add helper function to `test_helpers.go`:**
   ```go
   // WithChiRouteContext adds chi URL parameters to request context
   func WithChiRouteContext(r *http.Request, params map[string]string) *http.Request {
       rctx := chi.NewRouteContext()
       for key, value := range params {
           rctx.URLParams.Add(key, value)
       }
       return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
   }
   ```

3. **Update all security tests in `users_security_test.go`:**
   - Add chi route context to each test request
   - Verify each test now exercises the actual authorization logic
   - Update assertions to match expected behavior

4. **Add three test cases:**
   ```go
   func TestUpdateUser_PrivilegeEscalation_UserCannotChangeOwnRole(t *testing.T)
   func TestUpdateUser_PrivilegeEscalation_AdminCannotChangeOwnRole(t *testing.T)
   func TestUpdateUser_PrivilegeEscalation_AdminCanChangeOtherUserRole(t *testing.T)
   ```

5. **Run tests:**
   ```bash
   go test ./internal/handlers/users_security_test.go -v
   # Should now see ✅ PASS for all three tests
   ```

#### Testing

The fixed test should:
1. Create authenticated user (non-admin)
2. Attempt to change own role to "admin"
3. Verify response is 403 Forbidden (not 400 Bad Request)
4. Verify error message indicates authorization failure

```go
// Expected test output
assert.Equal(t, http.StatusForbidden, w.Code)

var errResp pkghttp.ErrorResponse
json.NewDecoder(w.Body).Decode(&errResp)
assert.Equal(t, "forbidden", errResp.Error)
assert.Contains(t, errResp.Message, "cannot change role")
```

#### Code Location Reference

- **Test file:** `internal/handlers/users_security_test.go`
- **Authorization logic:** `internal/handlers/users.go:270-290`
- **Router context key:** `chi.RouteCtxKey` (from chi/chi v5)
- **Helper import:** `"github.com/go-chi/chi/v5"`

#### Deployment Notes

- **Risk Level:** None (test-only change)
- **Breaking Change:** No
- **Impact:** None on production code - test becomes effective

#### Dependencies

- Requires: `github.com/go-chi/chi/v5` (already in go.mod)

---

### BLOCKER #3: MFA Token Not Revoked After Use (Replay Attack Vector)

**Severity:** 🔴 CRITICAL
**Security Impact:** MEDIUM (MFA token replay possible within 5-minute window)
**Effort:** 2-3 hours
**Risk:** Low (adding revocation call to existing path)
**Status:** Completed

#### Problem Statement

When a user successfully verifies an MFA code with their MFA token, the MFA token itself is not revoked. This allows an attacker who intercepts the MFA token to attempt unlimited MFA code guesses within the 5-minute token expiration window.

**Attack Scenario:**
1. User initiates login, receives MFA token (valid for 5 min)
2. Attacker intercepts MFA token in transit
3. Attacker attempts 1000+ MFA code guesses using the same token
4. Rate limiting only blocks after 5 failed attempts per 15-min window
5. Attacker can try multiple codes across multiple 15-min windows using same token

**Current Code Flow:**
```
VerifyMFACode handler
  ↓
Validates MFA token (checks expiry, signature)
  ↓
Validates TOTP code (checks rate limit)
  ↓
Generates new tokens (access + refresh)
  ↓
Returns success
  ✗ MFA token never revoked - still valid for 5 minutes
```

#### Files to Modify

1. **`internal/handlers/mfa.go`** (line ~240-280)
   - Add token revocation after successful verification

2. **`internal/services/mfa_service.go`** (if service layer exists)
   - Ensure token revocation is called from service

3. **`internal/repositories/token_revocation_repo.go`**
   - Verify `RevokeToken()` method exists (should already exist)

#### Current Code

```go
// In handlers/mfa.go - VerifyMFACode method (~line 224-280)
func (h *MFAHandler) VerifyMFACode(w http.ResponseWriter, r *http.Request) {
    var req mfaVerifyRequest
    json.NewDecoder(r.Body).Decode(&req)

    // Validate MFA token
    claims, err := h.tm.ValidateToken(req.MFAToken)
    if err != nil || claims.Type != "mfa" {
        pkghttp.WriteUnauthorized(w, "Invalid MFA token")
        return
    }

    // Validate TOTP code
    valid, err := h.mfaService.VerifyCode(r.Context(), claims.UserID, req.Code)
    if !valid {
        pkghttp.WriteUnauthorized(w, "Invalid code")
        return
    }

    // Generate new tokens
    accessToken, err := h.tm.GenerateAccessToken(claims.UserID, claims.Email)
    refreshToken, err := h.tm.GenerateRefreshToken(claims.UserID, claims.Email)

    // ✗ MISSING: Revoke MFA token here

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "access_token":  accessToken,
        "refresh_token": refreshToken,
    })
}
```

#### Change Required

```go
// In handlers/mfa.go - VerifyMFACode method (FIXED)
func (h *MFAHandler) VerifyMFACode(w http.ResponseWriter, r *http.Request) {
    var req mfaVerifyRequest
    json.NewDecoder(r.Body).Decode(&req)

    // Validate MFA token
    claims, err := h.tm.ValidateToken(req.MFAToken)
    if err != nil || claims.Type != "mfa" {
        pkghttp.WriteUnauthorized(w, "Invalid MFA token")
        return
    }

    // Validate TOTP code
    valid, err := h.mfaService.VerifyCode(r.Context(), claims.UserID, req.Code)
    if !valid {
        pkghttp.WriteUnauthorized(w, "Invalid code")
        return
    }

    // Generate new tokens
    accessToken, err := h.tm.GenerateAccessToken(claims.UserID, claims.Email)
    refreshToken, err := h.tm.GenerateRefreshToken(claims.UserID, claims.Email)

    // ✅ NEW: Revoke MFA token to prevent replay
    if err := h.revokeRepo.RevokeToken(
        r.Context(),
        claims.ID,                           // JTI from MFA token
        claims.UserID,
        "mfa",                               // token type
        claims.ExpiresAt.Time,              // expires_at from token
        "mfa_verified",                     // reason
    ); err != nil {
        // Log but don't fail - tokens are still generated
        h.logger.Error("failed to revoke MFA token", slog.Any("error", err))
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "access_token":  accessToken,
        "refresh_token": refreshToken,
    })
}
```

#### Implementation Steps

1. **Identify MFA handler location:**
   ```bash
   grep -n "func (h \*MFAHandler) VerifyMFACode" internal/handlers/mfa.go
   ```

2. **Add token revocation repository to handler dependencies:**
   - If not already present, add `revokeRepo repositories.TokenRevocationRepository`
   - Update `NewMFAHandler()` constructor to accept revocation repo

3. **Add revocation call after successful verification:**
   - After TOTP code validation succeeds
   - After new tokens are generated
   - Before returning response
   - Use JTI from claims (claims.ID)

4. **Test the change:**
   ```bash
   go build -o kamino ./cmd/api
   ```

5. **Verify in initialization (cmd/api/main.go):**
   - Check MFAHandler is initialized with revokeRepo

#### Code Location Reference

- **Handler:** `internal/handlers/mfa.go` (~line 240)
- **Method:** `VerifyMFACode()`
- **Dependency:** `TokenRevocationRepository` interface
- **Call location:** After successful TOTP validation

#### Testing

Create test case `TestVerifyMFACode_TokenRevoked`:

```go
func TestVerifyMFACode_TokenRevoked(t *testing.T) {
    // Setup
    userID := "user-123"
    mfaTokenJTI := "mfa-token-jti-123"

    mockRevokeRepo := &MockTokenRevocationRepository{
        RevokeTokenFn: func(ctx context.Context, jti, userID, tokenType string, expiresAt time.Time, reason string) error {
            // Verify revocation was called with MFA token JTI
            assert.Equal(t, mfaTokenJTI, jti)
            assert.Equal(t, "mfa", tokenType)
            assert.Equal(t, "mfa_verified", reason)
            return nil
        },
    }

    handler := handlers.NewMFAHandler(
        mfaService,
        tokenManager,
        mockRevokeRepo, // ← New dependency
        logger,
    )

    // Create request with valid MFA token
    validMFAToken, _ := tokenManager.GenerateMFAToken(userID, "user@example.com")

    requestBody := map[string]string{
        "mfa_token": validMFAToken,
        "code":      "123456",
    }
    body, _ := json.Marshal(requestBody)
    req := NewTestRequest("POST", "/auth/mfa/verify", bytes.NewReader(body))

    w := httptest.NewRecorder()
    handler.VerifyMFACode(w, req)

    // Verify success
    assert.Equal(t, http.StatusOK, w.Code)

    // Verify token was revoked (would be checked via mock)
    assert.True(t, mockRevokeRepo.RevokeTokenFn != nil)
}
```

#### Deployment Notes

- **Risk Level:** Low (adding defensive security measure)
- **Performance Impact:** Minimal (one additional DB write)
- **Monitoring:** Track `mfa_verified` revocation reasons in metrics

#### Related Issues

- This fix is independent of BLOCKER #1
- Works with existing token revocation infrastructure
- No breaking API changes

---

### BLOCKER #4: Email Service Graceful Degradation Creates Operational Blindness

**Severity:** 🔴 CRITICAL
**Operational Impact:** HIGH (Email verification silently broken in production)
**Effort:** 1-2 hours
**Risk:** Low (configuration change + startup validation)
**Status:** Completed

#### Problem Statement

If AWS SES credentials are invalid or misconfigured, the email service initialization fails silently (logs error, doesn't exit). This creates a dangerous production scenario where:

1. Server starts successfully
2. Operators believe email verification is working
3. Users register but never receive verification emails
4. Users cannot log in (email verification required since Phase 6)
5. No alert or error message - just silent failures

**Current Code Flow:**
```
main.go startup
  ↓
Initialize email service (AWS SES)
  ↓
If error: Log error, set emailService = nil
  ↓
Pass nil emailService to AuthHandler
  ↓
AuthHandler checks: if h.emailService == nil { return 500 }
  ↓
User gets 500 error with no diagnostic info
```

#### Files to Modify

1. **`cmd/api/main.go`** (lines 102-120)
   - Add startup validation check
   - Either hard-fail or explicitly enable graceful degradation

2. **`internal/config/config.go`** (optional)
   - Add `EmailConfig.Required` boolean
   - Allows operators to choose fail-hard vs graceful degradation

#### Current Code

```go
// In cmd/api/main.go (~line 102-120)
// Email service initialization
emailService, err := services.NewEmailService(
    cfg.Email.AWSRegion,
    cfg.Email.FromAddress,
)
if err != nil {
    logger.Error("failed to initialize email service", slog.Any("error", err))
    // ✗ PROBLEM: No exit, emailService becomes nil
    emailService = nil
}

// ... later ...

// Handler initialization with potentially nil service
authHandler := handlers.NewAuthHandlerWithEmailVerification(
    authService,
    emailVerificationService,
    emailService,  // ← Could be nil, handlers check for this
    ipConfig,
)
```

#### Change Required

**Option A: Hard-Fail (Recommended for production)**

```go
// In cmd/api/main.go (~line 102-120)
emailService, err := services.NewEmailService(
    cfg.Email.AWSRegion,
    cfg.Email.FromAddress,
)
if err != nil {
    // ✅ NEW: Fail hard - email verification is critical
    logger.Fatal("failed to initialize email service - email verification is required",
        slog.Any("error", err))
    // Exit code 1, no graceful degradation
}
```

**Option B: Explicit Feature Flag (More Flexible)**

```go
// In cmd/api/main.go (~line 102-120)
var emailService services.EmailService
if cfg.Email.Enabled {
    var err error
    emailService, err = services.NewEmailService(
        cfg.Email.AWSRegion,
        cfg.Email.FromAddress,
    )
    if err != nil {
        if cfg.Email.Required {
            // Hard fail if email is required
            logger.Fatal("failed to initialize email service - email verification is required",
                slog.Any("error", err))
        } else {
            // Graceful degradation if email is optional
            logger.Warn("email service disabled - registration without verification",
                slog.Any("error", err))
            emailService = nil
        }
    }
}

// Then in handlers, remove nil checks - always trust emailService is available
```

#### Implementation Steps (Option A - Recommended)

1. **Open `cmd/api/main.go`:**
   ```bash
   vim cmd/api/main.go
   # Go to line 102-120 (email service initialization)
   ```

2. **Replace error handling:**
   ```go
   // BEFORE:
   if err != nil {
       logger.Error("failed to initialize email service", slog.Any("error", err))
       emailService = nil
   }

   // AFTER:
   if err != nil {
       logger.Fatal("failed to initialize email service - email verification is required",
           slog.Any("error", err))
   }
   ```

3. **Remove nil checks from handlers:**
   ```bash
   # In internal/handlers/auth.go, find and remove:
   # - Line 335: if h.emailVerificationService == nil
   # - Line 384: if h.emailVerificationService == nil
   # - Line 425: if h.emailVerificationService == nil

   # These checks are no longer needed if email service must exist
   ```

4. **Test startup with bad credentials:**
   ```bash
   # Set invalid AWS credentials
   export AWS_REGION=invalid
   export AWS_ACCESS_KEY_ID=invalid
   export AWS_SECRET_ACCESS_KEY=invalid

   # Run server
   go run ./cmd/api/main.go

   # Expected: Immediate failure with clear error message
   # NOT: Silent degradation
   ```

5. **Verify build:**
   ```bash
   go build -o kamino ./cmd/api
   ```

#### Code Location Reference

- **Initialization:** `cmd/api/main.go:102-120`
- **Nil checks to remove:** `internal/handlers/auth.go:335, 384, 425`
- **Logger call:** Use `logger.Fatal()` (causes exit code 1)

#### Testing

**Test 1: Startup with valid credentials**
```bash
export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=valid_key
export AWS_SECRET_ACCESS_KEY=valid_secret
export EMAIL_FROM_ADDRESS=noreply@kamino.example

go run ./cmd/api/main.go
# Expected: Server starts successfully
# Check logs: No "failed to initialize email service" message
```

**Test 2: Startup with invalid credentials**
```bash
export AWS_REGION=invalid
export AWS_ACCESS_KEY_ID=invalid
export AWS_SECRET_ACCESS_KEY=invalid
unset EMAIL_FROM_ADDRESS

go run ./cmd/api/main.go
# Expected: Immediate exit with error message
# Exit code: 1
```

#### Deployment Notes

- **Risk Level:** Low (fail-safe approach)
- **Rollback:** Simple (revert error handling)
- **Monitoring:** Eliminate need for error detection (hard failure is obvious)
- **Breaking Change:** Yes - Now requires valid AWS SES credentials

#### Documentation

Update `docs/SECURITY.md`:
```markdown
### Email Verification (Required Feature)

Email verification is **mandatory** for this deployment. The server will refuse to start without valid AWS SES credentials. This is intentional - email verification is critical for security.

**Environment Variables Required:**
- AWS_REGION
- AWS_ACCESS_KEY_ID
- AWS_SECRET_ACCESS_KEY
- EMAIL_FROM_ADDRESS (must be verified in AWS SES)

If you need to disable email verification for development/testing, implement a feature flag via environment variable (e.g., `REQUIRE_EMAIL_VERIFICATION=false`).
```

#### Related Issues

- Fixes blocking of register/verify-email/resend-verification endpoints
- Simplifies error handling (no more nil checks for optional service)
- Makes missing email credentials visible immediately

---

## TIER 1: HIGH PRIORITY ISSUES (IMPLEMENT WITHIN 1 WEEK)

These issues significantly impact security or stability but don't completely block deployment if BLOCKER items are fixed.

---

### HIGH #1: CSRF Manager Goroutine Leak on Shutdown

**Severity:** 🟡 HIGH
**Operational Impact:** MEDIUM (Resource leak on restarts, affects container restarts)
**Effort:** 1-2 hours
**Risk:** Low (adding shutdown hook)
**Status:** Completed

#### Problem Statement

The CSRF token manager starts a background cleanup goroutine that runs indefinitely. When the server shuts down gracefully, this goroutine is never stopped, leading to:

- Resource leak (goroutine never exits)
- Container orchestration issues (graceful shutdown takes longer than timeout)
- Memory/CPU waste in containerized environments with frequent rolling updates

**Current Code:**
```go
// In internal/auth/csrf.go
func NewCSRFTokenManager() *CSRFTokenManager {
    m := &CSRFTokenManager{
        validTokens: make(map[string]*csrfTokenEntry),
        tokenTTL:    15 * time.Minute,
    }

    // ✗ Goroutine starts with no way to stop it
    go m.cleanupExpiredTokens()

    return m
}

func (m *CSRFTokenManager) cleanupExpiredTokens() {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        m.mu.Lock()
        now := time.Now()
        for token, entry := range m.validTokens {
            if now.After(entry.expiry) {
                delete(m.validTokens, token)
            }
        }
        m.mu.Unlock()
    }
    // ✗ Goroutine never reaches this point (infinite loop)
}
```

#### Files to Modify

1. **`internal/auth/csrf.go`**
   - Add `Stop()` method with channel-based shutdown
   - Change infinite loop to check for shutdown signal

2. **`cmd/api/main.go`**
   - Call `csrfManager.Stop()` during graceful shutdown
   - Add to shutdown handler (lines 240-252)

#### Change Required

**Step 1: Update CSRF Manager with Shutdown Support**

```go
// In internal/auth/csrf.go

type CSRFTokenManager struct {
    validTokens map[string]*csrfTokenEntry
    mu          sync.RWMutex
    tokenTTL    time.Duration

    // ✅ NEW: Shutdown signaling
    stopChan    chan struct{}
    stopped     bool
}

// NewCSRFTokenManager creates and starts the CSRF token manager
func NewCSRFTokenManager() *CSRFTokenManager {
    m := &CSRFTokenManager{
        validTokens: make(map[string]*csrfTokenEntry),
        tokenTTL:    15 * time.Minute,
        stopChan:    make(chan struct{}),
    }

    // Start background cleanup
    go m.cleanupExpiredTokens()

    return m
}

// Stop gracefully shuts down the CSRF token manager
func (m *CSRFTokenManager) Stop() error {
    m.mu.Lock()
    defer m.mu.Unlock()

    if m.stopped {
        return nil // Already stopped
    }

    m.stopped = true
    close(m.stopChan)
    return nil
}

// ✅ NEW: Updated cleanup with shutdown check
func (m *CSRFTokenManager) cleanupExpiredTokens() {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()

    for {
        select {
        case <-m.stopChan:
            // Graceful shutdown received
            return
        case <-ticker.C:
            // Perform cleanup
            m.mu.Lock()
            now := time.Now()
            for token, entry := range m.validTokens {
                if now.After(entry.expiry) {
                    delete(m.validTokens, token)
                }
            }
            m.mu.Unlock()
        }
    }
}
```

**Step 2: Update Main Graceful Shutdown**

```go
// In cmd/api/main.go (~line 240-252)

// Graceful shutdown block
go func() {
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
    <-sigChan

    logger.Info("received shutdown signal, cleaning up...")

    // ✅ NEW: Stop CSRF manager
    if err := csrfManager.Stop(); err != nil {
        logger.Error("error stopping CSRF manager", slog.Any("error", err))
    }

    // Existing shutdown handlers...
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    if err := server.Shutdown(ctx); err != nil {
        logger.Error("server shutdown error", slog.Any("error", err))
    }
}()
```

#### Implementation Steps

1. **Backup current file:**
   ```bash
   cp internal/auth/csrf.go internal/auth/csrf.go.bak
   ```

2. **Update CSRF manager struct:**
   - Add `stopChan chan struct{}` field
   - Add `stopped bool` field

3. **Update NewCSRFTokenManager():**
   - Initialize `stopChan: make(chan struct{})`
   - Start cleanup goroutine

4. **Add Stop() method:**
   ```go
   func (m *CSRFTokenManager) Stop() error {
       m.mu.Lock()
       defer m.mu.Unlock()
       if m.stopped {
           return nil
       }
       m.stopped = true
       close(m.stopChan)
       return nil
   }
   ```

5. **Update cleanupExpiredTokens():**
   - Change infinite `for` to `for { select { case <-m.stopChan: return ... } }`

6. **Update main.go graceful shutdown:**
   - Call `csrfManager.Stop()` before server.Shutdown()
   - Add error logging

7. **Test build:**
   ```bash
   go build -o kamino ./cmd/api
   ```

8. **Test shutdown behavior:**
   ```bash
   # Start server
   go run ./cmd/api/main.go &
   PID=$!

   # Wait for startup
   sleep 2

   # Send SIGTERM
   kill -TERM $PID

   # Verify graceful shutdown completes quickly
   # Should see "received shutdown signal, cleaning up..." in logs
   wait $PID
   echo "Exit code: $?"  # Should be 0
   ```

#### Code Location Reference

- **CSRF manager:** `internal/auth/csrf.go` (entire file)
- **Cleanup method:** `cleanupExpiredTokens()`
- **Main shutdown:** `cmd/api/main.go:240-252`

#### Testing

No new tests needed if existing shutdown tests exist. If not, add integration test:

```go
func TestCSRFManagerGracefulShutdown(t *testing.T) {
    manager := auth.NewCSRFTokenManager()

    // Generate token
    token := manager.GenerateToken("user-123")
    assert.NotEmpty(t, token)

    // Verify token is valid
    assert.True(t, manager.ValidateToken(token, "user-123"))

    // Stop manager
    err := manager.Stop()
    assert.NoError(t, err)

    // Goroutine should exit within 100ms
    time.Sleep(100 * time.Millisecond)

    // Verify subsequent operations still work (graceful)
    // but manager is marked as stopped
}
```

#### Deployment Notes

- **Risk Level:** Low (adding safe shutdown mechanism)
- **Breaking Change:** No
- **Monitoring:** Add metric for graceful shutdown completion time

---

### HIGH #2: Add MFA Service Layer Tests (30+ Test Cases)

**Severity:** 🟡 HIGH
**Coverage Impact:** MFA flows completely untested at service layer
**Effort:** 20-25 hours
**Risk:** Low (test code only)
**Status:** Completed

#### Problem Statement

There are zero tests for the MFA service layer despite it being critical for authentication. This includes:
- TOTP secret generation and QR code creation
- TOTP code verification and replay prevention
- Backup code generation and validation
- MFA device management and rate limiting
- Integration between MFA setup and token generation

#### Files to Create

1. **`internal/services/mfa_service_test.go`** (New file, ~500 lines)
   - Test all 5+ public methods
   - Test error cases
   - Test rate limiting

2. **`internal/auth/totp_test.go`** (New file, ~300 lines)
   - Test secret generation
   - Test TOTP code validation
   - Test replay prevention
   - Test backup code generation

#### Test Cases to Add

**MFA Service Tests (15 cases):**

1. `TestMFAService_InitiateSetup_GeneratesSecret` - Secret creation
2. `TestMFAService_InitiateSetup_GeneratesBackupCodes` - Backup code generation
3. `TestMFAService_InitiateSetup_CreatesDevice` - Device in DB
4. `TestMFAService_VerifySetup_ValidatesCorrectCode` - Setup validation success
5. `TestMFAService_VerifySetup_RejectsIncorrectCode` - Setup validation failure
6. `TestMFAService_VerifySetup_MarksDeviceVerified` - Verified flag set
7. `TestMFAService_VerifyCode_ValidCode` - Login MFA verification
8. `TestMFAService_VerifyCode_InvalidCode` - Bad code rejection
9. `TestMFAService_VerifyCode_ReplayDetection` - Code replay prevention
10. `TestMFAService_VerifyCode_RateLimitEnforced` - Rate limiting kicks in after 5 failures
11. `TestMFAService_VerifyBackupCode_Success` - Backup code validation
12. `TestMFAService_VerifyBackupCode_SingleUse` - Backup code can't be reused
13. `TestMFAService_DisableMFA_ClearsDevices` - Disable removes all devices
14. `TestMFAService_GetStatus_ReturnsInfo` - Status endpoint
15. `TestMFAService_UpdateLastUsed_UpdatesTimestamp` - Replay prevention tracking

**TOTP Manager Tests (12 cases):**

1. `TestTOTPManager_GenerateSecret_Creates32ByteSecret` - Secret size
2. `TestTOTPManager_GenerateSecret_CorrectBase32Encoding` - Encoding validation
3. `TestTOTPManager_GenerateSecretWithQR_IncludesQRCode` - QR generation
4. `TestTOTPManager_GenerateSecretWithQR_IncludesIssuer` - Issuer in URI
5. `TestTOTPManager_EncryptSecret_DecryptSecret_RoundTrip` - Encryption/decryption
6. `TestTOTPManager_EncryptSecret_DifferentNonceEachTime` - Unique nonce
7. `TestTOTPManager_ValidateTOTP_ValidCode` - Code validation
8. `TestTOTPManager_ValidateTOTP_TimestepTolerance_Plus1` - ±1 time step
9. `TestTOTPManager_ValidateTOTP_TimestepTolerance_Minus1` - ±1 time step
10. `TestTOTPManager_ValidateTOTP_ReplayPrevention` - Duplicate code rejected
11. `TestTOTPManager_GenerateBackupCodes_10Codes` - Code count
12. `TestTOTPManager_GenerateBackupCodes_UniqueAndRandom` - Uniqueness/entropy

#### Implementation Steps

1. **Create `internal/services/mfa_service_test.go`:**
   ```bash
   touch internal/services/mfa_service_test.go
   ```

2. **Add test file header and imports:**
   ```go
   package services

   import (
       "context"
       "testing"
       "time"

       "github.com/stretchr/testify/assert"
       "github.com/stretchr/testify/require"

       "kamino/internal/auth"
       "kamino/internal/models"
   )
   ```

3. **Create mock repositories:**
   - `MockMFADeviceRepository`
   - `MockMFAAttemptRepository`
   - `MockUserRepository`

4. **Implement each test case** (refer to test list above)

5. **Create `internal/auth/totp_test.go`:**
   - Similar structure
   - Focus on cryptographic operations

6. **Run tests:**
   ```bash
   go test ./internal/services/mfa_service_test.go -v
   go test ./internal/auth/totp_test.go -v
   ```

#### Code Reference

- **MFA Service:** `internal/services/mfa_service.go`
- **TOTP Manager:** `internal/auth/totp.go`
- **Test patterns:** `internal/services/email_verification_service_test.go` (reference)

#### Testing

```bash
# Run all new MFA tests
go test ./internal/services -run MFA -v
go test ./internal/auth -run TOTP -v

# Check coverage
go test -cover ./internal/services
go test -cover ./internal/auth
```

#### Deployment Notes

- **Risk Level:** None (test code only)
- **Effort:** 20-25 hours (40% of overall test plan)
- **Can run in parallel:** Yes, while other blockers are being fixed

---

### HIGH #3: Add AuthService Layer Tests (25+ Test Cases)

**Severity:** 🟡 HIGH
**Coverage Impact:** Login, Register, Refresh completely untested at service layer
**Effort:** 20-25 hours
**Risk:** Low (test code only)
**Status:** Completed


#### Problem Statement

Core auth logic (Login, Register, RefreshToken, Logout) has zero service-layer tests. Only handler-level tests with mocked services exist. This means:
- Password validation logic never tested
- Rate limiting enforcement never tested
- Email verification integration never tested (especially Phase 6 fix)
- Token refresh revocation flow never tested
- Account state checks never tested

#### Files to Create

1. **`internal/services/auth_service_test.go`** (New file, ~700 lines)
   - Test all 5 public methods
   - Test error paths
   - Test database interactions

#### Test Cases to Add

**AuthService Tests (27 cases):**

1. `TestAuthService_Register_Success` - Valid registration
2. `TestAuthService_Register_DuplicateEmail` - Email uniqueness
3. `TestAuthService_Register_InvalidPassword` - Password validation
4. `TestAuthService_Register_SendsEmail` - Email service called
5. `TestAuthService_Register_SetsEmailNotVerified` - Email flag
6. `TestAuthService_Login_Success` - Valid login
7. `TestAuthService_Login_InvalidPassword` - Password mismatch
8. `TestAuthService_Login_UserNotFound` - Non-existent user
9. `TestAuthService_Login_EmailNotVerified` - Verification required
10. `TestAuthService_Login_AccountLocked` - Rate limit lockout
11. `TestAuthService_Login_AccountSuspended` - Suspended account
12. `TestAuthService_Login_AccountDisabled` - Disabled account
13. `TestAuthService_Login_WithMFA_ReturnsChallengeToken` - MFA flow
14. `TestAuthService_Login_WithoutMFA_ReturnsTokens` - Normal flow
15. `TestAuthService_Login_AppliesTimingDelay` - Anti-enumeration
16. `TestAuthService_Login_RecordsAttempt` - Audit logging
17. `TestAuthService_RefreshToken_Success` - Valid refresh
18. `TestAuthService_RefreshToken_ExpiredToken` - Expired check
19. `TestAuthService_RefreshToken_RevokedToken` - Revocation check
20. `TestAuthService_RefreshToken_InvalidTokenType` - Type validation
21. `TestAuthService_RefreshToken_EmailNotVerified` - Phase 6 fix
22. `TestAuthService_RefreshToken_PasswordChanged` - Password change invalidation
23. `TestAuthService_RefreshToken_RevokesOldToken` - Fail-closed revocation
24. `TestAuthService_Logout_RevokesToken` - Token revocation
25. `TestAuthService_LogoutAll_RevokesAllTokens` - Bulk revocation
26. `TestAuthService_LogoutAll_RotatesTokenKey` - Key rotation
27. `TestAuthService_ValidateAccountState_ChecksAllFlags` - Account validation

#### Implementation Steps

1. **Create test file:**
   ```bash
   touch internal/services/auth_service_test.go
   ```

2. **Add mock repositories:**
   - `MockUserRepository`
   - `MockTokenRevocationRepository`
   - `MockRateLimitService`
   - `MockEmailVerificationService`
   - `MockTokenManager`
   - `MockTimingDelay`

3. **Implement test helper:**
   ```go
   // Helper to create initialized AuthService for testing
   func NewTestAuthService(t *testing.T) *AuthService {
       // ... setup mocks and service
   }
   ```

4. **Implement each test case** (27 total)

5. **Run tests:**
   ```bash
   go test ./internal/services/auth_service_test.go -v
   ```

#### Code Reference

- **Auth Service:** `internal/services/auth_service.go`
- **Methods to test:** Login, Register, RefreshToken, Logout, LogoutAll
- **Test patterns:** `internal/services/email_verification_service_test.go` (reference)

#### Testing

```bash
# Run all auth service tests
go test ./internal/services -run AuthService -v

# Check coverage
go test -cover ./internal/services/auth_service_test.go
```

#### Deployment Notes

- **Risk Level:** None (test code only)
- **Effort:** 20-25 hours
- **Can run in parallel:** Yes, with HIGH #2 (MFA tests)

---

### HIGH #4: Add Integration Tests for Complete Auth Flows

**Severity:** 🟡 HIGH
**Coverage Impact:** No end-to-end flow validation
**Effort:** 25-30 hours
**Risk:** Low (test code only)
**Status:** Completed

#### Problem Statement

There are no integration tests validating end-to-end authentication flows:
- Register → Email Verify → Login → Use Token → Refresh → Logout
- Login → MFA Challenge → Verify Code → Use Tokens
- Token revocation actually blocking access
- Email verification requirement at login AND refresh

#### Files to Create

1. **`tests/integration/auth_flow_test.go`** (New file, ~400 lines)
   - Test with real database (PostgreSQL)
   - Test with mocked email service
   - Test complete workflows

#### Integration Test Cases (12+ cases)

1. `TestAuthFlow_Register_VerifyEmail_Login_Success` - Complete flow
2. `TestAuthFlow_Login_SkipsIfEmailNotVerified` - Verification required
3. `TestAuthFlow_Login_WithMFA_VerifyCode_GetTokens` - MFA flow
4. `TestAuthFlow_AccessToken_UsedForAPIEndpoint` - Token usage
5. `TestAuthFlow_RefreshToken_GeneratesNewTokens` - Token refresh
6. `TestAuthFlow_RefreshToken_ChecksEmailVerified` - Phase 6 fix
7. `TestAuthFlow_Logout_RevokesSingleToken` - Logout revocation
8. `TestAuthFlow_LogoutAll_RevokesAllTokens` - Logout all
9. `TestAuthFlow_RevokedToken_DeniesAccess` - Revocation enforcement
10. `TestAuthFlow_ExpiredToken_Rejected` - Expiry enforcement
11. `TestAuthFlow_PasswordChange_InvalidatesTokens` - Password change invalidation
12. `TestAuthFlow_ConcurrentLogins_RateLimited` - Rate limiting under load

#### Implementation Steps

1. **Create integration test directory:**
   ```bash
   mkdir -p tests/integration
   touch tests/integration/auth_flow_test.go
   ```

2. **Add test setup (database):**
   ```go
   package integration

   import (
       "context"
       "testing"

       "github.com/jackc/pgx/v5/pgxpool"
       "github.com/stretchr/testify/require"

       "kamino/internal/database"
       "kamino/internal/models"
       "kamino/internal/repositories"
   )

   // TestDatabase manages a test PostgreSQL instance
   type TestDatabase struct {
       Pool *pgxpool.Pool
   }

   // SetupTest creates test database and runs migrations
   func SetupTest(t *testing.T) *TestDatabase {
       // Connect to test database
       // Run migrations
       // Return pool for tests
   }

   // TeardownTest cleans up test database
   func TeardownTest(t *testing.T, db *TestDatabase) {
       // Clear tables
       // Close pool
   }
   ```

3. **Implement test helper functions:**
   ```go
   // Helper to create and verify user
   func RegisterAndVerifyUser(t *testing.T, db *TestDatabase, email, password string) string {
       // Call register endpoint
       // Get verification token
       // Call verify endpoint
       // Return user ID
   }

   // Helper to login user
   func LoginUser(t *testing.T, email, password string) (accessToken, refreshToken string) {
       // Call login endpoint
       // Return tokens
   }
   ```

4. **Implement each test case**

5. **Run integration tests:**
   ```bash
   go test ./tests/integration -v
   ```

#### Code Reference

- **Test patterns:** `internal/handlers/auth_test.go` (reference)
- **Database setup:** `internal/database/database.go`
- **Migrations:** `migrations/` directory

#### Testing

```bash
# Run integration tests (requires database)
go test ./tests/integration -v -tags=integration

# Or use build constraint to skip without flag
go test ./tests/integration -v
```

#### Deployment Notes

- **Risk Level:** Low (test code, requires database)
- **Effort:** 25-30 hours
- **Dependencies:** PostgreSQL must be running
- **Can run in parallel:** After blockers fixed

---

## TIER 2: MEDIUM PRIORITY ISSUES (IMPLEMENT WITHIN 2-3 WEEKS)

---

### MEDIUM #1: Add TOTP Code Format Validation

**Severity:** 🟢 MEDIUM
**Effort:** 1 hour
**Risk:** Very Low (input validation)
**Status:** Completed

#### Problem Statement

MFA code input is not validated for format before being passed to TOTP validator. This allows malformed codes to reach the validation logic, creating potential probe attacks.

#### Files to Modify

1. **`internal/handlers/mfa.go`** (line ~224)

#### Current Code

```go
// In handlers/mfa.go - VerifyMFACode
if req.MFAToken == "" || req.Code == "" {
    pkghttp.WriteBadRequest(w, "mfa_token and code are required")
    return
}

// ✗ No format validation - invalid formats passed to service
```

#### Change Required

```go
// In handlers/mfa.go - VerifyMFACode (FIXED)
if req.MFAToken == "" || req.Code == "" {
    pkghttp.WriteBadRequest(w, "mfa_token and code are required")
    return
}

// ✅ NEW: Validate code format before service call
if !isValidTOTPCodeFormat(req.Code) {
    pkghttp.WriteBadRequest(w, "Invalid code format")
    return
}

// ... rest of handler ...

// ✅ NEW: Helper function at end of file
func isValidTOTPCodeFormat(code string) bool {
    // TOTP codes are 6 digits
    // Backup codes are 8 alphanumeric characters
    if len(code) == 6 {
        // Must be all digits
        for _, ch := range code {
            if ch < '0' || ch > '9' {
                return false
            }
        }
        return true
    }
    if len(code) == 8 {
        // Backup codes: alphanumeric only (no special chars)
        for _, ch := range code {
            if !((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z')) {
                return false
            }
        }
        return true
    }
    return false
}
```

#### Implementation Steps

1. Add format validation function to `handlers/mfa.go`
2. Call validation before service method
3. Return 400 Bad Request for invalid format
4. Run `go build -o kamino ./cmd/api`

#### Testing

```go
func TestVerifyMFACode_InvalidFormat_Rejected(t *testing.T) {
    tests := []struct {
        code  string
        valid bool
    }{
        {"123456", true},   // Valid TOTP (6 digits)
        {"ABCD1234", true}, // Valid backup (8 alphanumeric)
        {"12345", false},   // Too short
        {"1234567890", false}, // Too long
        {"12345a", false},  // TOTP with letter
        {"ABCD123!", false}, // Backup with special char
    }

    for _, tt := range tests {
        result := isValidTOTPCodeFormat(tt.code)
        assert.Equal(t, tt.valid, result)
    }
}
```

---

### MEDIUM #2: Centralize Server Timeout Configuration

**Severity:** 🟢 MEDIUM
**Effort:** 1-2 hours
**Risk:** Very Low (configuration refactor)
**Status:** Completed

#### Problem Statement

Server read/write/idle timeouts are hardcoded in `cmd/api/main.go` instead of being in the config struct. This is inconsistent with auth timeouts (which are configurable) and makes it difficult to tune timeouts for different environments.

#### Files to Modify

1. **`internal/config/config.go`** (add ServerConfig fields)
2. **`cmd/api/main.go`** (use config values)

#### Current Code

```go
// In cmd/api/main.go (~line 214-216)
server := &http.Server{
    Addr:         ":" + cfg.Server.Port,
    Handler:      router,
    ReadTimeout:  15 * time.Second,      // ✗ Hardcoded
    WriteTimeout: 15 * time.Second,      // ✗ Hardcoded
    IdleTimeout:  60 * time.Second,      // ✗ Hardcoded
}
```

#### Change Required

```go
// In internal/config/config.go - ServerConfig struct
type ServerConfig struct {
    Port         string
    TrustedProxies []string

    // ✅ NEW: Timeout configuration
    ReadTimeout  time.Duration
    WriteTimeout time.Duration
    IdleTimeout  time.Duration
}

// In internal/config/config.go - LoadConfig function
func LoadConfig() (*Config, error) {
    // ... existing code ...

    // ✅ NEW: Load timeout config from env or defaults
    cfg.Server.ReadTimeout = parseDurationEnv("SERVER_READ_TIMEOUT", 15*time.Second)
    cfg.Server.WriteTimeout = parseDurationEnv("SERVER_WRITE_TIMEOUT", 15*time.Second)
    cfg.Server.IdleTimeout = parseDurationEnv("SERVER_IDLE_TIMEOUT", 60*time.Second)

    return cfg, nil
}

// In cmd/api/main.go (~line 214-216)
server := &http.Server{
    Addr:         ":" + cfg.Server.Port,
    Handler:      router,
    ReadTimeout:  cfg.Server.ReadTimeout,   // ✅ From config
    WriteTimeout: cfg.Server.WriteTimeout,  // ✅ From config
    IdleTimeout:  cfg.Server.IdleTimeout,   // ✅ From config
}
```

#### Implementation Steps

1. Add timeout fields to `ServerConfig` struct
2. Add env var parsing in `LoadConfig()`
3. Update `main.go` to use config values
4. Run `go build -o kamino ./cmd/api`

#### Environment Variables

```bash
SERVER_READ_TIMEOUT=15s
SERVER_WRITE_TIMEOUT=15s
SERVER_IDLE_TIMEOUT=60s
```

---

### MEDIUM #3: Improve Device Fingerprinting for Rate Limiting

**Severity:** 🟢 MEDIUM
**Effort:** 3-4 hours
**Risk:** Medium (changes rate limit logic)
**Status:** On Hold -- seen as overkill

#### Problem Statement

Current device fingerprinting only uses IP + User-Agent. This has limitations:
- User-Agent easily spoofed
- Same office (same IP) affects multiple users
- Proxy networks (same IP for many devices)

#### Solution

Add secondary signals to fingerprinting:
- Accept-Language header
- Accept-Encoding header
- Browser type detection
- Time zone (if available)

#### Files to Modify

1. **`internal/services/rate_limit_service.go`** (generateDeviceFingerprint method)
2. **`internal/handlers/auth.go`** (extract additional headers)

#### Implementation Steps

1. Extend `generateDeviceFingerprint()` to hash additional headers
2. Update auth handler to pass additional context
3. Increase fingerprint entropy
4. Run `go test ./internal/services -run RateLimit -v`

---

## TIER 3: LOW PRIORITY ISSUES (IMPLEMENT WITHIN 1 MONTH)

---

### LOW #1: Add User-Agent Length Validation

**Severity:** 🟢 LOW
**Effort:** 30 minutes
**Risk:** Very Low
**Status:**

Add validation before hashing User-Agent to prevent extremely long headers from causing issues.

---

### LOW #2: Improve Timing Delay Error Handling

**Severity:** 🟢 LOW
**Effort:** 1 hour
**Risk:** Very Low
**Status:**

Add logging if crypto/rand fails during timing delay generation (currently silently discarded).

---

### LOW #3: Create Test Fixtures and Builders

**Severity:** 🟢 LOW
**Effort:** 5-10 hours
**Risk:** Very Low

Create `/tests/fixtures/` with seed data and builder functions for tests:
- `NewTestUser()`
- `NewTestToken()`
- `NewTestLoginAttempt()`
- etc.

---

## IMPLEMENTATION ROADMAP

### Week 1: Critical Blockers (8-10 hours)

**Must complete before any deployment:**

| Item | Effort | Order | Dependencies |
|------|--------|-------|--------------|
| BLOCKER #1: Revocation fail-open | 0.5h | 1 | None |
| BLOCKER #2: Security test framework | 2-3h | 2 | None |
| BLOCKER #3: MFA token revocation | 2-3h | 3 | BLOCKER #1 |
| BLOCKER #4: Email service hard-fail | 1-2h | 4 | None |
| BLOCKER #5: CSRF goroutine shutdown | 1-2h | 5 | None |

**Total Week 1:** 8-10 hours

### Week 2: High Priority Tests (50-55 hours) - Can parallelize

**Run these in parallel after blockers are fixed:**

| Item | Effort | Dependencies |
|------|--------|--------------|
| HIGH #1: CSRF shutdown (already done) | - | BLOCKER fixes |
| HIGH #2: MFA service tests | 20-25h | Code reviewed |
| HIGH #3: AuthService tests | 20-25h | Code reviewed |
| HIGH #4: Integration tests | 25-30h | Both above done |

**Suggested parallelization:**
- Developer A: MFA tests (20-25h)
- Developer B: AuthService tests (20-25h)
- Developer C: Integration tests (25-30h, starts after A & B)

### Week 3: Medium Priority (5-10 hours)

| Item | Effort | Dependencies |
|------|--------|--------------|
| MEDIUM #1: TOTP format validation | 1h | None |
| MEDIUM #2: Centralize timeouts | 1-2h | Config review |
| MEDIUM #3: Fingerprinting | 3-4h | Tests pass |

**Total Week 3:** 5-10 hours

### Week 4: Low Priority & Cleanup (10-15 hours)

- Create test fixtures
- Improve error handling
- Add documentation
- Final testing

---

## CRITICAL PATH ANALYSIS

**Minimum viable path to production (70-85 hours):**

1. Fix all 5 blockers (8-10 hours) ← BLOCKING
2. Add service-layer tests (40-50 hours) ← REQUIRED
3. Add integration tests (25-30 hours) ← REQUIRED
4. Code review & fixes (10 hours)
5. Final testing (5-10 hours)

**Total: 88-110 hours (2.5-3 weeks for 1 developer, 1-2 weeks for 2 developers)**

---

## SUCCESS CRITERIA

### Checklist: Production Ready

- [ ] All 5 blockers fixed and tested
- [ ] All handler tests passing (35 cases)
- [ ] All service-layer tests added and passing (50+ cases)
- [ ] All integration tests added and passing (12+ cases)
- [ ] Security tests all passing (including privilegeescalation)
- [ ] Build succeeds: `go build -o kamino ./cmd/api`
- [ ] All existing tests still pass: `go test ./...`
- [ ] Code review completed
- [ ] Documentation updated
- [ ] Deployment tested in staging

### Metrics to Track

```
Test Coverage:
  - Overall: target 70%+
  - Auth handlers: 100%
  - Auth services: 90%+
  - Security: 100%

Build Status:
  - Zero warnings
  - Zero linting errors

Deployment:
  - Graceful shutdown < 5 seconds
  - No resource leaks
  - Email service validation at startup
```

---

## DEPENDENCIES & CONFLICTS

### No Conflicts

All fixes can be implemented independently without conflicts:
- Blocker fixes don't conflict with tests
- Tests can run in parallel
- Configuration changes are backward compatible

### Dependencies

```
BLOCKER #1 (revocation)
  ↓
BLOCKER #3 (MFA revocation) - requires BLOCKER #1

BLOCKER #2 (security test)
  ← Independent

BLOCKER #4 (email hard-fail)
  ← Independent

BLOCKER #5 (CSRF shutdown)
  ← Independent

HIGH #2 & #3 (MFA & Auth tests)
  ← Can run in parallel
  ← Depend on code being correct (requires blockers fixed)

HIGH #4 (Integration tests)
  ← Depends on HIGH #2 & #3 passing
```

---

## ROLLBACK PLAN

Each fix can be rolled back independently:

| Fix | Rollback Method | Risk |
|-----|-----------------|------|
| BLOCKER #1 | Revert 2 lines | None |
| BLOCKER #2 | Revert test file | None |
| BLOCKER #3 | Remove revocation call | Low |
| BLOCKER #4 | Add graceful degradation | Low |
| BLOCKER #5 | Remove stop channel | Low |
| Tests | Delete test files | None |

---

## MONITORING & OBSERVABILITY

### Metrics to Add

```go
// In handlers
metrics.IncrCounter("auth.login.attempt", "success", bool)
metrics.IncrCounter("auth.mfa.verify.attempt", "success", bool)
metrics.IncrCounter("token.revocation.request", "token_type", type)
metrics.GaugeSet("csrf.tokens.valid", count)

// In services
metrics.RecordHistogram("auth.login.duration_ms", duration)
metrics.RecordHistogram("token.refresh.duration_ms", duration)
```

### Logging to Add

```go
// At startup
logger.Info("revocation config", slog.Bool("fail_closed", cfg.Auth.Revocation.FailClosed))
logger.Info("email verification", slog.Bool("required", cfg.Email.Required))

// On critical path
logger.Warn("rate_limit_exceeded", slog.String("email", email))
logger.Warn("mfa_replay_detected", slog.String("user_id", userID))
```

---

## SIGN-OFF

This fix plan is ready for implementation. All items are scoped, estimated, and dependencies are clear.

**Next Steps:**
1. Assign developers to critical path items
2. Start with BLOCKER fixes (parallel possible)
3. Run blockers by end of week 1
4. Begin test implementation by start of week 2

---

**Document Version:** 1.0
**Last Updated:** 2026-02-19
**Status:** Ready for Development
