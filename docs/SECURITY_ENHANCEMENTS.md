# Security Enhancements Implementation

This document describes the three major security enhancements implemented in Kamino to address critical authentication vulnerabilities.

## Overview

### Problems Addressed

1. **IP-based rate limiting can be bypassed** - Attackers using proxies/VPNs/Tor could bypass IP-based rate limits
2. **JWT tokens vulnerable to XSS** - Tokens stored in localStorage are accessible to malicious JavaScript
3. **Timing attacks possible** - Differences in response time could leak whether a user exists

### Solutions Implemented

- **Enhanced Rate Limiting** - Multi-level rate limiting (account-based, IP-based, device-based) with progressive lockouts
- **Secure Token Storage** - httpOnly cookies for refresh tokens + CSRF protection
- **Timing Attack Prevention** - Constant-time delays on authentication failures

---

## 1. Enhanced Rate Limiting

### Architecture

#### Database Schema

A new `login_attempts` table tracks all login attempts (success and failure) with TTL-based cleanup:

```sql
CREATE TABLE login_attempts (
    id UUID PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    attempt_time TIMESTAMP,
    success BOOLEAN,
    failure_reason VARCHAR(100),
    device_fingerprint VARCHAR(255),
    expires_at TIMESTAMP
);
```

#### Rate Limiting Levels

1. **Account-Based (Email)**
   - Max 5 failed attempts per 15 minutes
   - Triggers account lockout for 15 minutes
   - Progressive lockouts increase duration for repeated violations

2. **IP-Based**
   - Max 20 attempts (any status) per 15 minutes
   - Returns 429 Too Many Requests

3. **Device-Based (IP + User-Agent Hash)**
   - Max 10 attempts per 15 minutes
   - Returns 429 Too Many Requests

### Integration Points

**AuthService.Login() now:**
1. Extracts IP address and User-Agent from request
2. Checks rate limits BEFORE password validation
3. Records both success and failure with device fingerprint
4. Returns appropriate errors (429, 401, or generic 401)

**Handler (handlers/auth.go):**
```go
ipAddress := pkghttp.ExtractClientIP(r)
userAgent := r.Header.Get("User-Agent")
authResp, err := h.service.Login(ctx, email, password, ipAddress, userAgent)
```

### Configuration

```bash
MAX_FAILED_ATTEMPTS_PER_EMAIL=5
EMAIL_LOCKOUT_DURATION=15m
MAX_ATTEMPTS_PER_IP=20
MAX_ATTEMPTS_PER_DEVICE=10
RATE_LIMIT_LOOKBACK_WINDOW=15m
```

### Monitoring

- Track `login_attempts` table size growth
- Alert if rate limit checks start failing (DB unavailable)
- Monitor spike in 429 responses (potential attack)

---

## 2. Secure Token Storage & CSRF Protection

### Token Storage Modes

#### Cookie Mode (New - Recommended)

**Request Header:** `X-Auth-Mode: cookie`

**Response:**
```json
{
  "access_token": "eyJhb...",
  "csrf_token": "abc123...",
  "user": { ... }
}
```

**Token Storage:**
- Access token → sessionStorage (JavaScript can access)
- Refresh token → httpOnly cookie (JavaScript cannot access)
- CSRF token → sessionStorage (JavaScript sends in header)

**Subsequent Requests:**
- Authorization: Bearer <access_token>
- X-CSRF-Token: <csrf_token>
- Cookie: refresh_token=... (automatic)

#### JSON Mode (Legacy - Backward Compatible)

**No special header needed**

**Response:**
```json
{
  "access_token": "eyJhb...",
  "refresh_token": "xyz789...",
  "user": { ... }
}
```

Old clients continue to work unchanged.

### Cookie Security

Cookies are configured with:
- **HttpOnly**: JavaScript cannot access (XSS protection)
- **Secure**: HTTPS only (in production)
- **SameSite=Strict**: No cross-origin cookie sending (CSRF protection)
- **Domain**: Empty in development, explicit in production

### CSRF Protection

**CSRF Middleware** (`internal/middleware/csrf.go`):
- Validates CSRF tokens on POST/PUT/DELETE/PATCH
- Extracts token from `X-CSRF-Token` header or cookie
- Returns 403 Forbidden if missing/invalid
- Only applies to authenticated requests

**Token Lifecycle:**
- Generated on login (24-hour TTL)
- Stored in-memory with automatic cleanup
- Revoked on logout
- Regenerated on token refresh

### Configuration

```bash
COOKIE_DOMAIN=              # Empty = current host
COOKIE_SECURE=false         # Set true in production
COOKIE_SAME_SITE=strict     # strict, lax, or none
```

### Frontend Migration

**Phase 1 (Backward Compatibility):**
- Deploy with dual-mode support
- Existing clients use JSON mode

**Phase 2 (Adoption):**
- Update frontend to use cookie mode
- Send `X-Auth-Mode: cookie` header on login
- Store tokens in sessionStorage
- Send CSRF token in X-CSRF-Token header on mutations

**Phase 3 (Deprecation):**
- Monitor adoption (track X-Auth-Mode header)
- After 90 days, deprecate JSON mode

---

## 3. Timing Attack Prevention

### Problem

Different code paths take different amounts of time:
- User not found: Returns early (fast)
- Wrong password: Validates hash (slower)
- Account locked: Checks status (variable)

Attackers can measure response times to enumerate users.

### Solution

All authentication failures incur constant-time delay: **500ms + random(0-500ms)**

### Implementation

**Defer-based approach** ensures delay runs regardless of early returns:

```go
func (s *AuthService) Login(ctx context.Context, email, password, ip, ua string) (*AuthResponse, error) {
    startTime := time.Now()
    var authErr error

    // Defer applies delay if authErr is set (failure case)
    defer func() {
        if authErr != nil {
            s.timingDelay.WaitFrom(startTime, false)
        }
    }()

    // ... authentication logic ...
    // If anything fails, set authErr = someError, all paths get delayed
}
```

### Configuration

```bash
TIMING_DELAY_BASE_MS=500        # Base delay in ms
TIMING_DELAY_RANDOM_MS=500      # Random range in ms
TIMING_DELAY_ON_SUCCESS=false   # Only delay failures
```

### Performance Impact

- All failures: ~500-1000ms (typical range)
- Successful login: ~0ms (immediate)
- No impact on legitimate users

---

## Database Migration

Run migration to create `login_attempts` table:

```bash
goose postgres "postgres://user:pass@localhost/kamino" up
```

This creates the table with optimized indexes for:
- Email + time lookups
- IP address + time lookups
- Device fingerprint + time lookups
- Expiration-based cleanup

---

## Testing

### Unit Tests

```bash
go test ./internal/auth -run TestCSRF
go test ./internal/auth -run TestTiming
go test ./internal/services -run TestRateLimit
```

### Manual Testing

**Rate Limiting:**
```bash
for i in {1..6}; do
  curl -X POST http://localhost:8000/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"wrong"}'
done
# 6th attempt returns 429 Too Many Requests
```

**Cookie Mode:**
```bash
curl -i -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Auth-Mode: cookie" \
  -d '{"email":"admin@example.com","password":"password"}'

# Check response headers:
# - Set-Cookie: refresh_token=...;HttpOnly;Secure;SameSite=Strict
# - Set-Cookie: csrf_token=...;Secure;SameSite=Strict
```

**Timing:**
```bash
time curl -X POST http://localhost:8000/auth/login \
  -d '{"email":"nonexistent@example.com","password":"test"}'
# ~500-1000ms

time curl -X POST http://localhost:8000/auth/login \
  -d '{"email":"existing@example.com","password":"wrong"}'
# ~500-1000ms (similar)
```

---

## API Changes

### Backward Compatibility

✅ **Fully backward compatible**

- Old clients continue to use JSON mode
- New clients opt-in via `X-Auth-Mode: cookie` header
- All endpoints function with both modes

### New Error Codes

- **429 Too Many Requests** - Rate limit exceeded
- **403 Forbidden** - CSRF token missing/invalid

### New Request Headers

- `X-Auth-Mode: cookie` - Request cookie-based auth
- `X-CSRF-Token: <token>` - CSRF protection on mutations

### New Response Headers

- `Set-Cookie: refresh_token=...` - Refresh token (httpOnly)
- `Set-Cookie: csrf_token=...` - CSRF token

### Response Format (Cookie Mode)

```json
{
  "access_token": "eyJhb...",
  "csrf_token": "abc123...",
  "user": {
    "id": "...",
    "email": "...",
    "name": "..."
  }
}
```

---

## Deployment Checklist

- [ ] Run database migration: `goose up`
- [ ] Set environment variables (see .env.example)
- [ ] Build and deploy new code
- [ ] Monitor logs for rate limit blocks
- [ ] Test cookie mode with staging frontend
- [ ] Verify timing delays (response times ~500-1000ms for failures)
- [ ] Confirm cleanup job removes expired login attempts
- [ ] Update API documentation
- [ ] Brief frontend team on migration plan

---

## Monitoring & Alerts

### Key Metrics

- `auth.rate_limit.blocked_total` - Cumulative rate limit blocks
- `auth.csrf.validation_failures_total` - CSRF validation failures
- `auth.login.duration_seconds` - Login endpoint latency (should include delays)
- `auth.login_attempts.per_email` - Distribution of attempts by email

### Alert Conditions

- Rate limit DB query fails (security risk, fail-open behavior)
- Spike in rate limit blocks (potential brute force attack)
- CSRF validation failures > 5% (misconfiguration or attack)
- Login attempts > 100 per unique email in 15 min window (attack)

---

## Limitations & Future Work

### Current Limitations

1. **In-memory CSRF tokens** - Lost on server restart (acceptable for stateless design)
   - Future: Persist to Redis for multi-server deployments

2. **Simple progressive lockout** - Currently uses fixed duration
   - Future: Track lockout history, increase multiplier for repeat offenders

3. **Device fingerprinting** - Basic IP + User-Agent hash
   - Future: TLS fingerprint, WebGL canvas fingerprint for better tracking

### Recommended Future Enhancements

- [ ] Redis-based CSRF token store for distributed systems
- [ ] Adaptive rate limiting (machine learning on attack patterns)
- [ ] Geographic anomaly detection (impossible travel)
- [ ] Device trust scoring (remember trusted devices)
- [ ] Two-factor authentication integration
- [ ] Risk-based authentication (step-up auth for suspicious attempts)

---

## Security Best Practices Applied

✅ **Defense-in-Depth** - Multiple independent layers (IP + account + device)
✅ **Constant-Time Operations** - Prevent timing-based user enumeration
✅ **HttpOnly Cookies** - Protect refresh tokens from XSS
✅ **CSRF Protection** - Prevent cross-site request forgery
✅ **Progressive Lockouts** - Escalating delays for persistent attacks
✅ **Audit Logging** - Track all authentication events
✅ **Secure Defaults** - Strict SameSite, Secure flag in production
✅ **Backward Compatibility** - Graceful migration path for clients

---

## References

- OWASP: [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- OWASP: [Rate Limiting Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Rate_Limiting_Cheat_Sheet.html)
- OWASP: [Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf)
- CWE-208: [Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)
- MDN: [HTTP Cookies - Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security)
