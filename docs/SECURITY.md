# Security Documentation

This document outlines the security enhancements implemented in Kamino's authentication system and HTTP request handling.

## Overview

Kamino implements a defense-in-depth approach with three major security hardening initiatives:

1. **CORS Protection** - Prevents unauthorized cross-origin requests
2. **Strong Password Validation** - Enforces cryptographically sound password policies
3. **Sensitive Data Protection** - Eliminates PII exposure and prevents user enumeration

---

## 1. CORS Protection

### Why JWT-in-Header Architecture Doesn't Need Traditional CSRF Protection

Kamino uses JWT tokens transmitted in the `Authorization` header, which provides inherent CSRF resistance:

- **Browser Security Policy**: Browsers cannot automatically include custom headers in cross-origin requests
- **Preflight Requests**: Cross-origin requests with custom headers trigger CORS preflight (OPTIONS) requests
- **Origin Validation**: The server validates the Origin header before responding

This is fundamentally different from cookie-based authentication, where credentials are automatically sent with cross-origin requests, requiring CSRF tokens.

### CORS Configuration

The CORS middleware validates request origins against a whitelist before setting response headers.

#### Development Environment

In development, localhost variants are automatically whitelisted:
```
http://localhost:3000
http://localhost:8080
http://localhost:5173  (Vite default)
http://127.0.0.1:3000
http://127.0.0.1:8080
http://127.0.0.1:5173
```

#### Production Environment

Production requires explicit origin whitelisting via environment variable:

```bash
ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com,https://api.example.com
```

### CORS Headers

The middleware sets the following response headers for allowed origins:

```
Access-Control-Allow-Origin: <origin>
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Expose-Headers: Content-Length, Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 3600
```

### Implementation Details

- **File**: `internal/middleware/cors.go`
- **Configuration**: `internal/config/config.go` (ServerConfig.AllowedOrigins)
- **Registration**: `cmd/api/main.go` (registered after RealIP, before Logger)

---

## 2. Strong Password Validation

### Password Requirements

All new user registrations and password changes are validated against these requirements:

- **Length**: 8-128 characters
- **Uppercase**: At least one uppercase letter (A-Z)
- **Lowercase**: At least one lowercase letter (a-z)
- **Digits**: At least one numeric digit (0-9)
- **Special Characters**: At least one punctuation or symbol character (!@#$%^&* etc.)
- **Common Password Blacklist**: Rejects commonly-guessed passwords (password, 12345678, qwerty, etc.)

### Error Messages

When validation fails, users receive a detailed message with specific requirements:

```
password requirements not met: must contain at least one uppercase letter
```

### Implementation Details

- **File**: `pkg/auth/password.go`
- **Type**: `PasswordValidationError` with `Errors []string` field
- **Validation**: Checked in `AuthService.Register()` and `UserService.CreateUser()`
- **Handler Response**: 400 Bad Request with detailed error message

### User Communication

Applications should inform users of password requirements during registration:

```
Password must contain:
- At least 8 characters (max 128)
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character (!@#$%^&* etc.)
```

---

## 3. Sensitive Data Protection

### Audit Logging

Kamino implements comprehensive audit logging for security-relevant events without exposing PII:

#### Logged Events

**Authentication Attempts**
- `login_success`: User successfully authenticated
  - Fields: user_id, timestamp
- `login_failed`: Failed login attempt
  - Fields: failure_reason (invalid_credentials, email_not_verified, account_blocked)
  - **Never includes**: email address, password attempt, or detailed user info

**Account Management**
- `user_registered`: New user registration
  - Fields: user_id, timestamp
- `password_change`: Password modification
  - Fields: user_id, success status, timestamp

### Request Logging

The `SecureLogger` middleware logs all HTTP requests with sensitive parameter redaction:

#### Sanitized Query Parameters

If any of these parameters appear in the query string, the entire query string is replaced with `[REDACTED]`:

- `password`
- `token`
- `secret`
- `api_key` / `apikey`
- `email`
- `apitoken`
- `auth`
- `csrf`

Example:
```
GET /api/users?email=test@example.com&role=admin
```
Logged as:
```
GET /api/users?[REDACTED]
```

#### Request Log Format

```json
{
  "timestamp": "2025-02-16T10:30:45Z",
  "level": "INFO",
  "message": "http_request",
  "method": "POST",
  "path": "/auth/login",
  "status": 200,
  "bytes": 1024,
  "duration": "42.5ms",
  "request_id": "abc123def456",
  "remote_addr": "203.0.113.45:54321"
}
```

### Email Privacy - No Enumeration

Failed login attempts intentionally use the same error message regardless of whether the email exists:

```
401 Unauthorized: "Invalid email or password"
```

**Previous behavior (vulnerable):**
```
User not found: user@example.com
Invalid password for: user@example.com
```

This prevents attackers from enumerating valid email addresses through error message analysis.

### Implementation Details

**Files:**
- `pkg/logger/audit.go` - AuditLogger with event types
- `pkg/logger/sanitize.go` - Query parameter sanitization
- `internal/middleware/logging.go` - SecureLogger middleware
- `internal/services/auth_service.go` - Audit event logging
- `internal/services/user_service.go` - Removed email logging
- `cmd/api/main.go` - Middleware registration

**Logger Configuration:**
```go
// Create audit logger
auditLogger := pkglogger.NewAuditLogger(logger)

// Register secure request logger (replaces Chi's default)
router.Use(middlewareCustom.SecureLogger(logger))
```

---

## Testing & Verification

### Manual CORS Testing

```bash
# Test with disallowed origin (should not return Access-Control-Allow-Origin)
curl -i -H "Origin: https://evil.com" http://localhost:8080/health

# Test with allowed origin (should return Access-Control-Allow-Origin header)
curl -i -H "Origin: http://localhost:3000" http://localhost:8080/health

# Test preflight request
curl -i -X OPTIONS \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST" \
  http://localhost:8080/auth/login
```

### Password Validation Testing

```bash
# Test weak password (too short)
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"weak","name":"Test"}'
# Response: 400 Bad Request

# Test strong password
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecureP@ss123","name":"Test"}'
# Response: 201 Created

# Test common password rejection
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Password123!","name":"Test"}'
# Response: 400 Bad Request (if "password123" is in blacklist)
```

### Audit Log Verification

```bash
# Verify no email addresses in logs
docker logs kamino-api | grep -i email
# Expected: No results

# Verify audit events are logged
docker logs kamino-api | grep "audit_type"
# Expected: audit_type: "auth", "account", or "password"

# Verify query parameter redaction
docker logs kamino-api | grep "REDACTED"
# Expected: Sensitive parameters redacted
```

### Secure Logger Testing

```bash
# Check request logging (should not include email in query string)
curl http://localhost:8080/users?email=test@example.com
# Log should show: GET /users?[REDACTED]

# Check status and duration are logged
curl http://localhost:8080/health
# Log should include: status: 200, duration: <time>ms
```

---

## Environment Variables

### CORS Configuration

**ALLOWED_ORIGINS** (Production Only)
- Comma-separated list of allowed origins
- Example: `ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com`
- Default in dev: Localhost variants auto-allowed
- Default in prod: Empty (no origins allowed unless explicitly listed)

### Logging Configuration

No additional environment variables required. Logging uses existing configuration.

---

## Compliance & Best Practices

### OWASP Top 10 Coverage

1. **A01:2021 – Broken Access Control**: CORS enforcement
2. **A02:2021 – Cryptographic Failures**: Strong password enforcement
3. **A04:2021 – Insecure Design**: Defense-in-depth approach
4. **A09:2021 – Security Logging and Monitoring**: Audit logging implementation

### PII Protection

- ✅ Email addresses not logged in application logs
- ✅ Password attempts not logged
- ✅ Query parameters with sensitive data redacted
- ✅ Audit logs use user_id, not email
- ✅ Generic error messages prevent user enumeration

### Deployment Checklist

- [ ] Set `ENV=production` in production
- [ ] Configure `ALLOWED_ORIGINS` with exact domain list
- [ ] Verify `JWT_SECRET` is at least 32 characters
- [ ] Enable log aggregation and monitoring
- [ ] Review audit logs for suspicious activity patterns
- [ ] Test CORS headers with authorized origins
- [ ] Verify password validation in staging environment

---

## Future Enhancements

- [ ] Rate limiting on authentication endpoints
- [ ] Account lockout after N failed login attempts
- [ ] Multi-factor authentication (MFA) support
- [ ] Password history (prevent reuse)
- [ ] Regular security audits of authentication flow
- [ ] Integration with SIEM systems for audit log analysis
- [ ] Monitoring for suspicious auth patterns (geographic anomalies, device fingerprints)

---

## References

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [MDN: CORS Documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [Go slog Package Documentation](https://pkg.go.dev/log/slog)
- [Chi Router Middleware Guide](https://pkg.go.dev/github.com/go-chi/chi/v5#pkg-subdirectories)
