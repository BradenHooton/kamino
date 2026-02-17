# Security Improvements

This document outlines the security improvements implemented to address missing security headers and database performance concerns.

## 1. Security Headers Middleware

### Overview
A new security headers middleware has been implemented in `internal/middleware/security_headers.go` that adds essential HTTP security headers to all API responses.

### Headers Added

#### X-Frame-Options: DENY
- **Purpose**: Clickjacking protection
- **Value**: `DENY` - Prevents the page from being displayed in a frame at all
- **Impact**: Protects against UI redressing attacks where attackers trick users into clicking hidden elements

#### X-Content-Type-Options: nosniff
- **Purpose**: MIME type sniffing prevention
- **Value**: `nosniff` - Forces browser to respect the declared Content-Type
- **Impact**: Prevents browsers from guessing content types, protecting against MIME confusion attacks

#### X-XSS-Protection: 1; mode=block
- **Purpose**: Legacy XSS protection for older browsers
- **Value**: `1; mode=block` - Enables XSS filtering and blocks rendering if XSS is detected
- **Impact**: Extra layer of XSS protection for browsers that support it

#### Referrer-Policy: strict-origin-when-cross-origin
- **Purpose**: Controls referrer information sharing
- **Value**: `strict-origin-when-cross-origin` - Only sends referrer for same-origin requests
- **Impact**: Prevents leaking URLs and query parameters to external sites

#### Content-Security-Policy (CSP)
- **Purpose**: XSS and injection attack prevention
- **Implementation**: Environment-aware policies
  - **Production**: Strict policy restricting inline scripts and styles
    - Only allows resources from same origin
    - Blocks inline styles/scripts
    - Frame ancestors set to 'none'
  - **Development**: More permissive policy for hot reloading and debugging
    - Allows unsafe-inline and unsafe-eval for development tools
    - Supports WebSocket connections for live reload

#### Strict-Transport-Security (HSTS)
- **Purpose**: HTTPS enforcement
- **Value**: `max-age=31536000; includeSubDomains; preload`
- **Implementation**: Only sent in production over HTTPS
- **Impact**: Forces browsers to use HTTPS for future connections (1 year), includes subdomains, and allows preload list inclusion

#### Permissions-Policy
- **Purpose**: Controls browser feature access
- **Restricted**: accelerometer, camera, geolocation, gyroscope, magnetometer, microphone, payment, usb
- **Impact**: Prevents unauthorized access to sensitive browser APIs

### Integration
The middleware is integrated in `cmd/api/main.go` and runs early in the middleware chain (after RequestID and RealIP) to ensure headers are applied to all responses.

```go
router.Use(middlewareCustom.SecurityHeaders(middlewareCustom.SecurityHeadersConfig{Env: cfg.Server.Env}))
```

## 2. Token Revocation Table Indexing

### Current Indexes (Already Present)
The `revoked_tokens` table had solid indexing already in place:

1. **idx_revoked_tokens_jti** (on `jti`)
   - Purpose: Fast lookup for `IsTokenRevoked` queries
   - Used by: Token validation during authentication

2. **idx_revoked_tokens_expires_at** (on `expires_at`)
   - Purpose: Efficient filtering and cleanup of expired tokens
   - Used by: `CleanupExpiredTokens` query

3. **idx_revoked_tokens_user_id** (on `user_id`)
   - Purpose: Finding all revoked tokens for a specific user
   - Used by: `RevokeAllUserTokens` and user-specific token queries

### Performance Optimization Added
**Migration: 004_optimize_revoked_tokens_cleanup.sql**

A partial index has been added:
```sql
CREATE INDEX idx_revoked_tokens_cleanup ON revoked_tokens(expires_at)
WHERE expires_at < CURRENT_TIMESTAMP;
```

**Benefits**:
- Dramatically improves performance of `CleanupExpiredTokens` queries
- The index only includes rows where `expires_at < CURRENT_TIMESTAMP`
- Reduces index size compared to full column index
- Queries targeting expired tokens scan much fewer index entries
- Particularly beneficial as the table grows over time

**Why This Matters**:
The cleanup query `DELETE FROM revoked_tokens WHERE expires_at < $1` benefits from this partial index because:
1. Most rows in the table have future expiry dates (not yet expired)
2. The partial index focuses only on the subset of rows being deleted
3. Database can quickly identify and remove only the relevant expired tokens
4. Reduces disk I/O and query execution time during cleanup operations

## Testing the Security Headers

To verify security headers are being sent, check the response headers:

```bash
curl -i http://localhost:8000/health
```

Expected headers in response:
```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: [policy based on environment]
Permissions-Policy: [restricted features]
Strict-Transport-Security: [only in production over HTTPS]
```

## Database Migrations

Apply the new optimization migration:

```bash
goose postgres "postgres://user:pass@localhost/kamino" up
```

This will create the partial index without any downtime and will not affect existing indexes.

## Security Best Practices Going Forward

1. **CSP Updates**: Review and update CSP policy as frontend requirements change
2. **HSTS Preload**: In production, consider submitting domain to HSTS preload list
3. **Security Headers Testing**: Regularly check headers using tools like:
   - [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
   - [Mozilla Observatory](https://observatory.mozilla.org/)
4. **Token Cleanup**: Ensure `CleanupExpiredTokens` is called regularly (via background job or cron)
5. **Regular Audits**: Audit security headers and indexing strategy quarterly
