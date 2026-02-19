# Email Verification Architecture

## Overview

This document defines the architecture and strategy for implementing email verification in Kamino. Email verification ensures users control the email addresses associated with their accounts and prevents invalid/malicious email registrations.

---

## 1. Core Requirements & Principles

### Functional Requirements
- **Verification on Registration**: New users must verify email before full account activation
- **Resend Mechanism**: Users can request new verification emails if the original expires or is lost
- **Expiration Handling**: Verification tokens expire after a configurable period (default: 24 hours)
- **Account States**: Accounts can be in different states based on verification status
- **Verification Email Links**: Tokens delivered via email for one-click verification

### Non-Functional Requirements
- **Security**: Tokens are cryptographically secure, single-use, and time-bound
- **Auditability**: Verification events logged for compliance and debugging
- **Scalability**: Efficient token storage and cleanup
- **User Experience**: Clear status feedback and clear next steps for users

### Security Principles
- Tokens cannot be reused after verification
- Tokens are invalidated on account deletion
- Tokens use secure random generation (same pattern as existing token infrastructure)
- Email verification does not require additional authentication factors
- Links are valid for a limited time and cannot be guessed

---

## 2. System Architecture

### 2.1 Data Model

#### User Model Enhancement
The `User` model already contains `email_verified` boolean. Extend with:
- Current verification status tracking
- Timestamp of last verification email sent (for rate limiting resends)
- Timestamp of email verification (when user confirmed)

#### New Entity: Email Verification Token
Separate table for verification tokens:

```
EmailVerificationToken
├── id (UUID, primary key)
├── user_id (UUID, foreign key to users)
├── token (string, hashed/encrypted)
├── email (string, the email being verified)
├── expires_at (timestamp)
├── used_at (timestamp, NULL if unused)
├── created_at (timestamp)
└── is_revoked (boolean, for explicit invalidation)
```

**Design Rationale**:
- Separates verification concerns from user table (follows single responsibility)
- Enables audit trail of verification attempts
- Allows multiple tokens per user (if one is lost)
- Efficient cleanup of expired tokens
- Email field stored separately to support email change flows in future

### 2.2 Workflow States

```
User Registration Flow:
┌─────────────┐
│  Registering│  User submits email + password
└──────┬──────┘
       │
       v
┌──────────────────────┐
│  Email Unverified    │  Account created, email_verified=false
│  (Restricted Access) │  Verification token generated & sent
└──────┬───────────────┘
       │
       ├─ Token Valid & Clicked ──────────┐
       │                                  │
       ├─ Token Expires (24h) ────────────┤──> Email Resend Requested
       │                                  │
       └─ User Requests Resend ───────────┘
                 │
                 v
        ┌─────────────────────┐
        │ New Token Generated │  Token sent via email
        └──────┬──────────────┘
               │
               v
    ┌──────────────────────┐
    │ Email Verified ✓     │  email_verified=true
    │ (Full Access)        │  used_at timestamp recorded
    └──────────────────────┘
```

---

## 3. Component Architecture

### 3.1 Database Layer

**New Migration**: `006_create_email_verification_tokens.sql`

Contains:
- Email verification tokens table
- Index on `user_id` for lookup by user
- Index on `expires_at` for cleanup queries
- Composite index on `user_id, email` for preventing duplicate pending verifications
- Trigger to automatically clean up used/expired tokens (optional, can be background job)

**Repository Pattern**:
- New `EmailVerificationRepository` handling:
  - Token creation (CRUD)
  - Token lookup and validation
  - Token expiration checks
  - Token revocation (mark as used or revoked)
  - Cleanup of expired/used tokens

### 3.2 Service Layer

**New Service**: `EmailVerificationService`

Responsibilities:
- **Token Generation**: Create secure, random verification tokens
- **Token Validation**: Verify token format, expiration, and revocation status
- **Email Trigger**: Integration point for email sending (delegates to external service)
- **State Transitions**: Manage user progression through verification states
- **Resend Logic**: Implement rate limiting and duplicate token prevention

Key Methods:
- `GenerateVerificationToken(ctx, userID, email)` → token string
- `VerifyToken(ctx, token)` → (userID, email, error)
- `ConfirmEmailVerification(ctx, token)` → (user, error)
- `RequestResendVerification(ctx, userID)` → (success, error)
- `GetVerificationStatus(ctx, userID)` → VerificationStatus

### 3.3 Handler Layer

**Extend Existing Handlers**:

1. **Registration Handler** (`/auth/register`)
   - On successful user creation, automatically trigger token generation
   - Return response with message: "Verification email sent to user@example.com"
   - Do not allow login until email is verified (prevent unverified login)

2. **New Verify Email Handler** (`POST /auth/verify-email`)
   - Accept verification token from URL/form
   - Call service to confirm verification
   - Return success response
   - Optionally auto-login user after verification

3. **New Resend Handler** (`POST /auth/resend-verification`)
   - Requires authentication or email + rate limit by email
   - Rate limit: 3 resend requests per hour per email
   - Generate new token, invalidate old tokens
   - Send new email

4. **Status Handler** (optional, `GET /auth/verification-status`)
   - Returns current verification state for authenticated user
   - Useful for frontend to show status

---

## 4. Email Integration

### 4.1 Email Service Interface

Define clear abstraction for email sending:

```
EmailService Interface:
├── SendVerificationEmail(ctx, email, token, expiresIn) → error
└── (Future) SendPasswordReset, SendNotifications, etc.
```

**Implementation Options**:
1. **Queue-Based** (Recommended): Push email jobs to background queue (existing Asynq setup)
   - Async processing improves performance
   - Retries on failure
   - Logging and monitoring
   
2. **Direct**: Send via third-party API (SendGrid, Mailgun, AWS SES)
   - Simpler initial implementation
   - No queue infrastructure needed

### 4.2 Email Content

Verification email should contain:
- **Clickable Link**: `https://app.example.com/verify?token=TOKEN` 
- **Copy-Paste Token**: For users who can't click links
- **Expiration Notice**: "This link expires in 24 hours"
- **Security Notice**: "If you didn't request this, you can safely ignore it"
- **Support Contact**: Link to support if issues

---

## 5. Rate Limiting & Protection

### 5.1 Verification Endpoints Rate Limits
- `/auth/verify-email`: 10 attempts per minute per IP (prevent brute-force)
- `/auth/resend-verification`: 3 requests per hour per email (prevent spam)

### 5.2 Token Protection
- Tokens are single-use (marked as used immediately upon verification)
- Invalid token attempts logged and monitored
- Multiple failed verification attempts could trigger account review

### 5.3 Account Registration Rate Limiting
- New registrations rate limited by IP (existing mechanism)
- Consider additional limits: `n` accounts per IP per day

---

## 6. Database Schema Evolution

### Migration Strategy
1. **Phase 1**: Create email verification tokens table
   - Add necessary indexes
   - No changes to users table (email_verified already exists)

2. **Phase 2** (Optional, Future): Add verification metadata to users
   - `verified_at` timestamp
   - `last_verification_email_sent_at` timestamp

### Data Cleanup Strategy
- **Token Expiration**: Automatic cleanup of tokens older than 30 days
- **Mechanism**: Background job using existing Asynq infrastructure
- **Frequency**: Run daily (configurable)
- **Only Cleanup**: Tokens marked as used OR expired > 30 days

---

## 7. Integration with Existing Components

### 7.1 Authentication Flow
```
Traditional Auth Flow:
Register → Login → Access Protected Resources

New Auth Flow:
Register → Send Verification Email → Verify Email → Access Protected Resources
                                                  (or Login after verification)
```

**Decision Point**: Should unverified users be able to:
- **Option A (Restrictive)**: Cannot login until verified. Must complete email verification first.
- **Option B (Flexible)**: Can login but have limited access. Some features require verified email.
- **Recommendation**: Option A for security, Option B for UX

### 7.2 Middleware Integration
- Auth middleware: Check `email_verified` status
- If unverified and accessing restricted endpoint: Return 403 with specific error
- Verification endpoints should be public (no auth required)

### 7.3 Error Handling
- **Invalid Token**: 400 Bad Request, "Invalid or expired verification link"
- **Already Verified**: 400 Bad Request, "Email already verified"
- **User Not Found**: 404 Not Found (don't reveal if email exists)
- **Token Expired**: 400 Bad Request, "Verification link expired. Request a new one."
- **Rate Limit Exceeded**: 429 Too Many Requests

### 7.4 Audit Logging
Log events:
- Verification email sent (email, token created_at)
- Verification link clicked/verified (user_id, email, timestamp)
- Verification resend requested (email, reason)
- Failed verification attempts (token, error reason)

---

## 8. Frontend Integration Points

### API Contracts

**Register Endpoint** (`POST /auth/register`)
```
Response (after user creation):
{
  "status": "success",
  "message": "Account created. Check your email to verify your address.",
  "data": {
    "user_id": "uuid",
    "email": "user@example.com",
    "requires_verification": true
  }
}
```

**Verify Email Endpoint** (`POST /auth/verify-email`)
```
Request:
{
  "token": "verification_token_from_email"
}

Response (Success):
{
  "status": "success",
  "message": "Email verified successfully",
  "data": {
    "user_id": "uuid",
    "access_token": "jwt_token",
    "refresh_token": "jwt_token"
  }
}
```

**Resend Verification Endpoint** (`POST /auth/resend-verification`)
```
Request:
{
  "email": "user@example.com"
}

Response:
{
  "status": "success",
  "message": "Verification email sent to user@example.com"
}
```

---

## 9. Configuration

### Environment Variables
```
# Email Verification Settings
EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS=24
EMAIL_VERIFICATION_CLEANUP_ENABLED=true
EMAIL_VERIFICATION_CLEANUP_INTERVAL_HOURS=24
EMAIL_VERIFICATION_CLEANUP_DAYS_THRESHOLD=30

# Rate Limiting
RESEND_VERIFICATION_RATE_LIMIT=3          # per hour
RESEND_VERIFICATION_RATE_WINDOW_MINUTES=60

# Email Service
EMAIL_SERVICE_TYPE=asynq|direct           # queue vs direct send
EMAIL_FROM_ADDRESS=noreply@kamino.example
EMAIL_VERIFICATION_URL_BASE=https://app.example.com
```

---

## 10. Security Considerations

### Token Security
- Tokens are 32+ characters, cryptographically random
- Stored hashed (bcrypt or argon2) in database
- Never logged or exposed in error messages
- Single-use pattern prevents replay attacks

### Email Enumeration Prevention
- Resend endpoint doesn't confirm if email exists
- Response is generic: "If an account exists, verification email sent"
- Failed resend attempts logged but not exposed to user

### Token Leakage Prevention
- Links sent via email (encrypted in transit with HTTPS)
- Tokens not included in any API response after verification
- Frontend removes token from URL after verification (hash-based routing)

### Future Enhancements
- TOTP/2FA as additional verification method
- Email verification during account recovery
- Support for email change with re-verification

---

## 11. Testing Strategy

### Unit Tests
- Token generation (randomness, uniqueness)
- Token validation (expiration, format, single-use)
- Service business logic (state transitions, rate limiting)

### Integration Tests
- Full verification flow (generate → send → verify)
- Resend flow (rate limiting, token invalidation)
- Cleanup job (expired token removal)
- Email service integration (mock/real email API)

### E2E Tests
- User registration → verification email → click link → account activated
- Resend flow with expiration
- Rate limiting enforcement

---

## 12. Monitoring & Observability

### Metrics to Track
- `email_verification_tokens_created` - Counter
- `email_verification_tokens_verified` - Counter
- `email_verification_tokens_expired` - Counter
- `email_verification_resend_requested` - Counter
- `email_verification_failures` - Counter (by reason)
- `email_verification_time_to_verify` - Histogram (minutes)
- `verification_email_send_duration` - Histogram (milliseconds)

### Alerts
- Verification email send failure rate > 5%
- Unusually high failed verification attempts (potential attack)
- Cleanup job failures

### Logs
- All token generation, verification, and cleanup events
- Failed verification attempts with reason
- Email send success/failure with error details

---

## 13. Implementation Roadmap

### Phase 1: Foundation (Core Feature)
1. Create email verification tokens table & migration
2. Implement `EmailVerificationRepository`
3. Implement `EmailVerificationService`
4. Add verification endpoints to handlers
5. Integrate with registration flow
6. Unit and integration tests

### Phase 2: Enhancement (UX)
1. Implement resend endpoint with rate limiting
2. Add verification status endpoint
3. Auto-login after verification (optional)
4. Frontend integration and error messaging

### Phase 3: Operations (Reliability)
1. Implement background cleanup job
2. Add monitoring and alerting
3. Email service integration (queue-based)
4. E2E testing

### Phase 4: Security Hardening (Optional)
1. Email change verification
2. TOTP integration for high-security accounts
3. Account recovery with email verification

---

## 14. Future Considerations

### Email Change Flow
When user wants to change registered email:
1. Generate verification token for new email
2. Send verification email to new address
3. Only commit email change after verification
4. Optionally notify old email address of change attempt

### Password Reset Integration
Email verification can be used as part of password reset flow:
1. User requests password reset
2. Token sent to registered email
3. Link takes user to password reset form
4. Verification confirms email ownership before allowing reset

### Account Recovery
Email verification central to account recovery:
1. User logs out / loses access
2. Recovery process verifies email ownership
3. Safe way to restore access without compromising other accounts

---

## 15. Related Documentation

- [SECURITY.md](./SECURITY.md) - Existing security controls
- [AUTH_REVIEW.md](./AUTH_REVIEW.md) - Authentication architecture
- [PRD.md](./PRD.md) - Product requirements
