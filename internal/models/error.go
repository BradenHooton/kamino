package models

import "errors"

// Sentinel errors for common failure conditions
var (
	ErrNotFound       = errors.New("resource not found")
	ErrConflict       = errors.New("resource already exists")
	ErrUnauthorized   = errors.New("unauthorized")
	ErrForbidden      = errors.New("forbidden")
	ErrBadRequest     = errors.New("bad request")
	ErrInternalServer = errors.New("internal server error")

	// Account state errors
	ErrAccountDisabled    = errors.New("account is disabled")
	ErrAccountSuspended   = errors.New("account is suspended")
	ErrAccountLocked      = errors.New("account is temporarily locked")
	ErrEmailNotVerified   = errors.New("email address not verified")

	// Rate limiting errors
	ErrRateLimitExceeded      = errors.New("rate limit exceeded")
	ErrTooManyFailedAttempts  = errors.New("too many failed login attempts")
	ErrAccountLockedBySystem  = errors.New("account locked due to failed login attempts")

	// MFA errors
	ErrMFARequired        = errors.New("mfa_required")
	ErrMFAInvalidCode     = errors.New("mfa_invalid_code")
	ErrMFARateLimited     = errors.New("mfa_rate_limited")
	ErrMFADeviceNotFound  = errors.New("mfa_device_not_found")
	ErrInvalidMFAToken    = errors.New("invalid_mfa_token")
)
