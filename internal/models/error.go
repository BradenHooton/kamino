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
)
