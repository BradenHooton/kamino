package handlers

import "time"

// MFA Setup DTOs

// InitiateMFASetupRequest is the request for starting MFA setup
type InitiateMFASetupRequest struct {
	DeviceName string `json:"device_name" validate:"required,max=255"`
}

// InitiateMFASetupResponse contains QR code and backup codes for setup
type InitiateMFASetupResponse struct {
	QRCode      string   `json:"qr_code"`      // Data URL for QR code
	Secret      string   `json:"secret"`       // Base32-encoded secret (for manual entry)
	BackupCodes []string `json:"backup_codes"` // 8 recovery codes
	DeviceID    string   `json:"device_id"`    // Device UUID for verification
	ExpiresAt   time.Time `json:"expires_at"`  // Setup window expiry (15 minutes)
}

// VerifyMFASetupRequest is the request to verify and enable MFA
type VerifyMFASetupRequest struct {
	DeviceID string `json:"device_id" validate:"required"`
	Code     string `json:"code" validate:"required,len=6,numeric"`
}

// VerifyMFASetupResponse confirms successful MFA enablement
type VerifyMFASetupResponse struct {
	Success    bool      `json:"success"`
	MFAEnabled bool      `json:"mfa_enabled"`
	EnrolledAt time.Time `json:"enrolled_at"`
	Message    string    `json:"message"`
}

// Verification DTOs

// VerifyMFACodeRequest is the request to verify an MFA code during login
type VerifyMFACodeRequest struct {
	MFAToken string `json:"mfa_token" validate:"required"`
	Code     string `json:"code" validate:"required,max=20"` // TOTP (6 digits) or backup code (8 chars)
}

// VerifyMFACodeResponse is returned after successful verification
type VerifyMFACodeResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	User         *UserResponseDTO `json:"user"`
}

// MFA Status DTOs

// MFAStatusResponse shows current MFA configuration
type MFAStatusResponse struct {
	MFAEnabled bool             `json:"mfa_enabled"`
	Devices    []MFADeviceInfo  `json:"devices"`
	EnrolledAt *time.Time       `json:"enrolled_at"`
}

// MFADeviceInfo represents a single MFA device
type MFADeviceInfo struct {
	DeviceID   string     `json:"device_id"`
	DeviceName string     `json:"device_name"`
	CreatedAt  time.Time  `json:"created_at"`
	VerifiedAt *time.Time `json:"verified_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// Disable MFA DTOs

// DisableMFARequest requests MFA disablement (requires password)
type DisableMFARequest struct {
	Password string `json:"password" validate:"required"`
	DeviceID *string `json:"device_id"` // If specified, only disable that device; otherwise disable all
}

// DisableMFAResponse confirms MFA disablement
type DisableMFAResponse struct {
	Success    bool   `json:"success"`
	MFAEnabled bool   `json:"mfa_enabled"`
	Message    string `json:"message"`
}

// Login DTOs (updated)

// LoginResponse is now either standard auth or MFA required
type LoginResponse struct {
	// If MFA not enabled
	AccessToken  *string `json:"access_token,omitempty"`
	RefreshToken *string `json:"refresh_token,omitempty"`
	User         *UserResponseDTO `json:"user,omitempty"`

	// If MFA required
	MFARequired bool   `json:"mfa_required,omitempty"`
	MFAToken    string `json:"mfa_token,omitempty"` // 5-minute JWT for MFA challenge
}

// UserResponseDTO represents a user in the HTTP response (with MFA field)
type UserResponseDTO struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"email_verified"`
	MFAEnabled    bool   `json:"mfa_enabled"`
	Role          string `json:"role"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}
