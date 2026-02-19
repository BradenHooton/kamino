package models

import (
	"time"
)

// MFADevice represents a registered MFA device for a user
type MFADevice struct {
	ID                     string
	UserID                 string
	DeviceName             string
	TOTPSecretEncrypted    []byte // AES-256-GCM encrypted TOTP secret
	TOTPSecretNonce        []byte // GCM nonce (12 bytes)
	BackupCodes            []BackupCodeEntry
	LastUsedAt             *time.Time // For replay prevention
	CreatedAt              time.Time
	VerifiedAt             *time.Time // When first TOTP code verified
}

// BackupCodeEntry represents a single backup code
type BackupCodeEntry struct {
	CodeHash  string     `json:"code_hash"`  // Bcrypt hash of backup code
	UsedAt    *time.Time `json:"used_at"`   // When used (nil = unused)
	CreatedAt time.Time  `json:"created_at"`
}

// IsVerified checks if the device has been verified
func (d *MFADevice) IsVerified() bool {
	return d.VerifiedAt != nil
}

// MFAVerificationAttempt tracks verification attempts for rate limiting
type MFAVerificationAttempt struct {
	ID               string
	UserID           string
	DeviceFingerprint string
	IPAddress        string
	Success          bool
	FailureReason    *string   // Reason for failure if Success=false
	AttemptedAt      time.Time
}

// MFAVerificationResponse is returned after successful TOTP verification
type MFAVerificationResponse struct {
	AccessToken  string
	RefreshToken string
	User         any // UserResponse
}

// MFARequiredResponse is returned when MFA is required for login
type MFARequiredResponse struct {
	MFARequired bool   `json:"mfa_required"`
	MFAToken    string `json:"mfa_token"` // 5-minute JWT token for MFA challenge
}

// MFAStatus represents the MFA status for a user
type MFAStatus struct {
	MFAEnabled  bool        `json:"mfa_enabled"`
	Devices     []MFADevice `json:"devices"`
	EnrolledAt  *time.Time  `json:"enrolled_at"`
}

// MFASetupResponse contains setup information for MFA enrollment
type MFASetupResponse struct {
	Secret      string   `json:"secret"`       // Encrypted TOTP secret (not exposed)
	QRCode      string   `json:"qr_code"`      // Data URL for QR code
	BackupCodes []string `json:"backup_codes"` // 8 backup codes for recovery
	DeviceID    string   `json:"device_id"`    // ID of the device being set up
}

