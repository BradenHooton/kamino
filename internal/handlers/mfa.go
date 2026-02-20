package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/internal/services"
	pkgauth "github.com/BradenHooton/kamino/pkg/auth"
	pkghttp "github.com/BradenHooton/kamino/pkg/http"
)

// MFAHandler handles MFA-related HTTP requests
type MFAHandler struct {
	mfaService *services.MFAService
	tm         *auth.TokenManager
	userRepo   services.UserRepository
	revokeRepo services.TokenRevocationRepository
	logger     *slog.Logger
}

// NewMFAHandler creates a new MFA handler
func NewMFAHandler(mfaService *services.MFAService, tm *auth.TokenManager, userRepo services.UserRepository, revokeRepo services.TokenRevocationRepository, logger *slog.Logger) *MFAHandler {
	return &MFAHandler{
		mfaService: mfaService,
		tm:         tm,
		userRepo:   userRepo,
		revokeRepo: revokeRepo,
		logger:     logger,
	}
}

// InitiateSetup handles POST /mfa/setup to begin MFA setup
func (h *MFAHandler) InitiateSetup(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r)
	if user == nil {
		pkghttp.WriteUnauthorized(w, "Unauthorized")
		return
	}

	var req InitiateMFASetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		pkghttp.WriteBadRequest(w, "Invalid request")
		return
	}

	if req.DeviceName == "" {
		pkghttp.WriteBadRequest(w, "device_name is required")
		return
	}

	device, backupCodes, qrCode, err := h.mfaService.InitiateSetup(r.Context(), user.UserID, req.DeviceName, user.Email)
	if err != nil {
		h.logger.Error("failed to initiate MFA setup", slog.Any("error", err))
		pkghttp.WriteInternalError(w, "Setup failed")
		return
	}

	response := InitiateMFASetupResponse{
		QRCode:      qrCode,
		BackupCodes: backupCodes,
		DeviceID:    device.ID,
		ExpiresAt:   device.CreatedAt.Add(15 * time.Minute),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// VerifySetup handles POST /mfa/setup/verify to confirm MFA setup
func (h *MFAHandler) VerifySetup(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r)
	if user == nil {
		pkghttp.WriteUnauthorized(w, "Unauthorized")
		return
	}

	var req VerifyMFASetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		pkghttp.WriteBadRequest(w, "Invalid request")
		return
	}

	if req.DeviceID == "" || req.Code == "" {
		pkghttp.WriteBadRequest(w, "device_id and code are required")
		return
	}

	if len(req.Code) != 6 || !isNumeric(req.Code) {
		pkghttp.WriteBadRequest(w, "code must be 6 digits")
		return
	}

	err := h.mfaService.VerifySetup(r.Context(), user.UserID, req.DeviceID, req.Code)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if err == models.ErrMFAInvalidCode {
			statusCode = http.StatusUnauthorized
		} else if err == models.ErrMFADeviceNotFound || err == models.ErrForbidden {
			statusCode = http.StatusNotFound
		} else if err == models.ErrConflict {
			statusCode = http.StatusConflict
		}

		h.logger.Warn("failed to verify MFA setup", slog.String("user_id", user.UserID), slog.Any("error", err))
		pkghttp.WriteError(w, statusCode, "mfa_verification_failed", "Verification failed")
		return
	}

	response := VerifyMFASetupResponse{
		Success:    true,
		MFAEnabled: true,
		EnrolledAt: time.Now(),
		Message:    "MFA has been successfully enabled",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// DisableMFA handles POST /mfa/disable to disable MFA
func (h *MFAHandler) DisableMFA(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r)
	if user == nil {
		pkghttp.WriteUnauthorized(w, "Unauthorized")
		return
	}

	var req DisableMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		pkghttp.WriteBadRequest(w, "Invalid request")
		return
	}

	if req.Password == "" {
		pkghttp.WriteBadRequest(w, "password is required to disable MFA")
		return
	}

	// Verify password
	userRecord, err := h.userRepo.GetByID(r.Context(), user.UserID)
	if err != nil {
		h.logger.Error("failed to fetch user", slog.Any("error", err))
		pkghttp.WriteUnauthorized(w, "Authentication failed")
		return
	}

	if err := pkgauth.ComparePassword(userRecord.PasswordHash, req.Password); err != nil {
		h.logger.Warn("invalid password for MFA disable", slog.String("user_id", user.UserID))
		pkghttp.WriteUnauthorized(w, "Invalid credentials")
		return
	}

	// Disable MFA
	err = h.mfaService.DisableMFA(r.Context(), user.UserID)
	if err != nil {
		h.logger.Error("failed to disable MFA", slog.Any("error", err))
		pkghttp.WriteInternalError(w, "Failed to disable MFA")
		return
	}

	response := DisableMFAResponse{
		Success:    true,
		MFAEnabled: false,
		Message:    "MFA has been disabled",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetStatus handles GET /mfa/status to check MFA configuration
func (h *MFAHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r)
	if user == nil {
		pkghttp.WriteUnauthorized(w, "Unauthorized")
		return
	}

	status, err := h.mfaService.GetStatus(r.Context(), user.UserID)
	if err != nil {
		h.logger.Error("failed to get MFA status", slog.Any("error", err))
		pkghttp.WriteInternalError(w, "Failed to retrieve MFA status")
		return
	}

	// Build response without exposing encrypted secrets
	response := MFAStatusResponse{
		MFAEnabled: status.MFAEnabled,
		EnrolledAt: status.EnrolledAt,
		Devices:    make([]MFADeviceInfo, len(status.Devices)),
	}

	for i, device := range status.Devices {
		response.Devices[i] = MFADeviceInfo{
			DeviceID:   device.ID,
			DeviceName: device.DeviceName,
			CreatedAt:  device.CreatedAt,
			VerifiedAt: device.VerifiedAt,
			LastUsedAt: device.LastUsedAt,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// VerifyMFACode handles POST /auth/mfa/verify to verify TOTP during login
func (h *MFAHandler) VerifyMFACode(w http.ResponseWriter, r *http.Request) {
	var req VerifyMFACodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		pkghttp.WriteBadRequest(w, "Invalid request")
		return
	}

	if req.MFAToken == "" || req.Code == "" {
		pkghttp.WriteBadRequest(w, "mfa_token and code are required")
		return
	}

	// Validate MFA code format (6 digits or 8-char backup code)
	if !isValidMFACodeFormat(req.Code) {
		pkghttp.WriteBadRequest(w, "Invalid code format")
		return
	}

	// Validate the MFA token
	claims, err := h.tm.ValidateToken(req.MFAToken)
	if err != nil || claims.Type != "mfa" {
		h.logger.Warn("invalid MFA token")
		pkghttp.WriteUnauthorized(w, "Invalid MFA token")
		return
	}

	// Get device fingerprint from user agent
	deviceFingerprint := hashUserAgent(r.Header.Get("User-Agent"))
	ipAddress := getClientIP(r)

	// Verify the MFA code
	success, err := h.mfaService.VerifyCode(r.Context(), claims.UserID, req.Code, deviceFingerprint, ipAddress)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if err == models.ErrMFAInvalidCode {
			statusCode = http.StatusUnauthorized
		} else if err == models.ErrMFARateLimited {
			statusCode = http.StatusTooManyRequests
		} else if err == models.ErrMFADeviceNotFound {
			statusCode = http.StatusNotFound
		}

		h.logger.Warn("MFA verification failed", slog.String("user_id", claims.UserID), slog.Any("error", err))
		pkghttp.WriteError(w, statusCode, "mfa_auth_failed", "Authentication failed")
		return
	}

	if !success {
		pkghttp.WriteUnauthorized(w, "Authentication failed")
		return
	}

	// Generate final access and refresh tokens
	accessToken, err := h.tm.GenerateAccessToken(claims.UserID, claims.Email)
	if err != nil {
		h.logger.Error("failed to generate access token", slog.Any("error", err))
		pkghttp.WriteInternalError(w, "Authentication failed")
		return
	}

	refreshToken, err := h.tm.GenerateRefreshToken(claims.UserID, claims.Email)
	if err != nil {
		h.logger.Error("failed to generate refresh token", slog.Any("error", err))
		pkghttp.WriteInternalError(w, "Authentication failed")
		return
	}

	// Revoke MFA token to prevent replay attacks
	if err := h.revokeRepo.RevokeToken(
		r.Context(),
		claims.ID,              // JTI from MFA token
		claims.UserID,
		"mfa",                  // token type
		claims.ExpiresAt.Time,  // expires_at from token
		"mfa_verified",         // reason
	); err != nil {
		// Log but don't fail - tokens are already generated
		// Failing here would be worse than allowing a small replay window
		h.logger.Error("failed to revoke MFA token",
			slog.String("user_id", claims.UserID),
			slog.String("jti", claims.ID),
			slog.Any("error", err))
	}

	// Fetch user for response
	userRecord, err := h.userRepo.GetByID(r.Context(), claims.UserID)
	if err != nil {
		h.logger.Error("failed to fetch user", slog.Any("error", err))
		pkghttp.WriteInternalError(w, "Authentication failed")
		return
	}

	response := VerifyMFACodeResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User: &UserResponseDTO{
			ID:            userRecord.ID,
			Email:         userRecord.Email,
			Name:          userRecord.Name,
			EmailVerified: userRecord.EmailVerified,
			MFAEnabled:    userRecord.MFAEnabled,
			Role:          userRecord.Role,
			CreatedAt:     userRecord.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:     userRecord.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		},
	}

	h.logger.Info("MFA verification successful", slog.String("user_id", claims.UserID))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Helper functions

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func hashUserAgent(userAgent string) string {
	hash := sha256.Sum256([]byte(userAgent))
	return hex.EncodeToString(hash[:])
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (for proxied requests)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to remote address
	return strings.Split(r.RemoteAddr, ":")[0]
}

// isValidMFACodeFormat validates MFA code format before service processing
// Returns true if code is either:
//   - 6 digits (TOTP code)
//   - 8 alphanumeric characters from backup code charset (excludes 0,1,I,L,O)
func isValidMFACodeFormat(code string) bool {
	// TOTP codes: exactly 6 digits
	if len(code) == 6 {
		for _, ch := range code {
			if ch < '0' || ch > '9' {
				return false
			}
		}
		return true
	}

	// Backup codes: exactly 8 characters from charset "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
	if len(code) == 8 {
		// Allowed: digits 2-9 and uppercase A-Z (excluding 0,1,I,L,O)
		for _, ch := range code {
			if !((ch >= '2' && ch <= '9') ||
				(ch >= 'A' && ch <= 'H') ||
				(ch >= 'J' && ch <= 'K') ||
				(ch >= 'M' && ch <= 'N') ||
				(ch >= 'P' && ch <= 'Z')) {
				return false
			}
		}
		return true
	}

	return false
}
