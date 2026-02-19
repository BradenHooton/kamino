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
)

// MFAHandler handles MFA-related HTTP requests
type MFAHandler struct {
	mfaService *services.MFAService
	tm         *auth.TokenManager
	userRepo   services.UserRepository
	logger     *slog.Logger
}

// NewMFAHandler creates a new MFA handler
func NewMFAHandler(mfaService *services.MFAService, tm *auth.TokenManager, userRepo services.UserRepository, logger *slog.Logger) *MFAHandler {
	return &MFAHandler{
		mfaService: mfaService,
		tm:         tm,
		userRepo:   userRepo,
		logger:     logger,
	}
}

// InitiateSetup handles POST /mfa/setup to begin MFA setup
func (h *MFAHandler) InitiateSetup(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req InitiateMFASetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.DeviceName == "" {
		http.Error(w, "device_name is required", http.StatusBadRequest)
		return
	}

	device, backupCodes, qrCode, err := h.mfaService.InitiateSetup(r.Context(), user.UserID, req.DeviceName, user.Email)
	if err != nil {
		h.logger.Error("failed to initiate MFA setup", slog.Any("error", err))
		http.Error(w, "Setup failed", http.StatusInternalServerError)
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
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req VerifyMFASetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.DeviceID == "" || req.Code == "" {
		http.Error(w, "device_id and code are required", http.StatusBadRequest)
		return
	}

	if len(req.Code) != 6 || !isNumeric(req.Code) {
		http.Error(w, "code must be 6 digits", http.StatusBadRequest)
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
		http.Error(w, "Verification failed", statusCode)
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
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req DisableMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Password == "" {
		http.Error(w, "password is required to disable MFA", http.StatusBadRequest)
		return
	}

	// Verify password
	userRecord, err := h.userRepo.GetByID(r.Context(), user.UserID)
	if err != nil {
		h.logger.Error("failed to fetch user", slog.Any("error", err))
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	if err := pkgauth.ComparePassword(userRecord.PasswordHash, req.Password); err != nil {
		h.logger.Warn("invalid password for MFA disable", slog.String("user_id", user.UserID))
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Disable MFA
	err = h.mfaService.DisableMFA(r.Context(), user.UserID)
	if err != nil {
		h.logger.Error("failed to disable MFA", slog.Any("error", err))
		http.Error(w, "Failed to disable MFA", http.StatusInternalServerError)
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
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	status, err := h.mfaService.GetStatus(r.Context(), user.UserID)
	if err != nil {
		h.logger.Error("failed to get MFA status", slog.Any("error", err))
		http.Error(w, "Failed to retrieve MFA status", http.StatusInternalServerError)
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
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.MFAToken == "" || req.Code == "" {
		http.Error(w, "mfa_token and code are required", http.StatusBadRequest)
		return
	}

	// Validate the MFA token
	claims, err := h.tm.ValidateToken(req.MFAToken)
	if err != nil || claims.Type != "mfa" {
		h.logger.Warn("invalid MFA token")
		http.Error(w, "Invalid MFA token", http.StatusUnauthorized)
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
		http.Error(w, "Authentication failed", statusCode)
		return
	}

	if !success {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Generate final access and refresh tokens
	accessToken, err := h.tm.GenerateAccessToken(claims.UserID, claims.Email)
	if err != nil {
		h.logger.Error("failed to generate access token", slog.Any("error", err))
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	refreshToken, err := h.tm.GenerateRefreshToken(claims.UserID, claims.Email)
	if err != nil {
		h.logger.Error("failed to generate refresh token", slog.Any("error", err))
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Fetch user for response
	userRecord, err := h.userRepo.GetByID(r.Context(), claims.UserID)
	if err != nil {
		h.logger.Error("failed to fetch user", slog.Any("error", err))
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
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
