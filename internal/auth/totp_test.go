package auth

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Constructor Tests (2 tests)
// ============================================================================

func TestTOTPManager_NewTOTPManager_ValidKey(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTOTPManager(key, "Kamino")
	assert.NoError(t, err)
	assert.NotNil(t, tm)
}

func TestTOTPManager_NewTOTPManager_InvalidKeyLength(t *testing.T) {
	// Test with various invalid key lengths
	tests := []int{0, 16, 24, 31, 33, 64}
	for _, length := range tests {
		key := make([]byte, length)
		tm, err := NewTOTPManager(key, "Kamino")
		assert.Error(t, err)
		assert.Nil(t, tm)
		assert.Contains(t, err.Error(), "must be exactly 32 bytes")
	}
}

// ============================================================================
// Secret Generation Tests (3 tests)
// ============================================================================

func TestTOTPManager_GenerateSecret_Success(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTOTPManager(key, "Kamino")
	require.NoError(t, err)

	secret, err := tm.GenerateSecret()
	assert.NoError(t, err)
	assert.NotNil(t, secret)
	assert.Greater(t, len(secret), 0) // Base32 encoded secret
}

func TestTOTPManager_GenerateSecretWithQR_Success(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTOTPManager(key, "Kamino")
	require.NoError(t, err)

	encrypted, nonce, plainSecret, qrCode, err := tm.GenerateSecretWithQR("test_device", "user@example.com")

	assert.NoError(t, err)
	assert.NotNil(t, encrypted)
	assert.NotNil(t, nonce)
	assert.NotEmpty(t, plainSecret)
	assert.NotEmpty(t, qrCode)
	assert.Equal(t, 12, len(nonce)) // GCM nonce is 12 bytes
}

func TestTOTPManager_GenerateSecretWithQR_QRCodeFormat(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTOTPManager(key, "Kamino")
	require.NoError(t, err)

	_, _, _, qrCode, err := tm.GenerateSecretWithQR("test_device", "user@example.com")
	require.NoError(t, err)

	// QR code should be a data URL
	assert.Contains(t, qrCode, "data:image/png;base64,")

	// Extract and decode base64 part
	dataURL := qrCode[len("data:image/png;base64,"):]
	pngData, err := base64.StdEncoding.DecodeString(dataURL)
	assert.NoError(t, err)
	assert.Greater(t, len(pngData), 0)

	// PNG signature: 137 80 78 71
	assert.Equal(t, byte(137), pngData[0])
	assert.Equal(t, byte(80), pngData[1])
	assert.Equal(t, byte(78), pngData[2])
	assert.Equal(t, byte(71), pngData[3])
}

// ============================================================================
// Encryption/Decryption Tests (4 tests) - SECURITY CRITICAL
// ============================================================================

func TestTOTPManager_EncryptDecrypt_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTOTPManager(key, "Kamino")
	require.NoError(t, err)

	originalSecret := []byte("test_secret_value_for_encryption")

	// Encrypt
	encrypted, nonce, err := tm.EncryptSecret(originalSecret)
	require.NoError(t, err)

	// Decrypt
	decrypted, err := tm.DecryptSecret(encrypted, nonce)
	require.NoError(t, err)

	assert.Equal(t, originalSecret, decrypted)
}

func TestTOTPManager_DecryptSecret_TamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTOTPManager(key, "Kamino")
	require.NoError(t, err)

	originalSecret := []byte("test_secret_value")

	// Encrypt
	encrypted, nonce, err := tm.EncryptSecret(originalSecret)
	require.NoError(t, err)

	// Tamper with ciphertext
	if len(encrypted) > 0 {
		encrypted[0] ^= 0xFF // Flip bits
	}

	// Decrypt should fail due to GCM authentication
	decrypted, err := tm.DecryptSecret(encrypted, nonce)
	assert.Error(t, err)
	assert.Nil(t, decrypted)
	assert.Contains(t, err.Error(), "failed to decrypt")
}

func TestTOTPManager_DecryptSecret_WrongNonce(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTOTPManager(key, "Kamino")
	require.NoError(t, err)

	originalSecret := []byte("test_secret_value")

	// Encrypt
	encrypted, _, err := tm.EncryptSecret(originalSecret)
	require.NoError(t, err)

	// Use wrong nonce
	wrongNonce := make([]byte, 12)
	_, err = rand.Read(wrongNonce)
	require.NoError(t, err)

	// Decrypt should fail
	decrypted, err := tm.DecryptSecret(encrypted, wrongNonce)
	assert.Error(t, err)
	assert.Nil(t, decrypted)
}

func TestTOTPManager_DecryptSecret_WrongNonceLength(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTOTPManager(key, "Kamino")
	require.NoError(t, err)

	originalSecret := []byte("test_secret_value")

	// Encrypt
	encrypted, _, err := tm.EncryptSecret(originalSecret)
	require.NoError(t, err)

	// Use wrong nonce length (11 bytes instead of 12)
	wrongNonce := make([]byte, 11)
	_, err = rand.Read(wrongNonce)
	require.NoError(t, err)

	// Should panic or fail due to incorrect nonce length
	// GCM requires exactly 12 bytes - this will cause a panic in crypto/cipher
	assert.Panics(t, func() {
		tm.DecryptSecret(encrypted, wrongNonce)
	})
}

// ============================================================================
// TOTP Validation Tests (6 tests) - SECURITY CRITICAL
// ============================================================================

func TestTOTPManager_ValidateTOTP_ValidCode(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTOTPManager(key, "Kamino")
	require.NoError(t, err)

	// GenerateSecretWithQR returns the plaintext secret in base32 format
	_, _, secretBase32, _, err := tm.GenerateSecretWithQR("test", "user@example.com")
	require.NoError(t, err)

	// Convert base32 back to bytes for storage/encryption
	secretBytes, err := base64.StdEncoding.DecodeString(secretBase32)
	require.NoError(t, err)

	// Generate valid code for current time
	validCode, err := totp.GenerateCode(secretBase32, time.Now())
	require.NoError(t, err)

	valid, err := tm.ValidateTOTP(secretBytes, validCode, nil)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestTOTPManager_ValidateTOTP_PlusOneTimeStep(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTOTPManager(key, "Kamino")
	require.NoError(t, err)

	_, _, secretBase32, _, err := tm.GenerateSecretWithQR("test", "user@example.com")
	require.NoError(t, err)

	secretBytes, err := base64.StdEncoding.DecodeString(secretBase32)
	require.NoError(t, err)

	// Generate code from +30 seconds (next time step)
	futureTime := time.Now().Add(30 * time.Second)
	futureCode, err := totp.GenerateCode(secretBase32, futureTime)
	require.NoError(t, err)

	// Should accept due to ±1 skew tolerance
	valid, err := tm.ValidateTOTP(secretBytes, futureCode, nil)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestTOTPManager_ValidateTOTP_MinusOneTimeStep(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTOTPManager(key, "Kamino")
	require.NoError(t, err)

	_, _, secretBase32, _, err := tm.GenerateSecretWithQR("test", "user@example.com")
	require.NoError(t, err)

	secretBytes, err := base64.StdEncoding.DecodeString(secretBase32)
	require.NoError(t, err)

	// Generate code from -30 seconds (previous time step)
	pastTime := time.Now().Add(-30 * time.Second)
	pastCode, err := totp.GenerateCode(secretBase32, pastTime)
	require.NoError(t, err)

	// Should accept due to ±1 skew tolerance
	valid, err := tm.ValidateTOTP(secretBytes, pastCode, nil)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestTOTPManager_ValidateTOTP_InvalidCode(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTOTPManager(key, "Kamino")
	require.NoError(t, err)

	_, _, secretBase32, _, err := tm.GenerateSecretWithQR("test", "user@example.com")
	require.NoError(t, err)

	secretBytes, err := base64.StdEncoding.DecodeString(secretBase32)
	require.NoError(t, err)

	valid, err := tm.ValidateTOTP(secretBytes, "000000", nil)
	assert.NoError(t, err)
	assert.False(t, valid)
}

func TestTOTPManager_ValidateTOTP_ReplayAttack(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTOTPManager(key, "Kamino")
	require.NoError(t, err)

	_, _, secretBase32, _, err := tm.GenerateSecretWithQR("test", "user@example.com")
	require.NoError(t, err)

	secretBytes, err := base64.StdEncoding.DecodeString(secretBase32)
	require.NoError(t, err)

	validCode, err := totp.GenerateCode(secretBase32, time.Now())
	require.NoError(t, err)

	// First use should succeed
	valid, err := tm.ValidateTOTP(secretBytes, validCode, nil)
	require.NoError(t, err)
	assert.True(t, valid)

	// Second use with same code within 90 seconds should fail (replay attack)
	lastUsedAt := time.Now().Add(-30 * time.Second) // 30 seconds ago
	valid, err = tm.ValidateTOTP(secretBytes, validCode, &lastUsedAt)
	assert.Error(t, err)
	assert.False(t, valid)
	assert.Contains(t, err.Error(), "replay")
}

func TestTOTPManager_ValidateTOTP_ExpiredCode(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTOTPManager(key, "Kamino")
	require.NoError(t, err)

	_, _, secretBase32, _, err := tm.GenerateSecretWithQR("test", "user@example.com")
	require.NoError(t, err)

	secretBytes, err := base64.StdEncoding.DecodeString(secretBase32)
	require.NoError(t, err)

	pastTime := time.Now().Add(-3 * time.Minute) // 3 minutes ago (outside 90s window)
	expiredCode, err := totp.GenerateCode(secretBase32, pastTime)
	require.NoError(t, err)

	// Should reject code from >90 seconds ago
	valid, err := tm.ValidateTOTP(secretBytes, expiredCode, nil)
	assert.NoError(t, err)
	assert.False(t, valid)
}

// ============================================================================
// Backup Code Generation Tests (3 tests)
// ============================================================================

func TestTOTPManager_GenerateBackupCodes_Count(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTOTPManager(key, "Kamino")
	require.NoError(t, err)

	codes, err := tm.GenerateBackupCodes(8)
	assert.NoError(t, err)
	assert.Len(t, codes, 8)
}

func TestTOTPManager_GenerateBackupCodes_Uniqueness(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTOTPManager(key, "Kamino")
	require.NoError(t, err)

	codes, err := tm.GenerateBackupCodes(8)
	require.NoError(t, err)

	// Check all codes are unique
	seen := make(map[string]bool)
	for _, code := range codes {
		assert.False(t, seen[code], "duplicate code found: %s", code)
		seen[code] = true
	}
}

func TestTOTPManager_GenerateBackupCodes_CharsetValidation(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	tm, err := NewTOTPManager(key, "Kamino")
	require.NoError(t, err)

	codes, err := tm.GenerateBackupCodes(8)
	require.NoError(t, err)

	// Charset should only contain: 2-9, A-Z (excluding 0/O/1/I/L)
	validCharset := "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
	for _, code := range codes {
		assert.Equal(t, 8, len(code))
		for _, ch := range code {
			assert.Contains(t, validCharset, string(ch), "invalid character in code: %c", ch)
		}
	}
}
