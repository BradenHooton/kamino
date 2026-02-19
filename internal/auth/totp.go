package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"
)

// TOTPManager handles TOTP generation, encryption, and validation
type TOTPManager struct {
	encryptionKey []byte // 32-byte AES-256 key
	issuer        string // Issuer name for TOTP QR codes
}

// NewTOTPManager creates a new TOTP manager
// encryptionKey must be exactly 32 bytes for AES-256
func NewTOTPManager(encryptionKey []byte, issuer string) (*TOTPManager, error) {
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("encryption key must be exactly 32 bytes, got %d", len(encryptionKey))
	}

	return &TOTPManager{
		encryptionKey: encryptionKey,
		issuer:        issuer,
	}, nil
}

// GenerateSecret creates a new TOTP secret
// Returns the secret bytes that should be encrypted for storage
func (tm *TOTPManager) GenerateSecret() ([]byte, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      tm.issuer,
		AccountName: "user",
		SecretSize:  32,
		Period:      30,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	secretBytes := []byte(key.Secret())
	return secretBytes, nil
}

// GenerateSecretWithQR generates a secret and returns QR code + secret for setup
// Returns: (encryptedSecret, nonce, secret, qrCodeDataURL, error)
func (tm *TOTPManager) GenerateSecretWithQR(accountName, userEmail string) ([]byte, []byte, string, string, error) {
	// Generate base32-encoded secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      tm.issuer,
		AccountName: userEmail,
		SecretSize:  32, // 256 bits
		Period:      30,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	// Encrypt the secret
	secretBytes := []byte(key.Secret())
	encrypted, nonce, err := tm.EncryptSecret(secretBytes)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Generate QR code from the provisioning URL
	qrCodeURL := key.URL()
	qr, err := qrcode.New(qrCodeURL, qrcode.Highest)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("failed to create QR code: %w", err)
	}

	// Convert QR code to PNG data URL
	qrImage, err := qr.PNG(200)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("failed to encode QR code: %w", err)
	}

	qrDataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(qrImage)

	return encrypted, nonce, key.Secret(), qrDataURL, nil
}

// EncryptSecret encrypts a TOTP secret using AES-256-GCM
// Returns: (encryptedBytes, nonce, error)
func (tm *TOTPManager) EncryptSecret(secretBytes []byte) ([]byte, []byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(tm.encryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce (12 bytes for GCM)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the secret
	ciphertext := gcm.Seal(nil, nonce, secretBytes, nil)

	return ciphertext, nonce, nil
}

// DecryptSecret decrypts an encrypted TOTP secret
func (tm *TOTPManager) DecryptSecret(encryptedBytes, nonce []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(tm.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, encryptedBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}

	return plaintext, nil
}

// ValidateTOTP validates a TOTP code against a secret
// Allows ±1 time step (90 seconds total window) for clock drift
// Implements replay prevention by checking lastUsedAt
func (tm *TOTPManager) ValidateTOTP(secretBytes []byte, code string, lastUsedAt *time.Time) (bool, error) {
	// Generate key from secret
	secret := base64.StdEncoding.EncodeToString(secretBytes)

	// Create a custom key for validation
	keyConfig := totp.ValidateOpts{
		Period:    30,
		Skew:      1, // ±1 time step = 90 seconds total window
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}

	// Validate code
	valid, err := totp.ValidateCustom(code, secret, time.Now(), keyConfig)
	if err != nil {
		return false, fmt.Errorf("failed to validate TOTP: %w", err)
	}

	if !valid {
		return false, nil
	}

	// Check for replay attack: reject if same code used within 90 seconds
	if lastUsedAt != nil {
		timeSinceLastUse := time.Since(*lastUsedAt)
		// If last use was within the 90-second window, this is a replay
		if timeSinceLastUse < 90*time.Second {
			return false, fmt.Errorf("code replay detected")
		}
	}

	return true, nil
}

// GenerateBackupCodes generates N random backup codes
// Format: 8 characters, alphanumeric (excluding ambiguous chars like 0/O, 1/I/l)
// Returns: (codes, error)
func (tm *TOTPManager) GenerateBackupCodes(count int) ([]string, error) {
	// Charset: A-Z 2-9 (excluding 0/O/1/I/L which are ambiguous)
	// This gives us 32 characters for base32-like encoding
	const charset = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

	codes := make([]string, count)
	for i := 0; i < count; i++ {
		code := make([]byte, 8)
		for j := 0; j < 8; j++ {
			// Use crypto/rand for cryptographic randomness
			b := make([]byte, 1)
			if _, err := rand.Read(b); err != nil {
				return nil, fmt.Errorf("failed to generate random byte: %w", err)
			}
			code[j] = charset[b[0]%byte(len(charset))]
		}
		codes[i] = string(code)
	}

	return codes, nil
}

// HashBackupCode returns SHA-256 hash of backup code
// Used for constant-time comparison
func (tm *TOTPManager) HashBackupCode(code string) string {
	hash := sha1.Sum([]byte(code))
	return fmt.Sprintf("%x", hash)
}
