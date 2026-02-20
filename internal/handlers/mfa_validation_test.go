package handlers

import (
	"testing"
)

func TestIsValidMFACodeFormat_TOTPCodes(t *testing.T) {
	tests := []struct {
		name  string
		code  string
		valid bool
	}{
		{"valid TOTP", "123456", true},
		{"valid TOTP all zeros", "000000", true},
		{"valid TOTP all nines", "999999", true},
		{"invalid - too short", "12345", false},
		{"invalid - too long", "1234567", false},
		{"invalid - contains letter", "12345a", false},
		{"invalid - contains special char", "12345!", false},
		{"invalid - space", "123 456", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidMFACodeFormat(tt.code)
			if result != tt.valid {
				t.Errorf("isValidMFACodeFormat(%q) = %v, want %v", tt.code, result, tt.valid)
			}
		})
	}
}

func TestIsValidMFACodeFormat_BackupCodes(t *testing.T) {
	tests := []struct {
		name  string
		code  string
		valid bool
	}{
		{"valid backup", "ABCD2345", true},
		{"valid backup all digits", "23456789", true},
		{"valid backup all letters", "ABCDEFGH", true},
		{"valid backup mixed", "A2B3C4D5", true},
		{"valid backup 2-9 range", "23456789", true},
		{"valid backup uppercase", "PQRSTUVW", true},
		{"invalid - too short", "ABCD234", false},
		{"invalid - too long", "ABCD23456", false},
		{"invalid - contains 0", "ABCD0234", false},
		{"invalid - contains 1", "ABCD1234", false},
		{"invalid - contains I", "ABCDI234", false},
		{"invalid - contains L", "ABCDL234", false},
		{"invalid - contains O", "ABCDO234", false},
		{"invalid - lowercase", "abcd2345", false},
		{"invalid - lowercase letter", "abcd5678", false},
		{"invalid - special char", "ABCD234!", false},
		{"invalid - space", "ABCD 234", false},
		{"invalid - hyphen", "ABCD-234", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidMFACodeFormat(tt.code)
			if result != tt.valid {
				t.Errorf("isValidMFACodeFormat(%q) = %v, want %v", tt.code, result, tt.valid)
			}
		})
	}
}

func TestIsValidMFACodeFormat_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		code  string
		valid bool
	}{
		{"empty", "", false},
		{"7 chars", "1234567", false},
		{"9 chars", "123456789", false},
		{"whitespace only", "        ", false},
		{"nil-like string", "\x00\x00\x00\x00\x00\x00", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidMFACodeFormat(tt.code)
			if result != tt.valid {
				t.Errorf("isValidMFACodeFormat(%q) = %v, want %v", tt.code, result, tt.valid)
			}
		})
	}
}

// TestIsValidMFACodeFormat_CharsetExclusions verifies that excluded characters
// (0, 1, I, L, O) are properly rejected for 8-character codes
func TestIsValidMFACodeFormat_CharsetExclusions(t *testing.T) {
	excluded := []struct {
		name string
		char rune
	}{
		{"digit 0", '0'},
		{"digit 1", '1'},
		{"letter I", 'I'},
		{"letter L", 'L'},
		{"letter O", 'O'},
	}

	for _, exc := range excluded {
		t.Run("backup code with "+string(exc.name), func(t *testing.T) {
			// Create 8-char code with the excluded character at each position
			for pos := 0; pos < 8; pos++ {
				code := make([]rune, 8)
				// Fill with valid characters
				for i := 0; i < 8; i++ {
					code[i] = '2' // valid digit
				}
				// Replace one position with excluded character
				code[pos] = exc.char

				result := isValidMFACodeFormat(string(code))
				if result {
					t.Errorf("isValidMFACodeFormat(%q) should reject %c at position %d, got true",
						string(code), exc.char, pos)
				}
			}
		})
	}
}
