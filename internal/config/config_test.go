package config

import (
	"os"
	"testing"
	"time"
)

func TestServerConfig_Timeouts_Defaults(t *testing.T) {
	// Set required env vars
	os.Setenv("JWT_SECRET", "test-secret-32-characters-long!")
	os.Setenv("DB_PASSWORD", "test")
	defer os.Clearenv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}

	// Verify default timeout values match hardcoded values from main.go
	tests := []struct {
		name     string
		actual   time.Duration
		expected time.Duration
	}{
		{"ReadTimeout", cfg.Server.ReadTimeout, 15 * time.Second},
		{"WriteTimeout", cfg.Server.WriteTimeout, 15 * time.Second},
		{"IdleTimeout", cfg.Server.IdleTimeout, 60 * time.Second},
	}

	for _, tt := range tests {
		if tt.actual != tt.expected {
			t.Errorf("%s: got %v, want %v", tt.name, tt.actual, tt.expected)
		}
	}
}

func TestServerConfig_Timeouts_CustomValues(t *testing.T) {
	// Set required env vars
	os.Setenv("JWT_SECRET", "test-secret-32-characters-long!")
	os.Setenv("DB_PASSWORD", "test")
	os.Setenv("SERVER_READ_TIMEOUT", "30s")
	os.Setenv("SERVER_WRITE_TIMEOUT", "45s")
	os.Setenv("SERVER_IDLE_TIMEOUT", "120s")
	defer os.Clearenv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}

	// Verify custom timeout values
	tests := []struct {
		name     string
		actual   time.Duration
		expected time.Duration
	}{
		{"ReadTimeout", cfg.Server.ReadTimeout, 30 * time.Second},
		{"WriteTimeout", cfg.Server.WriteTimeout, 45 * time.Second},
		{"IdleTimeout", cfg.Server.IdleTimeout, 120 * time.Second},
	}

	for _, tt := range tests {
		if tt.actual != tt.expected {
			t.Errorf("%s: got %v, want %v", tt.name, tt.actual, tt.expected)
		}
	}
}

func TestServerConfig_Timeouts_InvalidDuration(t *testing.T) {
	// Set required env vars
	os.Setenv("JWT_SECRET", "test-secret-32-characters-long!")
	os.Setenv("DB_PASSWORD", "test")
	os.Setenv("SERVER_READ_TIMEOUT", "not-a-duration")
	defer os.Clearenv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}

	// Invalid duration should fall back to default
	if cfg.Server.ReadTimeout != 15*time.Second {
		t.Errorf("ReadTimeout with invalid value: got %v, want %v", cfg.Server.ReadTimeout, 15*time.Second)
	}
}

func TestServerConfig_Timeouts_PartialCustom(t *testing.T) {
	// Set required env vars and only some timeouts
	os.Setenv("JWT_SECRET", "test-secret-32-characters-long!")
	os.Setenv("DB_PASSWORD", "test")
	os.Setenv("SERVER_READ_TIMEOUT", "25s")
	// WriteTimeout and IdleTimeout not set, should use defaults
	defer os.Clearenv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}

	// Verify mixed custom and default values
	tests := []struct {
		name     string
		actual   time.Duration
		expected time.Duration
	}{
		{"ReadTimeout (custom)", cfg.Server.ReadTimeout, 25 * time.Second},
		{"WriteTimeout (default)", cfg.Server.WriteTimeout, 15 * time.Second},
		{"IdleTimeout (default)", cfg.Server.IdleTimeout, 60 * time.Second},
	}

	for _, tt := range tests {
		if tt.actual != tt.expected {
			t.Errorf("%s: got %v, want %v", tt.name, tt.actual, tt.expected)
		}
	}
}

func TestServerConfig_Timeouts_ZeroValues(t *testing.T) {
	// Set required env vars
	os.Setenv("JWT_SECRET", "test-secret-32-characters-long!")
	os.Setenv("DB_PASSWORD", "test")
	os.Setenv("SERVER_READ_TIMEOUT", "0s")
	defer os.Clearenv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}

	// Explicitly setting 0s should be honored (no timeout)
	if cfg.Server.ReadTimeout != 0 {
		t.Errorf("ReadTimeout with 0s: got %v, want 0", cfg.Server.ReadTimeout)
	}
}
