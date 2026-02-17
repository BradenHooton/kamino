package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Database DatabaseConfig
	Server   ServerConfig
	Auth     AuthConfig
}

type DatabaseConfig struct {
	Host              string
	Port              int
	User              string
	Password          string
	Name              string
	SSLMode           string
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
}

type ServerConfig struct {
	Port            string
	Env             string
	LogLevel        string
	AllowedOrigins  []string
}

type AuthConfig struct {
	JWTSecret           string
	AccessTokenExpiry   time.Duration
	RefreshTokenExpiry  time.Duration
	CleanupInterval     time.Duration
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	jwtSecret := getEnv("JWT_SECRET", "")
	if jwtSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}

	env := getEnv("ENV", "development")

	cfg := &Config{
		Database: DatabaseConfig{
			Host:              getEnv("DB_HOST", "localhost"),
			Port:              getEnvAsInt("DB_PORT", 5432),
			User:              getEnv("DB_USER", "postgres"),
			Password:          getEnv("DB_PASSWORD", ""),
			Name:              getEnv("DB_NAME", "kamino"),
			SSLMode:           getEnv("DB_SSLMODE", "disable"),
			MaxConns:          int32(getEnvAsInt("DB_MAX_CONNS", 25)),
			MinConns:          int32(getEnvAsInt("DB_MIN_CONNS", 5)),
			MaxConnLifetime:   getEnvAsDuration("DB_MAX_CONN_LIFETIME", 5*time.Minute),
			MaxConnIdleTime:   getEnvAsDuration("DB_MAX_CONN_IDLE_TIME", 1*time.Minute),
			HealthCheckPeriod: getEnvAsDuration("DB_HEALTH_CHECK_PERIOD", 1*time.Minute),
		},
		Server: ServerConfig{
			Port:            getEnv("PORT", "8080"),
			Env:             env,
			LogLevel:        getEnv("LOG_LEVEL", "info"),
			AllowedOrigins:  parseAllowedOrigins(env),
		},
		Auth: AuthConfig{
			JWTSecret:          jwtSecret,
			AccessTokenExpiry:  getEnvAsDuration("ACCESS_TOKEN_EXPIRY", 15*time.Minute),
			RefreshTokenExpiry: getEnvAsDuration("REFRESH_TOKEN_EXPIRY", 7*24*time.Hour),
			CleanupInterval:    getEnvAsDuration("TOKEN_CLEANUP_INTERVAL", 1*time.Hour),
		},
	}

	if cfg.Database.Password == "" {
		return nil, fmt.Errorf("DB_PASSWORD is required")
	}

	// Validate JWT secret strength
	if err := validateJWTSecret(jwtSecret, env); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validateJWTSecret enforces minimum security standards for JWT secret
func validateJWTSecret(secret, env string) error {
	// Minimum length based on environment
	minLength := 16 // Development minimum
	if env == "production" {
		minLength = 32 // Production requires stronger secret (256 bits)
	}

	if len(secret) < minLength {
		return fmt.Errorf("JWT_SECRET must be at least %d characters in %s environment (got %d)",
			minLength, env, len(secret))
	}

	// Check against common weak secrets
	weakSecrets := []string{
		"secret", "test", "password", "12345", "changeme",
		"admin", "root", "default", "example",
	}

	secretLower := strings.ToLower(secret)
	for _, weak := range weakSecrets {
		if secretLower == weak {
			return fmt.Errorf("JWT_SECRET cannot be a common weak value")
		}
	}

	return nil
}

func (c *DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Name, c.SSLMode,
	)
}

func getEnv(key, defaultVal string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultVal
}

func getEnvAsInt(key string, defaultVal int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultVal
}

func getEnvAsDuration(key string, defaultVal time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultVal
}

func parseAllowedOrigins(env string) []string {
	if env == "production" {
		originsStr := getEnv("ALLOWED_ORIGINS", "")
		if originsStr == "" {
			return []string{} // Default to no origins in production
		}
		origins := strings.Split(originsStr, ",")
		for i, origin := range origins {
			origins[i] = strings.TrimSpace(origin)
		}
		return origins
	}

	// Development: allow localhost variants
	return []string{
		"http://localhost:3000",
		"http://localhost:8080",
		"http://localhost:5173", // Vite default
		"http://localhost:3001",
		"http://127.0.0.1:3000",
		"http://127.0.0.1:8080",
		"http://127.0.0.1:5173",
		"http://127.0.0.1:3001",
	}
}
