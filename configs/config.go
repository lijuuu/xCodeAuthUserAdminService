package configs

import (
	"log"
	"os"
)

// Config holds application configuration
type Config struct {
	UserGRPCPort string
	PostgresDSN  string
	JWTSecretKey string
	APPURL      string
	SMTPAppKey     string // New field for SMTP app key
	SMTPHost       string // SMTP host (e.g., smtp.gmail.com)
	SMTPPort       string // SMTP port (e.g., "587" for TLS)
	SMTPUser       string // SMTP username (e.g., your email)
}

// LoadConfig loads configuration from environment variables
func LoadConfig() Config {
	config := Config{
		UserGRPCPort: getEnv("USERGRPCPORT", "50051"),
		PostgresDSN:  getEnv("POSTGRESDSN", "host=localhost port=5432 user=admin password=password dbname=xcodedev sslmode=disable"),
		JWTSecretKey: getEnv("JWTSECRETKEY", "secretLeetcode"),
		APPURL:       getEnv("APP_URL", "http://localhost:7000"),
		SMTPAppKey:   getEnv("SMTP_APP_KEY", ""),
		SMTPHost:     getEnv("SMTP_HOST", "smtp.gmail.com"),
		SMTPPort:     getEnv("SMTP_PORT", "587"),
		SMTPUser:     getEnv("SMTP_USER", "xcodedev@gmail.com"),
	}

	return config
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	log.Printf("Environment variable %s not set, using default: %s", key, defaultValue)
	return defaultValue
}
