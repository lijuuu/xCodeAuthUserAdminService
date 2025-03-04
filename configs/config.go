package configs

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

// Config holds application configuration
type Config struct {
	UserGRPCPort string
	PostgresDSN  string
	JWTSecretKey string
	APPURL       string
	FRONTENDURL string
	SMTPAppKey   string // New field for SMTP app key
	SMTPHost     string // SMTP host (e.g., smtp.gmail.com)
	SMTPPort     string // SMTP port (e.g., "587" for TLS)
	SMTPUser     string // SMTP username (e.g., your email)
	AdminPassword string
	AdminUsername string
}

// LoadConfig loads configuration from environment variables
func LoadConfig() Config {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	config := Config{
		UserGRPCPort: getEnv("USERGRPCPORT", "50051"),
		PostgresDSN:  getEnv("POSTGRESDSN", "host=localhost port=5432 user=admin password=password dbname=xcodedev sslmode=disable"),
		JWTSecretKey: getEnv("JWTSECRETKEY", "secretLeetcode"),
		APPURL:        getEnv("APPURL", "http://localhost:7000"),
		FRONTENDURL:   getEnv("FRONTENDURL", "http://localhost:5173"),
		SMTPAppKey:    getEnv("SMTPAPPKEY", ""),
		SMTPHost:      getEnv("SMTPHOST", "smtp.gmail.com"),
		SMTPPort:      getEnv("SMTPPORT", "587"),
		SMTPUser:      getEnv("SMTPUSER", "xcodedev@gmail.com"),
		AdminPassword: getEnv("ADMINPASSWORD", "admin"),
		AdminUsername: getEnv("ADMINUSERNAME", "admin"),
	}

	fmt.Println(config)
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
