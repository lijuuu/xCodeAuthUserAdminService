package configs

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

// Config holds application configuration
type Config struct {
	Environment            string
	UserGRPCPort           string
	PostgresDSN            string
	JWTSecretKey           string
	APPURL                 string
	FRONTENDURL            string
	SMTPAppKey             string // New field for SMTP app key
	SMTPHost               string // SMTP host (e.g., smtp.gmail.com)
	SMTPPort               string // SMTP port (e.g., "587" for TLS)
	SMTPUser               string // SMTP username (e.g., your email)
	AdminPassword          string
	AdminUsername          string
	GoogleClientID         string
	GoogleClientSecret     string
	GoogleRedirectURL      string
	RedisURL               string
	ResendAPIKey           string
	BetterStackSourceToken string
	BetterStackUploadURL   string
}

// LoadConfig loads configuration from environment variables
func LoadConfig() Config {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file", err)
	}
	config := Config{
		Environment:        getEnv("ENVIRONMENT", "development"),
		UserGRPCPort:       getEnv("USERGRPCPORT", "50051"),
		PostgresDSN:        getEnv("POSTGRESDSN", "host=localhost port=5432 user=admin password=password dbname=xcodedev sslmode=disable"),
		JWTSecretKey:       getEnv("JWTSECRETKEY", "secretLeetcode"),
		APPURL:             getEnv("APPURL", "http://localhost:7000"),
		FRONTENDURL:        getEnv("FRONTENDURL", "http://localhost:8080"),
		SMTPAppKey:         getEnv("SMTPAPPKEY", ""),
		SMTPHost:           getEnv("SMTPHOST", "smtp.gmail.com"),
		SMTPPort:           getEnv("SMTPPORT", "587"),
		SMTPUser:           getEnv("SMTPUSER", "zenxbattle.space"),
		AdminPassword:      getEnv("ADMINPASSWORD", "admin"),
		AdminUsername:      getEnv("ADMINUSERNAME", "admin"),
		GoogleClientID:     getEnv("GOOGLECLIENTID", ""),
		GoogleClientSecret: getEnv("GOOGLECLIENTSECRET", ""),
		GoogleRedirectURL:  getEnv("GOOGLEREDIRECTURL", ""),
		RedisURL:           getEnv("REDISURL", "localhost:6379"),
		ResendAPIKey:       getEnv("RESENDAPIKEY", ""),

		BetterStackSourceToken: getEnv("BETTERSTACKSOURCETOKEN", ""),
		BetterStackUploadURL:   getEnv("BETTERSTACKUPLOADURL", ""),
	}

	// fmt.Println(config)
	return config
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	// log.Printf("Environment variable %s not set, using default: %s", key, defaultValue)
	return defaultValue
}
