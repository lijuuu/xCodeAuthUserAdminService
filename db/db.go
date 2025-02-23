package db

import (
	"log"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// InitDB initializes a GORM PostgreSQL connection with connection pooling and auto-migration
func InitDB(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		// Configure connection pooling
		PrepareStmt:            true, // Cache prepared statements
		SkipDefaultTransaction: true, // Improve performance by skipping transactions for single queries
	})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(100) // Adjust based on load
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Auto-migrate the schema
	err = db.AutoMigrate(&User{}, &Following{}, &Follower{}, &Verification{}, &ForgotPassword{})
	if err != nil {
		return nil, err
	}

	log.Println("Connected to PostgreSQL database with GORM")
	return db, nil
}

func Close(db *gorm.DB) {
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("Failed to get SQL DB: %v", err)
	}
	sqlDB.Close()
}
