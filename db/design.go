package db

import (
	"time"

	"gorm.io/gorm"
)

// User represents the users table
type User struct {
	ID                string         `gorm:"primaryKey;type:uuid;not null" json:"id"`
	FirstName         string         `gorm:"type:varchar(255);not null;index" json:"first_name"`
	LastName          string         `gorm:"type:varchar(255);not null;index" json:"last_name"`
	Country           string         `gorm:"type:varchar(100);not null" json:"country"`
	Role              string         `gorm:"type:varchar(50);not null;index:idx_role_status" json:"role"`
	PrimaryLanguageID string         `gorm:"type:varchar(10);not null" json:"primary_language_id"`
	Email             string         `gorm:"type:varchar(255);unique;not null;index" json:"email"`
	AuthType          string         `gorm:"type:varchar(50);not null" json:"auth_type"`
	Password          string         `gorm:"type:varchar(255);not null" json:"password"`
	MuteNotifications bool           `gorm:"default:false;not null" json:"mute_notifications"`
	IsBanned          bool           `gorm:"default:false;not null;index" json:"is_banned"`
	BanReason         string         `gorm:"type:text" json:"ban_reason"`
	BanExpiration     *time.Time     `gorm:"type:timestamp" json:"ban_expiration"`
	IsVerified        bool           `gorm:"default:false;not null" json:"is_verified"`
	Status            string         `gorm:"type:varchar(50);default:'active';not null;index:idx_role_status" json:"status"`
	AvatarData        string         `gorm:"type:text" json:"avatar_data"`
	Github            string         `gorm:"type:varchar(255)" json:"github"`
	Twitter           string         `gorm:"type:varchar(255)" json:"twitter"`
	Linkedin          string         `gorm:"type:varchar(255)" json:"linkedin"`
	CreatedAt         time.Time      `gorm:"autoCreateTime;not null" json:"created_at"`
	UpdatedAt         time.Time      `gorm:"autoUpdateTime;not null" json:"updated_at"`
	DeletedAt         gorm.DeletedAt `gorm:"index" json:"deleted_at"`
	Following         []Following    `gorm:"foreignKey:FollowerID" json:"following"`
	Followers         []Follower     `gorm:"foreignKey:FolloweeID" json:"followers"`
}

type Following struct {
	FollowerID string    `gorm:"primaryKey;type:uuid;index" json:"follower_id"`
	FolloweeID string    `gorm:"primaryKey;type:uuid;index" json:"followee_id"`
	CreatedAt  time.Time `gorm:"autoCreateTime" json:"created_at"`
}

type Follower struct {
	FollowerID string    `gorm:"primaryKey;type:uuid;index" json:"follower_id"`
	FolloweeID string    `gorm:"primaryKey;type:uuid;index" json:"followee_id"`
	CreatedAt  time.Time `gorm:"autoCreateTime" json:"created_at"`
}

// Verification represents the verification tokens (e.g., OTP) table
type Verification struct {
	ID        string    `gorm:"primaryKey;type:uuid;not null" json:"id"`
	UserID    string    `gorm:"type:uuid;not null;index" json:"user_id"`
	Email     string    `gorm:"type:varchar(255);not null;index" json:"email"`
	Token     string    `gorm:"type:varchar(255);not null" json:"token"`
	CreatedAt time.Time `gorm:"autoCreateTime;not null" json:"created_at"`
	ExpiryAt  time.Time `gorm:"not null" json:"expiry_at"`
	Used      bool      `gorm:"default:false;not null" json:"used"`
}

// ForgotPassword represents the password reset tokens table
type ForgotPassword struct {
	ID        string    `gorm:"primaryKey;type:uuid;not null" json:"id"`
	UserID    string    `gorm:"type:uuid;not null;index" json:"user_id"`
	Email     string    `gorm:"type:varchar(255);not null;index" json:"email"`
	Token     string    `gorm:"type:varchar(255);not null" json:"token"`
	CreatedAt time.Time `gorm:"autoCreateTime;not null" json:"created_at"`
	ExpiryAt  time.Time `gorm:"not null" json:"expiry_at"`
	Used      bool      `gorm:"default:false;not null" json:"used"`
}
