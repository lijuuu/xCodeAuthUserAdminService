package db

import (
	"gorm.io/gorm"
)

// User represents the users table
type User struct {
	ID                string `gorm:"primaryKey;type:uuid;not null" json:"id"`
	UserName          string `gorm:"type:varchar(255);not null;index" json:"user_name"`
	FirstName         string `gorm:"type:varchar(255);not null;index" json:"first_name"`
	LastName          string `gorm:"type:varchar(255);not null;index" json:"last_name"`
	Country           string `gorm:"type:varchar(100);not null" json:"country"`
	Role              string `gorm:"type:varchar(50);not null;index:idx_role_status" json:"role"`
	Bio               string `gorm:"type:varchar(200);" json:"bio"`
	PrimaryLanguageID string `gorm:"type:varchar(10);not null" json:"primary_language_id"`
	Email             string `gorm:"type:varchar(255);unique;not null;index" json:"email"`
	AuthType          string `gorm:"type:varchar(50);not null" json:"auth_type"` // email, google, github
	// AuthID            string         `gorm:"type:varchar(255)" json:"auth_id"` // google id, github id
	// AuthToken         string         `gorm:"type:varchar(255)" json:"auth_token"` // google token, github token
	Salt              string         `gorm:"type:varchar(255);not null" json:"salt"`
	HashedPassword    string         `gorm:"type:varchar(255);not null" json:"hashed_password"`
	MuteNotifications bool           `gorm:"default:false;not null" json:"mute_notifications"`
	IsBanned          bool           `gorm:"default:false;not null;index" json:"is_banned"`
	BanID             string         `gorm:"type:varchar(255)" json:"ban_id"`
	BanReason         string         `gorm:"type:varchar(255)" json:"ban_reason"`
	BanExpiration     int64          `json:"ban_expiration"`
	TwoFactorEnabled  bool           `gorm:"default:false;not null" json:"two_factor_enabled"`
	IsVerified        bool           `gorm:"default:false;not null" json:"is_verified"`
	TwoFactorSecret   string         `gorm:"type:varchar(255)" json:"two_factor_secret"`
	AvatarData        string         `gorm:"type:text" json:"avatar_data"`
	Github            string         `gorm:"type:varchar(255)" json:"github"`
	Twitter           string         `gorm:"type:varchar(255)" json:"twitter"`
	Linkedin          string         `gorm:"type:varchar(255)" json:"linkedin"`
	CreatedAt         int64          `gorm:"not null" json:"created_at"`
	UpdatedAt         int64          `gorm:"not null" json:"updated_at"`
	DeletedAt         gorm.DeletedAt `gorm:"index" json:"deleted_at"`
	Following         []Following    `gorm:"foreignKey:FollowerID" json:"following"`
	Followers         []Follower     `gorm:"foreignKey:FolloweeID" json:"followers"`
}

//

type Following struct {
	FollowerID string `gorm:"primaryKey;type:uuid;index" json:"follower_id"`
	FolloweeID string `gorm:"primaryKey;type:uuid;index" json:"followee_id"`
	CreatedAt  int64  `gorm:"autoCreateTime" json:"created_at"`
}

type Follower struct {
	FollowerID string `gorm:"primaryKey;type:uuid;index" json:"follower_id"`
	FolloweeID string `gorm:"primaryKey;type:uuid;index" json:"followee_id"`
	CreatedAt  int64  `gorm:"autoCreateTime" json:"created_at"`
}

// Verification represents the verification tokens (e.g., OTP) table
type Verification struct {
	ID        string `gorm:"primaryKey;type:uuid;not null" json:"id"`
	UserID    string `gorm:"type:uuid;not null;index" json:"user_id"`
	Email     string `gorm:"type:varchar(255);not null;index" json:"email"`
	Token     string `gorm:"type:varchar(255);not null" json:"token"`
	CreatedAt int64  `gorm:"autoCreateTime;not null" json:"created_at"`
	ExpiryAt  int64  `gorm:"not null" json:"expiry_at"`
	Used      bool   `gorm:"default:false;not null" json:"used"`
}

// ForgotPassword represents the password reset tokens table
type ForgotPassword struct {
	ID        string `gorm:"primaryKey;type:uuid;not null" json:"id"`
	UserID    string `gorm:"type:uuid;not null;index" json:"user_id"`
	Email     string `gorm:"type:varchar(255);not null;index" json:"email"`
	Token     string `gorm:"type:varchar(255);not null" json:"token"`
	CreatedAt int64  `gorm:"autoCreateTime;not null" json:"created_at"`
	ExpiryAt  int64  `gorm:"not null" json:"expiry_at"`
	Used      bool   `gorm:"default:false;not null" json:"used"`
}

type BanHistory struct {
	ID        string `gorm:"primaryKey;type:uuid;not null" json:"id"`
	UserID    string `gorm:"type:uuid;not null;index" json:"user_id"`
	BanType   string `gorm:"type:varchar(50);not null" json:"ban_type"`
	BannedAt  int64  `gorm:"type:bigint;not null" json:"banned_at"`
	BanReason string `gorm:"type:text;not null" json:"ban_reason"`
	BanExpiry int64  `gorm:"type:bigint;not null" json:"ban_expiry"`
}

type Admin struct {
	ID        string `gorm:"primaryKey;type:uuid;not null" json:"id"`
	Email     string `gorm:"type:varchar(255);not null;index" json:"email"`
	FirstName string `gorm:"type:varchar(255);not null" json:"first_name"`
	LastName  string `gorm:"type:varchar(255);not null" json:"last_name"`
	AvatarURL string `gorm:"type:varchar(255)" json:"avatar_url"`
	CreatedAt int64  `gorm:"autoCreateTime;not null" json:"created_at"`
	UpdatedAt int64  `gorm:"autoUpdateTime;not null" json:"updated_at"`
}
