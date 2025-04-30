package repository

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"log"
	"math/rand"
	"strings"
	"time"

	"xcode/customerrors"
	"xcode/db"
	"xcode/utils"

	configs "xcode/configs"

	zap_betterstack "xcode/logger"

	"github.com/google/uuid"
	AuthUserAdminService "github.com/lijuuu/GlobalProtoXcode/AuthUserAdminService"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserRepository struct {
	db     *gorm.DB
	config *configs.Config
	logger *zap_betterstack.BetterStackLogStreamer
}

func NewUserRepository(db *gorm.DB, config *configs.Config, logger *zap_betterstack.BetterStackLogStreamer) *UserRepository {
	if db == nil || config == nil {
		logger.Log(zapcore.FatalLevel, "", "Database or config nil in NewUserRepository", map[string]any{
			"method": "NewUserRepository",
		}, "REPOSITORY", nil)
		log.Fatal("database or config cannot be nil")
	}
	return &UserRepository{db: db, config: config, logger: logger}
}

func (r *UserRepository) CreateUser(req *AuthUserAdminService.RegisterUserRequest) (string, string, error) {
	traceID := req.TraceID
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting CreateUser", map[string]any{
		"method": "CreateUser",
		"email":  req.Email,
	}, "REPOSITORY", nil)

	if req == nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Nil registration request", map[string]any{
			"method":     "CreateUser",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return "", customerrors.ERR_PARAM_EMPTY, fmt.Errorf("registration request cannot be nil")
	}
	if req.Password != req.ConfirmPassword {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Password mismatch", map[string]any{
			"method":     "CreateUser",
			"email":      req.Email,
			"errorType": customerrors.ERR_REG_PASSWORD_MISMATCH,
		}, "REPOSITORY", nil)
		return "", customerrors.ERR_REG_PASSWORD_MISMATCH, fmt.Errorf("the passwords you entered do not match")
	}
	if !IsValidEmail(req.Email) {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Invalid email", map[string]any{
			"method":     "CreateUser",
			"email":      req.Email,
			"errorType": customerrors.ERR_REG_INVALID_EMAIL,
		}, "REPOSITORY", nil)
		return "", customerrors.ERR_REG_INVALID_EMAIL, fmt.Errorf("please enter a valid email address")
	}
	if !IsValidPassword(req.Password) {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Invalid password", map[string]any{
			"method":     "CreateUser",
			"email":      req.Email,
			"errorType": customerrors.ERR_REG_INVALID_PASSWORD,
		}, "REPOSITORY", nil)
		return "", customerrors.ERR_REG_INVALID_PASSWORD, fmt.Errorf("password must be at least 8 characters long and include at least one uppercase letter and one number")
	}

	salt := uuid.New().String()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password+salt), bcrypt.DefaultCost)
	if err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to hash password", map[string]any{
			"method":     "CreateUser",
			"email":      req.Email,
			"errorType": customerrors.ERR_PASSWORD_HASH_FAILED,
		}, "REPOSITORY", err)
		return "", customerrors.ERR_PASSWORD_HASH_FAILED, fmt.Errorf("failed to hash password")
	}

	user := db.User{
		ID:             uuid.New().String(),
		UserName:       strings.Split(req.Email, "@")[0][:4] + uuid.New().String()[:4],
		CreatedAt:      time.Now().Unix(),
		FirstName:      req.FirstName,
		LastName:       req.LastName,
		Email:          req.Email,
		Salt:           salt,
		Role:           "USER",
		AuthType:       "email",
		IsBanned:       false,
		HashedPassword: string(hashedPassword),
	}

	if err := r.db.Create(&user).Error; err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to create user", map[string]any{
			"method":     "CreateUser",
			"email":      req.Email,
			"errorType": customerrors.ERR_REG_CREATION_FAILED,
		}, "REPOSITORY", err)
		return "", customerrors.ERR_REG_CREATION_FAILED, fmt.Errorf("failed to create user")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "User created successfully", map[string]any{
		"method": "CreateUser",
		"userID": user.ID,
	}, "REPOSITORY", nil)
	return user.ID, "", nil
}

func (r *UserRepository) CreateGoogleUser(req *db.User) (string, string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting CreateGoogleUser", map[string]any{
		"method": "CreateGoogleUser",
		"email":  req.Email,
	}, "REPOSITORY", nil)

	if err := r.db.Create(&req).Error; err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to create Google user", map[string]any{
			"method":     "CreateGoogleUser",
			"email":      req.Email,
			"errorType": customerrors.ERR_REG_CREATION_FAILED,
		}, "REPOSITORY", err)
		return "", customerrors.ERR_REG_CREATION_FAILED, fmt.Errorf("failed to create user")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "Google user created successfully", map[string]any{
		"method": "CreateGoogleUser",
		"email":  req.Email,
	}, "REPOSITORY", nil)
	return "", "", nil
}

func (r *UserRepository) CheckUserPassword(userID, password string) (bool, string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting CheckUserPassword", map[string]any{
		"method": "CheckUserPassword",
		"userID": userID,
	}, "REPOSITORY", nil)

	if userID == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
			"method":     "CheckUserPassword",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return false, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	var user db.User
	if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			r.logger.Log(zapcore.ErrorLevel, traceID, "User not found", map[string]any{
				"method":     "CheckUserPassword",
				"userID":     userID,
				"errorType": customerrors.ERR_USER_NOT_FOUND,
			}, "REPOSITORY", err)
			return false, customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("user not found")
		}
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to verify credentials", map[string]any{
			"method":     "CheckUserPassword",
			"userID":     userID,
			"errorType": customerrors.ERR_CRED_CHECK_FAILED,
		}, "REPOSITORY", err)
		return false, customerrors.ERR_CRED_CHECK_FAILED, fmt.Errorf("unable to verify credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(password+user.Salt)); err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Incorrect password", map[string]any{
			"method":     "CheckUserPassword",
			"userID":     userID,
			"errorType": customerrors.ERR_CRED_WRONG,
		}, "REPOSITORY", err)
		return false, customerrors.ERR_CRED_WRONG, fmt.Errorf("incorrect password")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "Password verified successfully", map[string]any{
		"method": "CheckUserPassword",
		"userID": userID,
	}, "REPOSITORY", nil)
	return true, "", nil
}

func (r *UserRepository) CheckAdminPassword(password string) (bool, string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting CheckAdminPassword", map[string]any{
		"method": "CheckAdminPassword",
	}, "REPOSITORY", nil)

	if password == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty password", map[string]any{
			"method":     "CheckAdminPassword",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return false, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("password cannot be empty")
	}
	if r.config.AdminPassword == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Admin password not configured", map[string]any{
			"method":     "CheckAdminPassword",
			"errorType": customerrors.ERR_ADMIN_NOT_CONFIGURED,
		}, "REPOSITORY", nil)
		return false, customerrors.ERR_ADMIN_NOT_CONFIGURED, fmt.Errorf("admin password not configured")
	}
	if password != r.config.AdminPassword {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Invalid admin credentials", map[string]any{
			"method":     "CheckAdminPassword",
			"errorType": customerrors.ERR_CRED_WRONG,
		}, "REPOSITORY", nil)
		return false, customerrors.ERR_CRED_WRONG, fmt.Errorf("invalid admin credentials")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "Admin password verified successfully", map[string]any{
		"method": "CheckAdminPassword",
	}, "REPOSITORY", nil)
	return true, "", nil
}

func (r *UserRepository) GetUserByEmail(email string) (db.User, string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting GetUserByEmail", map[string]any{
		"method": "GetUserByEmail",
		"email":  email,
	}, "REPOSITORY", nil)

	if email == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty email", map[string]any{
			"method":     "GetUserByEmail",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return db.User{}, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("email cannot be empty")
	}
	var user db.User
	if err := r.db.Where("email = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			r.logger.Log(zapcore.InfoLevel, traceID, "User not found", map[string]any{
				"method": "GetUserByEmail",
				"email":  email,
			}, "REPOSITORY", nil)
			return db.User{}, "", nil
		}
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve user", map[string]any{
			"method":     "GetUserByEmail",
			"email":      email,
			"errorType": customerrors.ERR_CRED_CHECK_FAILED,
		}, "REPOSITORY", err)
		return db.User{}, customerrors.ERR_CRED_CHECK_FAILED, fmt.Errorf("unable to retrieve user")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "User retrieved successfully", map[string]any{
		"method": "GetUserByEmail",
		"userID": user.ID,
	}, "REPOSITORY", nil)
	return user, "", nil
}

func (r *UserRepository) GetUserByUserID(userID string) (db.User, string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting GetUserByUserID", map[string]any{
		"method": "GetUserByUserID",
		"userID": userID,
	}, "REPOSITORY", nil)

	if userID == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
			"method":     "GetUserByUserID",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return db.User{}, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	var user db.User
	if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			r.logger.Log(zapcore.InfoLevel, traceID, "User not found", map[string]any{
				"method": "GetUserByUserID",
				"userID": userID,
			}, "REPOSITORY", nil)
			return db.User{}, "", nil
		}
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve user", map[string]any{
			"method":     "GetUserByUserID",
			"userID":     userID,
			"errorType": customerrors.ERR_CRED_CHECK_FAILED,
		}, "REPOSITORY", err)
		return db.User{}, customerrors.ERR_CRED_CHECK_FAILED, fmt.Errorf("unable to retrieve user")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "User retrieved successfully", map[string]any{
		"method": "GetUserByUserID",
		"userID": userID,
	}, "REPOSITORY", nil)
	return user, "", nil
}

func (r *UserRepository) UpdateUserOnTwoFactorAuth(user db.User) (string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting UpdateUserOnTwoFactorAuth", map[string]any{
		"method": "UpdateUserOnTwoFactorAuth",
		"userID": user.ID,
	}, "REPOSITORY", nil)

	if err := r.db.Model(&user).Where("id = ? AND deleted_at IS NULL", user.ID).Updates(map[string]interface{}{
		"is_verified": false,
	}).Error; err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to update user for 2FA", map[string]any{
			"method":     "UpdateUserOnTwoFactorAuth",
			"userID":     user.ID,
			"errorType": customerrors.ERR_PROFILE_UPDATE_FAILED,
		}, "REPOSITORY", err)
		return customerrors.ERR_PROFILE_UPDATE_FAILED, fmt.Errorf("unable to update profile")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "User updated for 2FA successfully", map[string]any{
		"method": "UpdateUserOnTwoFactorAuth",
		"userID": user.ID,
	}, "REPOSITORY", nil)
	return "", nil
}

func (r *UserRepository) UpdateProfile(req *AuthUserAdminService.UpdateProfileRequest) (string, error) {
	traceID := req.TraceID
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting UpdateProfile", map[string]any{
		"method": "UpdateProfile",
		"userID": req.UserID,
	}, "REPOSITORY", nil)

	if req == nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Nil update profile request", map[string]any{
			"method":     "UpdateProfile",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("update profile request cannot be nil")
	}
	if req.UserID == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
			"method":     "UpdateProfile",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	socials := &AuthUserAdminService.Socials{}
	if req.Socials != nil {
		socials = req.Socials
	}
	user := db.User{
		ID:                req.UserID,
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		Country:           req.Country,
		UserName:          req.UserName,
		Bio:               req.Bio,
		PrimaryLanguageID: req.PrimaryLanguageID,
		MuteNotifications: req.MuteNotifications,
		Github:            socials.Github,
		Twitter:           socials.Twitter,
		Linkedin:          socials.Linkedin,
		UpdatedAt:         time.Now().Unix(),
	}
	if err := r.db.Model(&user).Where("id = ? AND deleted_at IS NULL", req.UserID).Updates(user).Error; err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to update profile", map[string]any{
			"method":     "UpdateProfile",
			"userID":     req.UserID,
			"errorType": customerrors.ERR_PROFILE_UPDATE_FAILED,
		}, "REPOSITORY", err)
		return customerrors.ERR_PROFILE_UPDATE_FAILED, fmt.Errorf("unable to update profile")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "Profile updated successfully", map[string]any{
		"method": "UpdateProfile",
		"userID": req.UserID,
	}, "REPOSITORY", nil)
	return "", nil
}

func (r *UserRepository) UpdateProfileImage(req *AuthUserAdminService.UpdateProfileImageRequest) (string, error) {
	traceID := req.TraceID
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting UpdateProfileImage", map[string]any{
		"method": "UpdateProfileImage",
		"userID": req.UserID,
	}, "REPOSITORY", nil)

	if req == nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Nil update profile image request", map[string]any{
			"method":     "UpdateProfileImage",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("update profile image request cannot be nil")
	}
	if req.UserID == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
			"method":     "UpdateProfileImage",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", req.UserID).
		Updates(map[string]interface{}{
			"avatar_data": req.AvatarURL,
			"updated_at":  time.Now().Unix(),
		}).Error; err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to update profile image", map[string]any{
			"method":     "UpdateProfileImage",
			"userID":     req.UserID,
			"errorType": customerrors.ERR_PROFILE_IMAGE_UPDATE_FAILED,
		}, "REPOSITORY", err)
		return customerrors.ERR_PROFILE_IMAGE_UPDATE_FAILED, fmt.Errorf("unable to update profile picture")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "Profile image updated successfully", map[string]any{
		"method": "UpdateProfileImage",
		"userID": req.UserID,
	}, "REPOSITORY", nil)
	return "", nil
}

func (r *UserRepository) GetUserProfileByUserID(userID string) (*AuthUserAdminService.GetUserProfileResponse, string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting GetUserProfileByUserID", map[string]any{
		"method": "GetUserProfileByUserID",
		"userID": userID,
	}, "REPOSITORY", nil)

	if userID == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
			"method":     "GetUserProfileByUserID",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return nil, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	var user db.User
	if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			r.logger.Log(zapcore.ErrorLevel, traceID, "Profile not found", map[string]any{
				"method":     "GetUserProfileByUserID",
				"userID":     userID,
				"errorType": customerrors.ERR_PROFILE_NOT_FOUND,
			}, "REPOSITORY", err)
			return nil, customerrors.ERR_PROFILE_NOT_FOUND, fmt.Errorf("user profile not found")
		}
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve profile", map[string]any{
			"method":     "GetUserProfileByUserID",
			"userID":     userID,
			"errorType": customerrors.ERR_CRED_CHECK_FAILED,
		}, "REPOSITORY", err)
		return nil, customerrors.ERR_CRED_CHECK_FAILED, fmt.Errorf("unable to retrieve profile")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "Profile retrieved successfully", map[string]any{
		"method": "GetUserProfileByUserID",
		"userID": userID,
	}, "REPOSITORY", nil)
	return &AuthUserAdminService.GetUserProfileResponse{
		UserProfile: &AuthUserAdminService.UserProfile{
			UserID:            user.ID,
			UserName:          user.UserName,
			FirstName:         user.FirstName,
			LastName:          user.LastName,
			AvatarData:        user.AvatarData,
			Email:             user.Email,
			Role:              user.Role,
			Bio:               user.Bio,
			Country:           user.Country,
			IsBanned:          user.IsBanned,
			IsVerified:        user.IsVerified,
			PrimaryLanguageID: user.PrimaryLanguageID,
			MuteNotifications: user.MuteNotifications,
			TwoFactorEnabled:  user.TwoFactorEnabled,
			Socials: &AuthUserAdminService.Socials{
				Github:   user.Github,
				Twitter:  user.Twitter,
				Linkedin: user.Linkedin,
			},
			CreatedAt: user.CreatedAt,
		},
	}, "", nil
}

func (r *UserRepository) GetUserProfileByUsername(userName string) (*AuthUserAdminService.GetUserProfileResponse, string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting GetUserProfileByUsername", map[string]any{
		"method":   "GetUserProfileByUsername",
		"username": userName,
	}, "REPOSITORY", nil)

	if userName == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty username", map[string]any{
			"method":     "GetUserProfileByUsername",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return nil, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("username cannot be empty")
	}
	var user db.User
	if err := r.db.Where("user_name = ? AND deleted_at IS NULL", userName).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			r.logger.Log(zapcore.ErrorLevel, traceID, "Profile not found", map[string]any{
				"method":     "GetUserProfileByUsername",
				"username":   userName,
				"errorType": customerrors.ERR_PROFILE_NOT_FOUND,
			}, "REPOSITORY", err)
			return nil, customerrors.ERR_PROFILE_NOT_FOUND, fmt.Errorf("user profile not found")
		}
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve profile", map[string]any{
			"method":     "GetUserProfileByUsername",
			"username":   userName,
			"errorType": customerrors.ERR_CRED_CHECK_FAILED,
		}, "REPOSITORY", err)
		return nil, customerrors.ERR_CRED_CHECK_FAILED, fmt.Errorf("unable to retrieve profile")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "Profile retrieved successfully", map[string]any{
		"method":   "GetUserProfileByUsername",
		"username": userName,
		"userID":   user.ID,
	}, "REPOSITORY", nil)
	return &AuthUserAdminService.GetUserProfileResponse{
		UserProfile: &AuthUserAdminService.UserProfile{
			UserID:            user.ID,
			UserName:          user.UserName,
			FirstName:         user.FirstName,
			LastName:          user.LastName,
			AvatarData:        user.AvatarData,
			Email:             user.Email,
			Role:              user.Role,
			Bio:               user.Bio,
			Country:           user.Country,
			IsBanned:          user.IsBanned,
			IsVerified:        user.IsVerified,
			PrimaryLanguageID: user.PrimaryLanguageID,
			MuteNotifications: user.MuteNotifications,
			TwoFactorEnabled:  user.TwoFactorEnabled,
			Socials: &AuthUserAdminService.Socials{
				Github:   user.Github,
				Twitter:  user.Twitter,
				Linkedin: user.Linkedin,
			},
			CreatedAt: user.CreatedAt,
		},
	}, "", nil
}

func (r *UserRepository) CheckBanStatus(userID string) (*AuthUserAdminService.CheckBanStatusResponse, string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting CheckBanStatus", map[string]any{
		"method": "CheckBanStatus",
		"userID": userID,
	}, "REPOSITORY", nil)

	if userID == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
			"method":     "CheckBanStatus",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return nil, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}

	var user db.User
	if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			r.logger.Log(zapcore.ErrorLevel, traceID, "User not found", map[string]any{
				"method":     "CheckBanStatus",
				"userID":     userID,
				"errorType": customerrors.ERR_BAN_STATUS_NOT_FOUND,
			}, "REPOSITORY", err)
			return nil, customerrors.ERR_BAN_STATUS_NOT_FOUND, fmt.Errorf("user not found")
		}
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to check ban status", map[string]any{
			"method":     "CheckBanStatus",
			"userID":     userID,
			"errorType": customerrors.ERR_BAN_STATUS_CHECK_FAILED,
		}, "REPOSITORY", err)
		return nil, customerrors.ERR_BAN_STATUS_CHECK_FAILED, fmt.Errorf("unable to check ban status")
	}

	if !user.IsBanned {
		r.logger.Log(zapcore.InfoLevel, traceID, "User is not banned", map[string]any{
			"method": "CheckBanStatus",
			"userID": userID,
		}, "REPOSITORY", nil)
		return &AuthUserAdminService.CheckBanStatusResponse{
			IsBanned: false,
			Message:  "User is not banned",
		}, "", nil
	}

	var banHistory db.BanHistory
	if err := r.db.Where("id = ?", user.BanID).First(&banHistory).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			if err := r.db.Model(&user).Updates(map[string]interface{}{
				"is_banned": false,
				"ban_id":    nil,
			}).Error; err != nil {
				r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to update ban status", map[string]any{
					"method":     "CheckBanStatus",
					"userID":     userID,
					"errorType": customerrors.ERR_BAN_UPDATE_FAILED,
				}, "REPOSITORY", err)
				return nil, customerrors.ERR_BAN_UPDATE_FAILED, fmt.Errorf("unable to update ban status")
			}
			r.logger.Log(zapcore.InfoLevel, traceID, "Ban record not found, cleared ban status", map[string]any{
				"method": "CheckBanStatus",
				"userID": userID,
			}, "REPOSITORY", nil)
			return &AuthUserAdminService.CheckBanStatusResponse{
				IsBanned: false,
				Message:  "User is not banned",
			}, "", nil
		}
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve ban info", map[string]any{
			"method":     "CheckBanStatus",
			"userID":     userID,
			"errorType": customerrors.ERR_BAN_STATUS_CHECK_FAILED,
		}, "REPOSITORY", err)
		return nil, customerrors.ERR_BAN_STATUS_CHECK_FAILED, fmt.Errorf("unable to retrieve ban info")
	}

	if banHistory.BanExpiry != 0 && banHistory.BanExpiry < time.Now().Unix() {
		if err := r.db.Model(&user).Updates(map[string]interface{}{
			"is_banned": false,
			"ban_id":    nil,
		}).Error; err != nil {
			r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to update expired ban status", map[string]any{
				"method":     "CheckBanStatus",
				"userID":     userID,
				"errorType": customerrors.ERR_BAN_UPDATE_FAILED,
			}, "REPOSITORY", err)
			return nil, customerrors.ERR_BAN_UPDATE_FAILED, fmt.Errorf("unable to update ban status")
		}
		r.logger.Log(zapcore.InfoLevel, traceID, "Ban expired, cleared ban status", map[string]any{
			"method": "CheckBanStatus",
			"userID": userID,
		}, "REPOSITORY", nil)
		return &AuthUserAdminService.CheckBanStatusResponse{
			IsBanned: false,
			Message:  "Previous ban has expired",
		}, "", nil
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "User is banned", map[string]any{
		"method":     "CheckBanStatus",
		"userID":     userID,
		"banReason":  banHistory.BanReason,
		"banExpiry":  banHistory.BanExpiry,
	}, "REPOSITORY", nil)
	return &AuthUserAdminService.CheckBanStatusResponse{
		IsBanned:      true,
		Reason:        banHistory.BanReason,
		BanExpiration: banHistory.BanExpiry,
		Message:       "User is currently banned",
	}, "", nil
}

func (r *UserRepository) FollowUser(followerID, followeeID string) (string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting FollowUser", map[string]any{
		"method":      "FollowUser",
		"followerID":  followerID,
		"followeeID":  followeeID,
	}, "REPOSITORY", nil)

	if followerID == "" || followeeID == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty follower or followee ID", map[string]any{
			"method":     "FollowUser",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("follower ID or followee ID cannot be empty")
	}
	if err := r.db.Transaction(func(tx *gorm.DB) error {
		return tx.Create(&db.Following{
			FollowerID: followerID,
			FolloweeID: followeeID,
		}).Error
	}); err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to follow user", map[string]any{
			"method":      "FollowUser",
			"followerID":  followerID,
			"followeeID":  followeeID,
			"errorType": customerrors.ERR_FOLLOW_ACTION_FAILED,
		}, "REPOSITORY", err)
		return customerrors.ERR_FOLLOW_ACTION_FAILED, fmt.Errorf("failed to follow user")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "User followed successfully", map[string]any{
		"method":     "FollowUser",
		"followerID": followerID,
		"followeeID": followeeID,
	}, "REPOSITORY", nil)
	return "", nil
}

func (r *UserRepository) UnfollowUser(followerID, followeeID string) (string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting UnfollowUser", map[string]any{
		"method":     "UnfollowUser",
		"followerID": followerID,
		"followeeID": followeeID,
	}, "REPOSITORY", nil)

	if followerID == "" || followeeID == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty follower or followee ID", map[string]any{
			"method":     "UnfollowUser",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("follower ID or followee ID cannot be empty")
	}
	if err := r.db.Transaction(func(tx *gorm.DB) error {
		return tx.Where("follower_id = ? AND followee_id = ?", followerID, followeeID).Delete(&db.Following{}).Error
	}); err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to unfollow user", map[string]any{
			"method":      "UnfollowUser",
			"followerID":  followerID,
			"followeeID":  followeeID,
			"errorType": customerrors.ERR_UNFOLLOW_ACTION_FAILED,
		}, "REPOSITORY", err)
		return customerrors.ERR_UNFOLLOW_ACTION_FAILED, fmt.Errorf("failed to unfollow user")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "User unfollowed successfully", map[string]any{
		"method":     "UnfollowUser",
		"followerID": followerID,
		"followeeID": followeeID,
	}, "REPOSITORY", nil)
	return "", nil
}

func (r *UserRepository) GetFollowing(userID string) ([]*AuthUserAdminService.UserProfile, string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting GetFollowing", map[string]any{
		"method": "GetFollowing",
		"userID": userID,
	}, "REPOSITORY", nil)

	if userID == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
			"method":     "GetFollowing",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return nil, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	var following []db.Following
	if err := r.db.Where("follower_id = ?", userID).Find(&following).Error; err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve following list", map[string]any{
			"method":     "GetFollowing",
			"userID":     userID,
			"errorType": customerrors.ERR_FOLLOWING_LIST_FAILED,
		}, "REPOSITORY", err)
		return nil, customerrors.ERR_FOLLOWING_LIST_FAILED, fmt.Errorf("failed to retrieve following list")
	}

	var followeeIDs []string
	for _, f := range following {
		followeeIDs = append(followeeIDs, f.FolloweeID)
	}

	var users []db.User
	if len(followeeIDs) > 0 {
		if err := r.db.Where("id IN (?) AND deleted_at IS NULL", followeeIDs).Find(&users).Error; err != nil {
			r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve followees", map[string]any{
				"method":     "GetFollowing",
				"userID":     userID,
				"errorType": customerrors.ERR_FOLLOWING_LIST_FAILED,
			}, "REPOSITORY", err)
			return nil, customerrors.ERR_FOLLOWING_LIST_FAILED, fmt.Errorf("failed to retrieve followees")
		}
	}

	var profiles []*AuthUserAdminService.UserProfile
	for _, u := range users {
		profiles = append(profiles, &AuthUserAdminService.UserProfile{
			UserID:    u.ID,
			FirstName: u.FirstName,
			LastName:  u.LastName,
			Email:     u.Email,
			Role:      u.Role,
			Socials: &AuthUserAdminService.Socials{
				Github:   u.Github,
				Twitter:  u.Twitter,
				Linkedin: u.Linkedin,
			},
		})
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "Following list retrieved successfully", map[string]any{
		"method": "GetFollowing",
		"userID": userID,
		"count":  len(profiles),
	}, "REPOSITORY", nil)
	return profiles, "", nil
}

func (r *UserRepository) GetFollowers(userID string) ([]*AuthUserAdminService.UserProfile, string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting GetFollowers", map[string]any{
		"method": "GetFollowers",
		"userID": userID,
	}, "REPOSITORY", nil)

	if userID == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
			"method":     "GetFollowers",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return nil, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	var followers []db.Follower
	if err := r.db.Where("followee_id = ?", userID).Find(&followers).Error; err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve followers", map[string]any{
			"method":     "GetFollowers",
			"userID":     userID,
			"errorType": customerrors.ERR_FOLLOWERS_LIST_FAILED,
		}, "REPOSITORY", err)
		return nil, customerrors.ERR_FOLLOWERS_LIST_FAILED, fmt.Errorf("failed to retrieve followers")
	}

	var followerIDs []string
	for _, f := range followers {
		followerIDs = append(followerIDs, f.FollowerID)
	}

	var users []db.User
	if len(followerIDs) > 0 {
		if err := r.db.Where("id IN (?) AND deleted_at IS NULL", followerIDs).Find(&users).Error; err != nil {
			r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve followers", map[string]any{
				"method":     "GetFollowers",
				"userID":     userID,
				"errorType": customerrors.ERR_FOLLOWERS_LIST_FAILED,
			}, "REPOSITORY", err)
			return nil, customerrors.ERR_FOLLOWERS_LIST_FAILED, fmt.Errorf("failed to retrieve followers")
		}
	}

	var profiles []*AuthUserAdminService.UserProfile
	for _, u := range users {
		profiles = append(profiles, &AuthUserAdminService.UserProfile{
			UserID:    u.ID,
			FirstName: u.FirstName,
			LastName:  u.LastName,
			Email:     u.Email,
			Role:      u.Role,
			Socials: &AuthUserAdminService.Socials{
				Github:   u.Github,
				Twitter:  u.Twitter,
				Linkedin: u.Linkedin,
			},
		})
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "Followers list retrieved successfully", map[string]any{
		"method": "GetFollowers",
		"userID": userID,
		"count":  len(profiles),
	}, "REPOSITORY", nil)
	return profiles, "", nil
}

func (r *UserRepository) CheckFollowRelationship(ownerUserID, targetUserID string) (isFollowing bool, isFollower bool, errorType string, err error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting CheckFollowRelationship", map[string]any{
		"method":        "CheckFollowRelationship",
		"ownerUserID":   ownerUserID,
		"targetUserID":  targetUserID,
	}, "REPOSITORY", nil)

	if ownerUserID == "" || targetUserID == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user IDs", map[string]any{
			"method":     "CheckFollowRelationship",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return false, false, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user IDs cannot be empty")
	}

	var following db.Following
	if err := r.db.Where("follower_id = ? AND followee_id = ?", ownerUserID, targetUserID).First(&following).Error; err != nil {
		if err != gorm.ErrRecordNotFound {
			r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to check following status", map[string]any{
				"method":       "CheckFollowRelationship",
				"ownerUserID":  ownerUserID,
				"targetUserID": targetUserID,
				"errorType":   customerrors.ERR_FOLLOW_CHECK_FAILED,
			}, "REPOSITORY", err)
			return false, false, customerrors.ERR_FOLLOW_CHECK_FAILED, fmt.Errorf("failed to check following status")
		}
	} else {
		isFollowing = true
	}

	var follower db.Follower
	if err := r.db.Where("follower_id = ? AND followee_id = ?", targetUserID, ownerUserID).First(&follower).Error; err != nil {
		if err != gorm.ErrRecordNotFound {
			r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to check follower status", map[string]any{
				"method":       "CheckFollowRelationship",
				"ownerUserID":  ownerUserID,
				"targetUserID": targetUserID,
				"errorType":   customerrors.ERR_FOLLOW_CHECK_FAILED,
			}, "REPOSITORY", err)
			return false, false, customerrors.ERR_FOLLOW_CHECK_FAILED, fmt.Errorf("failed to check follower status")
		}
	} else {
		isFollower = true
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "Follow relationship checked", map[string]any{
		"method":       "CheckFollowRelationship",
		"ownerUserID":  ownerUserID,
		"targetUserID": targetUserID,
		"isFollowing":  isFollowing,
		"isFollower":   isFollower,
	}, "REPOSITORY", nil)
	return isFollowing, isFollower, "", nil
}

func (r *UserRepository) CreateUserAdmin(req *AuthUserAdminService.CreateUserAdminRequest) (string, string, error) {
	traceID := req.TraceID
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting CreateUserAdmin", map[string]any{
		"method": "CreateUserAdmin",
		"email":  req.Email,
	}, "REPOSITORY", nil)

	if req == nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Nil create admin request", map[string]any{
			"method":     "CreateUserAdmin",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return "", customerrors.ERR_PARAM_EMPTY, fmt.Errorf("create admin request cannot be nil")
	}
	if req.Password != req.ConfirmPassword {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Password mismatch", map[string]any{
			"method":     "CreateUserAdmin",
			"email":      req.Email,
			"errorType": customerrors.ERR_ADMIN_CREATE_PASSWORD_MISMATCH,
		}, "REPOSITORY", nil)
		return "", customerrors.ERR_ADMIN_CREATE_PASSWORD_MISMATCH, fmt.Errorf("passwords do not match")
	}
	if !IsValidEmail(req.Email) {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Invalid email", map[string]any{
			"method":     "CreateUserAdmin",
			"email":      req.Email,
			"errorType": customerrors.ERR_ADMIN_CREATE_INVALID_EMAIL,
		}, "REPOSITORY", nil)
		return "", customerrors.ERR_ADMIN_CREATE_INVALID_EMAIL, fmt.Errorf("invalid email format")
	}
	if !IsValidPassword(req.Password) {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Invalid password", map[string]any{
			"method":     "CreateUserAdmin",
			"email":      req.Email,
			"errorType": customerrors.ERR_ADMIN_CREATE_INVALID_PASSWORD,
		}, "REPOSITORY", nil)
		return "", customerrors.ERR_ADMIN_CREATE_INVALID_PASSWORD, fmt.Errorf("invalid password format")
	}

	socials := &AuthUserAdminService.Socials{}
	if req.Socials != nil {
		socials = req.Socials
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to hash password", map[string]any{
			"method":     "CreateUserAdmin",
			"email":      req.Email,
			"errorType": customerrors.ERR_PASSWORD_HASH_FAILED,
		}, "REPOSITORY", err)
		return "", customerrors.ERR_PASSWORD_HASH_FAILED, fmt.Errorf("failed to hash password")
	}

	user := db.User{
		ID:                uuid.New().String(),
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		Country:           req.Country,
		Role:              req.Role,
		PrimaryLanguageID: req.PrimaryLanguageID,
		Email:             req.Email,
		AuthType:          req.AuthType,
		HashedPassword:    string(hashedPassword),
		MuteNotifications: req.MuteNotifications,
		Github:            socials.Github,
		Twitter:           socials.Twitter,
		Linkedin:          socials.Linkedin,
	}

	if err := r.db.Create(&user).Error; err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to create admin user", map[string]any{
			"method":     "CreateUserAdmin",
			"email":      req.Email,
			"errorType": customerrors.ERR_ADMIN_CREATE_FAILED,
		}, "REPOSITORY", err)
		return "", customerrors.ERR_ADMIN_CREATE_FAILED, fmt.Errorf("failed to create admin user")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "Admin user created successfully", map[string]any{
		"method": "CreateUserAdmin",
		"userID": user.ID,
	}, "REPOSITORY", nil)
	return user.ID, "", nil
}

func (r *UserRepository) UpdateUserAdmin(req *AuthUserAdminService.UpdateUserAdminRequest) (string, error) {
	traceID := req.TraceID
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting UpdateUserAdmin", map[string]any{
		"method": "UpdateUserAdmin",
		"userID": req.UserID,
	}, "REPOSITORY", nil)

	if req == nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Nil update admin request", map[string]any{
			"method":     "UpdateUserAdmin",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("update admin request cannot be nil")
	}
	if req.UserID == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
			"method":     "UpdateUserAdmin",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	if req.Password != "" && !IsValidPassword(req.Password) {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Invalid password", map[string]any{
			"method":     "UpdateUserAdmin",
			"userID":     req.UserID,
			"errorType": customerrors.ERR_ADMIN_UPDATE_INVALID_PASSWORD,
		}, "REPOSITORY", nil)
		return customerrors.ERR_ADMIN_UPDATE_INVALID_PASSWORD, fmt.Errorf("invalid password format")
	}

	socials := &AuthUserAdminService.Socials{}
	if req.Socials != nil {
		socials = req.Socials
	}

	user := db.User{
		ID:                req.UserID,
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		Country:           req.Country,
		Role:              req.Role,
		Email:             req.Email,
		PrimaryLanguageID: req.PrimaryLanguageID,
		MuteNotifications: req.MuteNotifications,
		Github:            socials.Github,
		Twitter:           socials.Twitter,
		Linkedin:          socials.Linkedin,
		UpdatedAt:         time.Now().Unix(),
	}
	if req.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to hash password", map[string]any{
				"method":     "UpdateUserAdmin",
				"userID":     req.UserID,
				"errorType": customerrors.ERR_PASSWORD_HASH_FAILED,
			}, "REPOSITORY", err)
			return customerrors.ERR_PASSWORD_HASH_FAILED, fmt.Errorf("failed to hash password")
		}
		user.HashedPassword = string(hashedPassword)
	}

	if err := r.db.Model(&user).Where("id = ? AND deleted_at IS NULL", req.UserID).Updates(user).Error; err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to update admin user", map[string]any{
			"method":     "UpdateUserAdmin",
			"userID":     req.UserID,
			"errorType": customerrors.ERR_ADMIN_UPDATE_FAILED,
		}, "REPOSITORY", err)
		return customerrors.ERR_ADMIN_UPDATE_FAILED, fmt.Errorf("failed to update admin user")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "Admin user updated successfully", map[string]any{
		"method": "UpdateUserAdmin",
		"userID": req.UserID,
	}, "REPOSITORY", nil)
	return "", nil
}

func (r *UserRepository) BanUser(userID, banReason string, banExpiry int64, banType string) (string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting BanUser", map[string]any{
		"method":    "BanUser",
		"userID":    userID,
		"banReason": banReason,
	}, "REPOSITORY", nil)

	if userID == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
			"method":     "BanUser",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	uuid := uuid.New().String()
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Updates(map[string]interface{}{
			"is_banned": true,
			"ban_id":    uuid,
		}).Error; err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to ban user", map[string]any{
			"method":     "BanUser",
			"userID":     userID,
			"errorType": customerrors.ERR_BAN_USER_FAILED,
		}, "REPOSITORY", err)
		return customerrors.ERR_BAN_USER_FAILED, fmt.Errorf("unable to ban user")
	}

	banHistory := db.BanHistory{
		ID:        uuid,
		UserID:    userID,
		BanType:   banType,
		BannedAt:  time.Now().Unix(),
		BanReason: banReason,
		BanExpiry: time.Now().Add(time.Duration(banExpiry) * time.Hour).Unix(),
	}

	if err := r.db.Create(&banHistory).Error; err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to record ban history", map[string]any{
			"method":     "BanUser",
			"userID":     userID,
			"errorType": customerrors.ERR_BAN_USER_FAILED,
		}, "REPOSITORY", err)
		return customerrors.ERR_BAN_USER_FAILED, fmt.Errorf("failed to record ban history")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "User banned successfully", map[string]any{
		"method":    "BanUser",
		"userID":    userID,
		"banReason": banReason,
	}, "REPOSITORY", nil)
	return "", nil
}

func (r *UserRepository) UnbanUser(userID string) (string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting UnbanUser", map[string]any{
		"method": "UnbanUser",
		"userID": userID,
	}, "REPOSITORY", nil)

	if userID == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
			"method":     "UnbanUser",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Updates(map[string]interface{}{
			"is_banned": false,
		}).Error; err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to unban user", map[string]any{
			"method":     "UnbanUser",
			"userID":     userID,
			"errorType": customerrors.ERR_UNBAN_USER_FAILED,
		}, "REPOSITORY", err)
		return customerrors.ERR_UNBAN_USER_FAILED, fmt.Errorf("unable to unban user")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "User unbanned successfully", map[string]any{
		"method": "UnbanUser",
		"userID": userID,
	}, "REPOSITORY", nil)
	return "", nil
}

func (r *UserRepository) VerifyAdminUser(userID string) (string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting VerifyAdminUser", map[string]any{
		"method": "VerifyAdminUser",
		"userID": userID,
	}, "REPOSITORY", nil)

	if userID == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
			"method":     "VerifyAdminUser",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Updates(map[string]interface{}{
			"is_verified": true,
			"updated_at":  time.Now().Unix(),
		}).Error; err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to verify user", map[string]any{
			"method":     "VerifyAdminUser",
			"userID":     userID,
			"errorType": customerrors.ERR_ADMIN_VERIFY_FAILED,
		}, "REPOSITORY", err)
		return customerrors.ERR_ADMIN_VERIFY_FAILED, fmt.Errorf("failed to verify user")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "User verified successfully", map[string]any{
		"method": "VerifyAdminUser",
		"userID": userID,
	}, "REPOSITORY", nil)
	return "", nil
}

func (r *UserRepository) UnverifyUser(userID string) (string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting UnverifyUser", map[string]any{
		"method": "UnverifyUser",
		"userID": userID,
	}, "REPOSITORY", nil)

	if userID == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
			"method":     "UnverifyUser",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Updates(map[string]interface{}{
			"is_verified": false,
			"updated_at":  time.Now().Unix(),
		}).Error; err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to unverify user", map[string]any{
			"method":     "UnverifyUser",
			"userID":     userID,
			"errorType": customerrors.ERR_ADMIN_UNVERIFY_FAILED,
		}, "REPOSITORY", err)
		return customerrors.ERR_ADMIN_UNVERIFY_FAILED, fmt.Errorf("failed to unverify user")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "User unverified successfully", map[string]any{
		"method": "UnverifyUser",
		"userID": userID,
	}, "REPOSITORY", nil)
	return "", nil
}

func (r *UserRepository) SoftDeleteUserAdmin(userID string) (string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting SoftDeleteUserAdmin", map[string]any{
		"method": "SoftDeleteUserAdmin",
		"userID": userID,
	}, "REPOSITORY", nil)

	if userID == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
			"method":     "SoftDeleteUserAdmin",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Update("deleted_at", time.Now()).Error; err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to soft delete user", map[string]any{
			"method":     "SoftDeleteUserAdmin",
			"userID":     userID,
			"errorType": customerrors.ERR_ADMIN_DELETE_FAILED,
		}, "REPOSITORY", err)
		return customerrors.ERR_ADMIN_DELETE_FAILED, fmt.Errorf("failed to delete user")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "User soft deleted successfully", map[string]any{
		"method": "SoftDeleteUserAdmin",
		"userID": userID,
	}, "REPOSITORY", nil)
	return "", nil
}

func (r *UserRepository) GetAllUsers(req *AuthUserAdminService.GetAllUsersRequest) ([]*AuthUserAdminService.UserProfile, int32, string, string, string, error) {
	traceID := req.TraceID
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting GetAllUsers", map[string]any{
		"method": "GetAllUsers",
	}, "REPOSITORY", nil)

	if req == nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Nil get all users request", map[string]any{
			"method":     "GetAllUsers",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return nil, 0, customerrors.ERR_PARAM_EMPTY, "", "", fmt.Errorf("get all users request cannot be nil")
	}

	query := r.db.Model(&db.User{}).Where("deleted_at IS NULL")

	if req.RoleFilter != "" {
		query = query.Where("role = ?", req.RoleFilter)
	}

	if req.StatusFilter != "" {
		switch strings.ToLower(req.StatusFilter) {
		case "active":
			query = query.Where("is_banned = ? AND is_verified = ?", false, true)
		case "inactive":
			query = query.Where("is_banned = ? AND is_verified = ?", false, false)
		case "banned":
			query = query.Where("is_banned = ?", true)
		case "unverified":
			query = query.Where("is_verified = ?", false)
		default:
			r.logger.Log(zapcore.ErrorLevel, traceID, "Invalid status filter", map[string]any{
				"method":       "GetAllUsers",
				"statusFilter": req.StatusFilter,
				"errorType":   customerrors.ERR_INVALID_FILTER,
			}, "REPOSITORY", nil)
			return nil, 0, customerrors.ERR_INVALID_FILTER, "", "", fmt.Errorf("invalid status filter: %s", req.StatusFilter)
		}
	}

	if req.NameFilter != "" || req.EmailFilter != "" {
		searchConditions := []string{}
		args := []interface{}{}

		if req.NameFilter != "" {
			searchTerm := "%" + strings.ToLower(req.NameFilter) + "%"
			searchConditions = append(searchConditions,
				"LOWER(first_name) LIKE ?",
				"LOWER(last_name) LIKE ?",
				"LOWER(user_name) LIKE ?",
			)
			args = append(args, searchTerm, searchTerm, searchTerm)
		}

		if req.EmailFilter != "" {
			searchTerm := "%" + strings.ToLower(req.EmailFilter) + "%"
			searchConditions = append(searchConditions, "LOWER(email) LIKE ?")
			args = append(args, searchTerm)
		}

		query = query.Where(strings.Join(searchConditions, " OR "), args...)
	}

	const (
		minTimestamp = 0
		maxTimestamp = 4102444800
	)

	if req.FromDateFilter > 0 {
		if req.FromDateFilter < minTimestamp || req.FromDateFilter > maxTimestamp {
			r.logger.Log(zapcore.ErrorLevel, traceID, "Invalid from date filter", map[string]any{
				"method":         "GetAllUsers",
				"fromDateFilter": req.FromDateFilter,
				"errorType":     customerrors.ERR_INVALID_FILTER,
			}, "REPOSITORY", nil)
			return nil, 0, customerrors.ERR_INVALID_FILTER, "", "", fmt.Errorf("fromDateFilter out of valid range: %d", req.FromDateFilter)
		}
		query = query.Where("created_at >= ?", req.FromDateFilter)
	}

	if req.ToDateFilter > 0 {
		if req.ToDateFilter < minTimestamp || req.ToDateFilter > maxTimestamp {
			r.logger.Log(zapcore.ErrorLevel, traceID, "Invalid to date filter", map[string]any{
				"method":       "GetAllUsers",
				"toDateFilter": req.ToDateFilter,
				"errorType":   customerrors.ERR_INVALID_FILTER,
			}, "REPOSITORY", nil)
			return nil, 0, customerrors.ERR_INVALID_FILTER, "", "", fmt.Errorf("toDateFilter out of valid range: %d", req.ToDateFilter)
		}
		query = query.Where("created_at <= ?", req.ToDateFilter)
	}

	var totalCount int64
	if err := query.Count(&totalCount).Error; err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to count users", map[string]any{
			"method":     "GetAllUsers",
			"errorType": customerrors.ERR_USERS_LIST_FAILED,
		}, "REPOSITORY", err)
		return nil, 0, customerrors.ERR_USERS_LIST_FAILED, "", "", fmt.Errorf("failed to count users: %v", err)
	}

	limit := int(req.Limit)
	if limit <= 0 {
		limit = 10
	}

	order := "id ASC"
	isBackward := req.PrevPageToken != ""
	if isBackward {
		order = "id DESC"
		query = query.Where("id < ?", req.PrevPageToken)
	} else if req.NextPageToken != "" {
		query = query.Where("id > ?", req.NextPageToken)
	}

	var users []db.User
	err := query.Order(order).Limit(limit).Find(&users).Error
	if err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve users", map[string]any{
			"method":     "GetAllUsers",
			"errorType": customerrors.ERR_USERS_LIST_FAILED,
		}, "REPOSITORY", err)
		return nil, 0, customerrors.ERR_USERS_LIST_FAILED, "", "", fmt.Errorf("failed to retrieve users: %v", err)
	}

	if isBackward && len(users) > 0 {
		for i, j := 0, len(users)-1; i < j; i, j = i+1, j-1 {
			users[i], users[j] = users[j], users[i]
		}
	}

	profiles := make([]*AuthUserAdminService.UserProfile, 0, len(users))
	for _, u := range users {
		profiles = append(profiles, &AuthUserAdminService.UserProfile{
			UserID:            u.ID,
			UserName:          u.UserName,
			FirstName:         u.FirstName,
			LastName:          u.LastName,
			Country:           u.Country,
			Role:              u.Role,
			PrimaryLanguageID: u.PrimaryLanguageID,
			Email:             u.Email,
			AuthType:          u.AuthType,
			AvatarData:        u.AvatarData,
			MuteNotifications: u.MuteNotifications,
			IsBanned:          u.IsBanned,
			BanReason:         u.BanReason,
			BanExpiration:     u.BanExpiration,
			TwoFactorEnabled:  u.TwoFactorEnabled,
			IsVerified:        u.IsVerified,
			CreatedAt:         u.CreatedAt,
			UpdatedAt:         u.UpdatedAt,
			Bio:               u.Bio,
			Socials: &AuthUserAdminService.Socials{
				Github:   u.Github,
				Twitter:  u.Twitter,
				Linkedin: u.Linkedin,
			},
		})
	}

	nextPageToken := ""
	prevPageToken := ""

	if len(users) > 0 {
		if len(users) == limit {
			nextPageToken = users[len(users)-1].ID
		}
		prevPageToken = users[0].ID
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "Users retrieved successfully", map[string]any{
		"method":       "GetAllUsers",
		"totalCount":   totalCount,
		"usersFetched": len(users),
	}, "REPOSITORY", nil)
	return profiles, int32(totalCount), "", nextPageToken, prevPageToken, nil
}

func (r *UserRepository) ChangePassword(email, hashedPassword string) (string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting ChangePassword", map[string]any{
		"method": "ChangePassword",
		"email":  email,
	}, "REPOSITORY", nil)

	if email == "" || hashedPassword == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty email or password", map[string]any{
			"method":     "ChangePassword",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("email or password cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("email = ? AND deleted_at IS NULL", email).
		Updates(map[string]interface{}{
			"hashed_password": hashedPassword,
			"updated_at":      time.Now().Unix(),
		}).Error; err != nil {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to update password", map[string]any{
			"method":     "ChangePassword",
			"email":      email,
			"errorType": customerrors.ERR_PW_CHANGE_MISMATCH,
		}, "REPOSITORY", err)
		return customerrors.ERR_PW_CHANGE_MISMATCH, fmt.Errorf("unable to update password")
	}

	r.logger.Log(zapcore.InfoLevel, traceID, "Password changed successfully", map[string]any{
		"method": "ChangePassword",
		"email":  email,
	}, "REPOSITORY", nil)
	return "", nil
}

func (r *UserRepository) IsUserVerified(userID string) (bool, string, error) {
	traceID := uuid.New().String()
	r.logger.Log(zapcore.InfoLevel, traceID, "Starting IsUserVerified", map[string]any{
		"method": "IsUserVerified",
		"userID": userID,
	}, "REPOSITORY", nil)

	if userID == "" {
		r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
			"method":     "IsUserVerified",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "REPOSITORY", nil)
		return false, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	var user db.User
	if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			r.logger.Log(zapcore.ErrorLevel, traceID, "User not found", map[string]any{
				"method":     "IsUserVerified",
				"userID":     userID,
				"errorType": customerrors.ERR_USER_NOT_FOUND,
			}, "REPOSITORY", err)
			return false, customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("user not found")
		}
		r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to check verification status", map[string]any{
			"method":     "IsUserVerified",
			"userID":     userID,
						"errorType": customerrors.ERR_CRED_CHECK_FAILED,
					}, "REPOSITORY", err)
					return false, customerrors.ERR_CRED_CHECK_FAILED, fmt.Errorf("failed to check verification status")
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "User verification status checked", map[string]any{
					"method":      "IsUserVerified",
					"userID":      userID,
					"isVerified":  user.IsVerified,
				}, "REPOSITORY", nil)
				return user.IsVerified, "", nil
}

func (r *UserRepository) IsAdmin(userID string) (bool, string, error) {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting IsAdmin", map[string]any{
					"method": "IsAdmin",
					"userID": userID,
				}, "REPOSITORY", nil)

				if userID == "" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
						"method":     "IsAdmin",
						"errorType": customerrors.ERR_PARAM_EMPTY,
					}, "REPOSITORY", nil)
					return false, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
				}
				var user db.User
				if err := r.db.Where("id = ? AND role = ? AND deleted_at IS NULL", userID, "ADMIN").First(&user).Error; err != nil {
					if err == gorm.ErrRecordNotFound {
						r.logger.Log(zapcore.InfoLevel, traceID, "User is not admin", map[string]any{
							"method": "IsAdmin",
							"userID": userID,
						}, "REPOSITORY", nil)
						return false, "", nil
					}
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to check admin status", map[string]any{
						"method":     "IsAdmin",
						"userID":     userID,
						"errorType": customerrors.ERR_CRED_CHECK_FAILED,
					}, "REPOSITORY", err)
					return false, customerrors.ERR_CRED_CHECK_FAILED, fmt.Errorf("failed to check admin status")
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "User is admin", map[string]any{
					"method": "IsAdmin",
					"userID": userID,
				}, "REPOSITORY", nil)
				return true, "", nil
}

func (r *UserRepository) GetUserFor2FA(userID string) (*db.User, string, error) {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting GetUserFor2FA", map[string]any{
					"method": "GetUserFor2FA",
					"userID": userID,
				}, "REPOSITORY", nil)

				if userID == "" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
						"method":     "GetUserFor2FA",
						"errorType": customerrors.ERR_PARAM_EMPTY,
					}, "REPOSITORY", nil)
					return nil, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
				}
				var user db.User
				if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
					if err == gorm.ErrRecordNotFound {
						r.logger.Log(zapcore.ErrorLevel, traceID, "User not found", map[string]any{
							"method":     "GetUserFor2FA",
							"userID":     userID,
							"errorType": customerrors.ERR_USER_NOT_FOUND,
						}, "REPOSITORY", err)
						return nil, customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("user not found")
					}
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve user for 2FA", map[string]any{
						"method":     "GetUserFor2FA",
						"userID":     userID,
						"errorType": customerrors.ERR_CRED_CHECK_FAILED,
					}, "REPOSITORY", err)
					return nil, customerrors.ERR_CRED_CHECK_FAILED, fmt.Errorf("failed to retrieve user for 2FA")
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "User retrieved for 2FA", map[string]any{
					"method": "GetUserFor2FA",
					"userID": userID,
				}, "REPOSITORY", nil)
				return &user, "", nil
}

func (r *UserRepository) CreateVerification(userID, email, token string) (string, error) {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting CreateVerification", map[string]any{
					"method": "CreateVerification",
					"userID": userID,
					"email":  email,
				}, "REPOSITORY", nil)

				if userID == "" || email == "" || token == "" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID, email, or token", map[string]any{
						"method":     "CreateVerification",
						"errorType": customerrors.ERR_PARAM_EMPTY,
					}, "REPOSITORY", nil)
					return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID, email, or token cannot be empty")
				}
				verification := db.Verification{
					UserID:    userID,
					Email:     email,
					Token:     token,
					CreatedAt: time.Now().Unix(),
					ExpiryAt:  time.Now().Add(30 * time.Minute).Unix(),
					Used:      false,
				}
				if err := r.db.Create(&verification).Error; err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to create verification record", map[string]any{
						"method":     "CreateVerification",
						"userID":     userID,
						"email":      email,
						"errorType": customerrors.ERR_TOKEN_CREATION_FAILED,
					}, "REPOSITORY", err)
					return customerrors.ERR_TOKEN_CREATION_FAILED, fmt.Errorf("failed to create verification record")
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "Verification record created", map[string]any{
					"method": "CreateVerification",
					"userID": userID,
					"email":  email,
				}, "REPOSITORY", nil)
				return "", nil
}

func (r *UserRepository) VerifyUserToken(email, token string) (bool, string, error) {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting VerifyUserToken", map[string]any{
					"method": "VerifyUserToken",
					"email":  email,
				}, "REPOSITORY", nil)

				if email == "" || token == "" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Empty email or token", map[string]any{
						"method":     "VerifyUserToken",
						"errorType": customerrors.ERR_PARAM_EMPTY,
					}, "REPOSITORY", nil)
					return false, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("email or token cannot be empty")
				}

				var user db.User
				if err := r.db.Where("email = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
					if err == gorm.ErrRecordNotFound {
						r.logger.Log(zapcore.ErrorLevel, traceID, "Account not found", map[string]any{
							"method":     "VerifyUserToken",
							"email":      email,
							"errorType": customerrors.ERR_USER_NOT_FOUND,
						}, "REPOSITORY", err)
						return false, customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("account not found")
					}
					r.logger.Log(zapcore.ErrorLevel, traceID, "Unable to verify account", map[string]any{
						"method":     "VerifyUserToken",
						"email":      email,
						"errorType": customerrors.ERR_VERIFY_CHECK_FAILED,
					}, "REPOSITORY", err)
					return false, customerrors.ERR_VERIFY_CHECK_FAILED, fmt.Errorf("unable to verify account")
				}

				if user.IsVerified {
					r.logger.Log(zapcore.ErrorLevel, traceID, "User already verified", map[string]any{
						"method":     "VerifyUserToken",
						"email":      email,
						"errorType": customerrors.ERR_ALREADY_VERIFIED,
					}, "REPOSITORY", nil)
					return false, customerrors.ERR_ALREADY_VERIFIED, fmt.Errorf("user already verified")
				}

				var verification db.Verification
				if err := r.db.Where("email = ? AND token = ? AND expiry_at > ? AND used = ?", email, token, time.Now().Unix(), false).First(&verification).Error; err != nil {
					if err == gorm.ErrRecordNotFound {
						r.logger.Log(zapcore.ErrorLevel, traceID, "Invalid or expired verification code", map[string]any{
							"method":     "VerifyUserToken",
							"email":      email,
							"errorType": customerrors.ERR_VERIFY_TOKEN_INVALID,
						}, "REPOSITORY", err)
						return false, customerrors.ERR_VERIFY_TOKEN_INVALID, fmt.Errorf("invalid or expired verification code")
					}
					r.logger.Log(zapcore.ErrorLevel, traceID, "Unable to verify account", map[string]any{
						"method":     "VerifyUserToken",
						"email":      email,
						"errorType": customerrors.ERR_VERIFY_CHECK_FAILED,
					}, "REPOSITORY", err)
					return false, customerrors.ERR_VERIFY_CHECK_FAILED, fmt.Errorf("unable to verify account")
				}

				if err := r.db.Model(&verification).Update("used", true).Error; err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to mark token as used", map[string]any{
						"method":     "VerifyUserToken",
						"email":      email,
						"errorType": customerrors.ERR_TOKEN_VERIFICATION_FAILED,
					}, "REPOSITORY", err)
					return false, customerrors.ERR_TOKEN_VERIFICATION_FAILED, fmt.Errorf("failed to mark token as used")
				}
				if err := r.db.Model(&db.User{}).Where("email = ?", email).Update("is_verified", true).Error; err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to update verification status", map[string]any{
						"method":     "VerifyUserToken",
						"email":      email,
						"errorType": customerrors.ERR_PROFILE_UPDATE_FAILED,
					}, "REPOSITORY", err)
					return false, customerrors.ERR_PROFILE_UPDATE_FAILED, fmt.Errorf("failed to update verification status")
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "User token verified successfully", map[string]any{
					"method": "VerifyUserToken",
					"email":  email,
				}, "REPOSITORY", nil)
				return true, "", nil
}

func (r *UserRepository) ResendEmailVerification(email string) (string, int64, string, error) {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting ResendEmailVerification", map[string]any{
					"method": "ResendEmailVerification",
					"email":  email,
				}, "REPOSITORY", nil)

				if email == "" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Empty email", map[string]any{
						"method":     "ResendEmailVerification",
						"errorType": customerrors.ERR_PARAM_EMPTY,
					}, "REPOSITORY", nil)
					return "", 0, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("email cannot be empty")
				}
				var user db.User
				if err := r.db.Where("email = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
					if err == gorm.ErrRecordNotFound {
						r.logger.Log(zapcore.ErrorLevel, traceID, "Account not found", map[string]any{
							"method":     "ResendEmailVerification",
							"email":      email,
							"errorType": customerrors.ERR_USER_NOT_FOUND,
						}, "REPOSITORY", err)
						return "", 0, customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("account not found")
					}
					r.logger.Log(zapcore.ErrorLevel, traceID, "Unable to send verification code", map[string]any{
						"method":     "ResendEmailVerification",
						"email":      email,
						"errorType": customerrors.ERR_EMAIL_RESEND_FAILED,
					}, "REPOSITORY", err)
					return "", 0, customerrors.ERR_EMAIL_RESEND_FAILED, fmt.Errorf("unable to send verification code")
				}

				if user.IsVerified {
					r.logger.Log(zapcore.ErrorLevel, traceID, "User already verified", map[string]any{
						"method":     "ResendEmailVerification",
						"email":      email,
						"errorType": customerrors.ERR_ALREADY_VERIFIED,
					}, "REPOSITORY", nil)
					return "", 0, customerrors.ERR_ALREADY_VERIFIED, fmt.Errorf("user already verified")
				}

				var existingVerification db.Verification
				if err := r.db.Where("user_id = ? AND expiry_at > ? AND used = ?", user.ID, time.Now().Unix(), false).First(&existingVerification).Error; err == nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Verification already exists", map[string]any{
						"method":     "ResendEmailVerification",
						"email":      email,
						"errorType": customerrors.ERR_VERIFICATION_ALREADY_EXISTS,
					}, "REPOSITORY", nil)
					return "", existingVerification.ExpiryAt, customerrors.ERR_VERIFICATION_ALREADY_EXISTS, fmt.Errorf("verification already exists")
				}

				otp := GenerateOTP(6)
				verification := db.Verification{
					ID:        uuid.New().String(),
					UserID:    user.ID,
					Email:     user.Email,
					Token:     otp,
					CreatedAt: time.Now().Unix(),
					ExpiryAt:  time.Now().Add(1 * time.Minute).Unix(),
					Used:      false,
				}
				if err := r.db.Create(&verification).Error; err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to create verification", map[string]any{
						"method":     "ResendEmailVerification",
						"email":      email,
						"errorType": customerrors.ERR_TOKEN_CREATION_FAILED,
					}, "REPOSITORY", err)
					return "", 0, customerrors.ERR_TOKEN_CREATION_FAILED, fmt.Errorf("failed to create verification")
				}

				if err := r.SendVerificationEmail(user.Email, otp); err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to send verification email", map[string]any{
						"method": "ResendEmailVerification",
						"email":  email,
					}, "REPOSITORY", err)
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "Verification email resent", map[string]any{
					"method": "ResendEmailVerification",
					"email":  email,
				}, "REPOSITORY", nil)
				return otp, verification.ExpiryAt, "", nil
}

func (r *UserRepository) CreateForgotPasswordToken(email, token string) (string, string, error) {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting CreateForgotPasswordToken", map[string]any{
					"method": "CreateForgotPasswordToken",
					"email":  email,
				}, "REPOSITORY", nil)

				if email == "" || token == "" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Empty email or token", map[string]any{
						"method":     "CreateForgotPasswordToken",
						"errorType": customerrors.ERR_PARAM_EMPTY,
					}, "REPOSITORY", nil)
					return "", customerrors.ERR_PARAM_EMPTY, fmt.Errorf("email or token cannot be empty")
				}
				var user db.User
				if err := r.db.Where("email = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
					if err == gorm.ErrRecordNotFound {
						r.logger.Log(zapcore.ErrorLevel, traceID, "User not found", map[string]any{
							"method":     "CreateForgotPasswordToken",
							"email":      email,
							"errorType": customerrors.ERR_USER_NOT_FOUND,
						}, "REPOSITORY", err)
						return "", customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("user not found")
					}
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve user", map[string]any{
						"method":     "CreateForgotPasswordToken",
						"email":      email,
						"errorType": customerrors.ERR_PW_FORGOT_INIT_FAILED,
					}, "REPOSITORY", err)
					return "", customerrors.ERR_PW_FORGOT_INIT_FAILED, fmt.Errorf("failed to retrieve user")
				}

				if err := r.db.Where("user_id = ? AND expiry_at > ? AND used = ?", user.ID, time.Now().Unix(), false).Delete(&db.ForgotPassword{}).Error; err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to clear existing reset token", map[string]any{
						"method":     "CreateForgotPasswordToken",
						"email":      email,
						"errorType": customerrors.ERR_TOKEN_CREATION_FAILED,
					}, "REPOSITORY", err)
					return "", customerrors.ERR_TOKEN_CREATION_FAILED, fmt.Errorf("failed to clear existing reset token")
				}

				forgot := db.ForgotPassword{
					ID:        uuid.New().String(),
					UserID:    user.ID,
					Email:     user.Email,
					Token:     token,
					CreatedAt: time.Now().Unix(),
					ExpiryAt:  time.Now().Add(1 * time.Hour).Unix(),
					Used:      false,
				}
				if err := r.db.Create(&forgot).Error; err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to create reset token", map[string]any{
						"method":     "CreateForgotPasswordToken",
						"email":      email,
						"errorType": customerrors.ERR_TOKEN_CREATION_FAILED,
					}, "REPOSITORY", err)
					return "", customerrors.ERR_TOKEN_CREATION_FAILED, fmt.Errorf("failed to create reset token")
				}

				if r.config.APPURL != "" {
					resetLink := fmt.Sprintf("http://localhost:5173/reset-password?token=%s&email=%s", token, user.Email)
					if err := r.SendForgotPasswordEmail(user.Email, resetLink); err != nil {
						r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to send password reset email", map[string]any{
							"method": "CreateForgotPasswordToken",
							"email":  email,
						}, "REPOSITORY", err)
					}
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "Forgot password token created", map[string]any{
					"method": "CreateForgotPasswordToken",
					"email":  email,
					"userID": user.ID,
				}, "REPOSITORY", nil)
				return user.ID, "", nil
}

func (r *UserRepository) VerifyForgotPasswordToken(userID, token string) (bool, string, error) {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting VerifyForgotPasswordToken", map[string]any{
					"method": "VerifyForgotPasswordToken",
					"userID": userID,
				}, "REPOSITORY", nil)

				if userID == "" || token == "" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID or token", map[string]any{
						"method":     "VerifyForgotPasswordToken",
						"errorType": customerrors.ERR_PARAM_EMPTY,
					}, "REPOSITORY", nil)
					return false, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID or token cannot be empty")
				}
				var forgot db.ForgotPassword
				if err := r.db.Where("user_id = ? AND token = ? AND expiry_at > ? AND used = ?", userID, token, time.Now().Unix(), false).First(&forgot).Error; err != nil {
					if err == gorm.ErrRecordNotFound {
						r.logger.Log(zapcore.InfoLevel, traceID, "Invalid or expired reset token", map[string]any{
							"method": "VerifyForgotPasswordToken",
							"userID": userID,
						}, "REPOSITORY", nil)
						return false, "", nil
					}
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to verify reset token", map[string]any{
						"method":     "VerifyForgotPasswordToken",
						"userID":     userID,
						"errorType": customerrors.ERR_TOKEN_VERIFICATION_FAILED,
					}, "REPOSITORY", err)
					return false, customerrors.ERR_TOKEN_VERIFICATION_FAILED, fmt.Errorf("failed to verify reset token")
				}

				if err := r.db.Model(&forgot).Update("used", true).Error; err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to mark reset token as used", map[string]any{
						"method":     "VerifyForgotPasswordToken",
						"userID":     userID,
						"errorType": customerrors.ERR_TOKEN_VERIFICATION_FAILED,
					}, "REPOSITORY", err)
					return false, customerrors.ERR_TOKEN_VERIFICATION_FAILED, fmt.Errorf("failed to mark reset token as used")
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "Reset token verified successfully", map[string]any{
					"method": "VerifyForgotPasswordToken",
					"userID": userID,
				}, "REPOSITORY", nil)
				return true, "", nil
}

func (r *UserRepository) FinishForgotPassword(email, token, newPassword string) (string, error) {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting FinishForgotPassword", map[string]any{
					"method": "FinishForgotPassword",
					"email":  email,
				}, "REPOSITORY", nil)

				if email == "" || token == "" || newPassword == "" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Empty email, token, or new password", map[string]any{
						"method":     "FinishForgotPassword",
						"errorType": customerrors.ERR_PARAM_EMPTY,
					}, "REPOSITORY", nil)
					return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("email, token, or new password cannot be empty")
				}

				var user db.User
				if err := r.db.Where("email = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
					if err == gorm.ErrRecordNotFound {
						r.logger.Log(zapcore.ErrorLevel, traceID, "No account found", map[string]any{
							"method":     "FinishForgotPassword",
							"email":      email,
							"errorType": customerrors.ERR_USER_NOT_FOUND,
						}, "REPOSITORY", err)
						return customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("no account found")
					}
					r.logger.Log(zapcore.ErrorLevel, traceID, "Unable to process password reset", map[string]any{
						"method":     "FinishForgotPassword",
						"email":      email,
						"errorType": customerrors.ERR_PW_RESET_MISMATCH,
					}, "REPOSITORY", err)
					return customerrors.ERR_PW_RESET_MISMATCH, fmt.Errorf("unable to process password reset")
				}

				var forgotPassword db.ForgotPassword
				if err := r.db.Where("user_id = ? AND token = ? AND expiry_at > ? AND used = ?", user.ID, token, time.Now().Unix(), false).First(&forgotPassword).Error; err != nil {
					if err == gorm.ErrRecordNotFound {
						r.logger.Log(zapcore.ErrorLevel, traceID, "Invalid or expired reset token", map[string]any{
							"method":     "FinishForgotPassword",
							"email":      email,
							"errorType": customerrors.ERR_VERIFY_TOKEN_INVALID,
						}, "REPOSITORY", err)
						return customerrors.ERR_VERIFY_TOKEN_INVALID, fmt.Errorf("invalid or expired reset token")
					}
					r.logger.Log(zapcore.ErrorLevel, traceID, "Unable to verify reset token", map[string]any{
						"method":     "FinishForgotPassword",
						"email":      email,
						"errorType": customerrors.ERR_TOKEN_VERIFICATION_FAILED,
					}, "REPOSITORY", err)
					return customerrors.ERR_TOKEN_VERIFICATION_FAILED, fmt.Errorf("unable to verify reset token")
				}

				salt := uuid.New().String()
				hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword+salt), bcrypt.DefaultCost)
				if err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Unable to process new password", map[string]any{
						"method":     "FinishForgotPassword",
						"email":      email,
						"errorType": customerrors.ERR_PASSWORD_HASH_FAILED,
					}, "REPOSITORY", err)
					return customerrors.ERR_PASSWORD_HASH_FAILED, fmt.Errorf("unable to process new password")
				}

				tx := r.db.Begin()
				if err := tx.Error; err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Unable to start transaction", map[string]any{
						"method":     "FinishForgotPassword",
						"email":      email,
						"errorType": customerrors.ERR_PW_RESET_MISMATCH,
					}, "REPOSITORY", err)
					return customerrors.ERR_PW_RESET_MISMATCH, fmt.Errorf("unable to process password reset")
				}

				if err := tx.Model(&user).Updates(map[string]interface{}{
					"hashed_password": string(hashedPassword),
					"salt":            salt,
					"updated_at":      time.Now().Unix(),
				}).Error; err != nil {
					tx.Rollback()
					r.logger.Log(zapcore.ErrorLevel, traceID, "Unable to update password", map[string]any{
						"method":     "FinishForgotPassword",
						"email":      email,
						"errorType": customerrors.ERR_PW_RESET_MISMATCH,
					}, "REPOSITORY", err)
					return customerrors.ERR_PW_RESET_MISMATCH, fmt.Errorf("unable to update password")
				}

				if err := tx.Model(&forgotPassword).Updates(map[string]interface{}{
					"used": true,
				}).Error; err != nil {
					tx.Rollback()
					r.logger.Log(zapcore.ErrorLevel, traceID, "Unable to complete password reset", map[string]any{
						"method":     "FinishForgotPassword",
						"email":      email,
						"errorType": customerrors.ERR_PW_RESET_MISMATCH,
					}, "REPOSITORY", err)
					return customerrors.ERR_PW_RESET_MISMATCH, fmt.Errorf("unable to complete password reset")
				}

				if err := tx.Commit().Error; err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Unable to commit transaction", map[string]any{
						"method":     "FinishForgotPassword",
						"email":      email,
						"errorType": customerrors.ERR_PW_RESET_MISMATCH,
					}, "REPOSITORY", err)
					return customerrors.ERR_PW_RESET_MISMATCH, fmt.Errorf("unable to complete password reset")
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "Password reset completed", map[string]any{
					"method": "FinishForgotPassword",
					"email":  email,
				}, "REPOSITORY", nil)
				return "", nil
}

func (r *UserRepository) ChangeAuthenticatedPassword(userID, oldPassword, newPassword string) (string, error) {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting ChangeAuthenticatedPassword", map[string]any{
					"method": "ChangeAuthenticatedPassword",
					"userID": userID,
				}, "REPOSITORY", nil)

				if userID == "" || oldPassword == "" || newPassword == "" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID, old password, or new password", map[string]any{
						"method":     "ChangeAuthenticatedPassword",
						"errorType": customerrors.ERR_PARAM_EMPTY,
					}, "REPOSITORY", nil)
					return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID, old password, or new password cannot be empty")
				}
				user, _, err := r.GetUserByUserID(userID)
				if err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve user", map[string]any{
						"method":     "ChangeAuthenticatedPassword",
						"userID":     userID,
						"errorType": customerrors.ERR_USER_NOT_FOUND,
					}, "REPOSITORY", err)
					return customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("failed to retrieve user")
				}

				if user.HashedPassword == "" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "No existing password found", map[string]any{
						"method":     "ChangeAuthenticatedPassword",
						"userID":     userID,
						"errorType": customerrors.ERR_NO_EXISTING_PASSWORD,
					}, "REPOSITORY", nil)
					return customerrors.ERR_NO_EXISTING_PASSWORD, fmt.Errorf("no existing password found")
				}

				if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(oldPassword+user.Salt)); err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Invalid old password", map[string]any{
						"method":     "ChangeAuthenticatedPassword",
						"userID":     userID,
						"errorType": customerrors.ERR_CRED_WRONG,
					}, "REPOSITORY", err)
					return customerrors.ERR_CRED_WRONG, fmt.Errorf("invalid old password")
				}

				if !IsValidPassword(newPassword) {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Invalid new password format", map[string]any{
						"method":     "ChangeAuthenticatedPassword",
						"userID":     userID,
						"errorType": customerrors.ERR_PW_CHANGE_INVALID_PASSWORD,
					}, "REPOSITORY", nil)
					return customerrors.ERR_PW_CHANGE_INVALID_PASSWORD, fmt.Errorf("invalid new password format")
				}

				hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword+user.Salt), bcrypt.DefaultCost)
				if err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to hash new password", map[string]any{
						"method":     "ChangeAuthenticatedPassword",
						"userID":     userID,
						"errorType": customerrors.ERR_PASSWORD_HASH_FAILED,
					}, "REPOSITORY", err)
					return customerrors.ERR_PASSWORD_HASH_FAILED, fmt.Errorf("failed to hash password")
				}

				_,err = r.ChangePassword(user.Email, string(hashedNewPassword))
				if err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to change password", map[string]any{
						"method":     "ChangeAuthenticatedPassword",
						"userID":     userID,
						"errorType": customerrors.ERR_PW_CHANGE_MISMATCH,
					}, "REPOSITORY", err)
					return customerrors.ERR_PW_CHANGE_MISMATCH, err
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "Authenticated password changed successfully", map[string]any{
					"method": "ChangeAuthenticatedPassword",
					"userID": userID,
				}, "REPOSITORY", nil)
				return "", nil
}

func (r *UserRepository) SendVerificationEmail(to, otp string) error {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting SendVerificationEmail", map[string]any{
					"method": "SendVerificationEmail",
					"email":  to,
				}, "REPOSITORY", nil)

				if to == "" || otp == "" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Empty email or OTP", map[string]any{
						"method": "SendVerificationEmail",
					}, "REPOSITORY", nil)
					return fmt.Errorf("email or OTP cannot be empty")
				}
				err := utils.SendOTPEmail(to, "user", otp, 30)
				if err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to send verification email", map[string]any{
						"method": "SendVerificationEmail",
						"email":  to,
					}, "REPOSITORY", err)
					return err
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "Verification email sent", map[string]any{
					"method": "SendVerificationEmail",
					"email":  to,
				}, "REPOSITORY", nil)
				return nil
}

func (r *UserRepository) SendForgotPasswordEmail(to, resetLink string) error {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting SendForgotPasswordEmail", map[string]any{
					"method": "SendForgotPasswordEmail",
					"email":  to,
				}, "REPOSITORY", nil)

				if to == "" || resetLink == "" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Empty email or reset link", map[string]any{
						"method": "SendForgotPasswordEmail",
					}, "REPOSITORY", nil)
					return fmt.Errorf("email or reset link cannot be empty")
				}
				err := utils.SendForgotPasswordEmail(to, resetLink)
				if err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to send forgot password email", map[string]any{
						"method": "SendForgotPasswordEmail",
						"email":  to,
					}, "REPOSITORY", err)
					return err
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "Forgot password email sent", map[string]any{
					"method": "SendForgotPasswordEmail",
					"email":  to,
				}, "REPOSITORY", nil)
				return nil
}

func GenerateOTP(length int) string {
				if length <= 0 {
					length = 6
				}
				const chars = "0123456789"
				result := make([]byte, length)
				for i := range result {
					result[i] = chars[rand.Intn(len(chars))]
				}
				return string(result)
}

func IsValidEmail(email string) bool {
				if email == "" || !strings.Contains(email, "@") || !strings.Contains(email, ".") {
					return false
				}
				return true
}

func IsValidPassword(password string) bool {
				if len(password) < 8 {
					return false
				}
				hasUpper := false
				hasDigit := false
				for _, c := range password {
					if c >= 'A' && c <= 'Z' {
						hasUpper = true
					} else if c >= '0' && c <= '9' {
						hasDigit = true
					}
				}
				return hasUpper && hasDigit
}

func (r *UserRepository) GetBanHistory(userID string) ([]*AuthUserAdminService.BanHistory, string, error) {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting GetBanHistory", map[string]any{
					"method": "GetBanHistory",
					"userID": userID,
				}, "REPOSITORY", nil)

				if userID == "" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
						"method":     "GetBanHistory",
						"errorType": customerrors.ERR_PARAM_EMPTY,
					}, "REPOSITORY", nil)
					return nil, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
				}
				var bans []db.BanHistory
				if err := r.db.Where("user_id = ?", userID).Find(&bans).Error; err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve ban history", map[string]any{
						"method":     "GetBanHistory",
						"userID":     userID,
						"errorType": customerrors.ERR_BAN_HISTORY_FAILED,
					}, "REPOSITORY", err)
					return nil, customerrors.ERR_BAN_HISTORY_FAILED, fmt.Errorf("failed to retrieve ban history")
				}

				var history []*AuthUserAdminService.BanHistory
				for _, ban := range bans {
					history = append(history, &AuthUserAdminService.BanHistory{
						Id:        ban.ID,
						UserID:    ban.UserID,
						BanType:   ban.BanType,
						BannedAt:  ban.BannedAt,
						BanReason: ban.BanReason,
						BanExpiry: ban.BanExpiry,
					})
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "Ban history retrieved", map[string]any{
					"method": "GetBanHistory",
					"userID": userID,
					"count":  len(history),
				}, "REPOSITORY", nil)
				return history, "", nil
}

func (r *UserRepository) SearchUsers(query, pageToken string, limit int32) ([]*AuthUserAdminService.UserProfile, string, string, error) {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting SearchUsers", map[string]any{
					"method": "SearchUsers",
					"query":  query,
				}, "REPOSITORY", nil)

				var users []db.User
				queryBuilder := r.db.Where("deleted_at IS NULL").Order("id ASC")

				if pageToken != "" {
					decodedToken, err := base64.StdEncoding.DecodeString(pageToken)
					if err != nil {
						pageToken = ""
					}
					lastID, err := uuid.Parse(string(decodedToken))
					if err != nil {
						pageToken = ""
					}
					queryBuilder = queryBuilder.Where("id > ?", lastID)
				}

				if query != "" {
					queryBuilder = queryBuilder.Where("first_name ILIKE ? OR last_name ILIKE ? OR email ILIKE ? OR user_name ILIKE ?", "%"+query+"%", "%"+query+"%", "%"+query+"%", "%"+query+"%")
				}

				if err := queryBuilder.Limit(int(limit)+1).Find(&users).Error; err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve users", map[string]any{
						"method":     "SearchUsers",
						"query":      query,
						"errorType": customerrors.ERR_USERS_SEARCH_FAILED,
					}, "REPOSITORY", err)
					return nil, "", customerrors.ERR_USERS_SEARCH_FAILED, fmt.Errorf("failed to retrieve users")
				}

				var profiles []*AuthUserAdminService.UserProfile
				for _, u := range users {
					profiles = append(profiles, &AuthUserAdminService.UserProfile{
						UserID:            u.ID,
						UserName:          u.UserName,
						FirstName:         u.FirstName,
						LastName:          u.LastName,
						AvatarData:        u.AvatarData,
						Email:             u.Email,
						Role:              u.Role,
						Country:           u.Country,
						Bio:               u.Bio,
						IsBanned:          u.IsBanned,
						PrimaryLanguageID: u.PrimaryLanguageID,
						Socials: &AuthUserAdminService.Socials{
							Github:   u.Github,
							Twitter:  u.Twitter,
							Linkedin: u.Linkedin,
						},
						CreatedAt: u.CreatedAt,
					})
				}

				var nextPageToken string
				if len(profiles) > int(limit) {
					profiles = profiles[:limit]
					lastID := profiles[len(profiles)-1].UserID
					nextPageToken = base64.StdEncoding.EncodeToString([]byte(lastID))
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "Users search completed", map[string]any{
					"method": "SearchUsers",
					"query":  query,
					"count":  len(profiles),
				}, "REPOSITORY", nil)
				return profiles, nextPageToken, "", nil
}

func (r *UserRepository) LogoutUser(userID string) (string, error) {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting LogoutUser", map[string]any{
					"method": "LogoutUser",
					"userID": userID,
				}, "REPOSITORY", nil)

				if userID == "" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
						"method":     "LogoutUser",
						"errorType": customerrors.ERR_PARAM_EMPTY,
					}, "REPOSITORY", nil)
					return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
				}

				var user db.User
				if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve user", map[string]any{
						"method":     "LogoutUser",
						"userID":     userID,
						"errorType": customerrors.ERR_USER_NOT_FOUND,
					}, "REPOSITORY", err)
					return customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("failed to retrieve user")
				}

				if !user.TwoFactorEnabled {
					r.logger.Log(zapcore.InfoLevel, traceID, "User logged out, 2FA not enabled", map[string]any{
						"method": "LogoutUser",
						"userID": userID,
					}, "REPOSITORY", nil)
					return "", nil
				}

				if err := r.db.Model(&user).Update("is_verified", false).Error; err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to toggle verification", map[string]any{
						"method":     "LogoutUser",
						"userID":     userID,
						"errorType": customerrors.ERR_PROFILE_UPDATE_FAILED,
					}, "REPOSITORY", err)
					return customerrors.ERR_PROFILE_UPDATE_FAILED, fmt.Errorf("failed to toggle verification")
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "User logged out successfully", map[string]any{
					"method": "LogoutUser",
					"userID": userID,
				}, "REPOSITORY", nil)
				return "", nil
}

func (r *UserRepository) SetUpTwoFactorAuth(userID string) (string, string, string, error) {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting SetUpTwoFactorAuth", map[string]any{
					"method": "SetUpTwoFactorAuth",
					"userID": userID,
				}, "REPOSITORY", nil)

				if userID == "" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
						"method":     "SetUpTwoFactorAuth",
						"errorType": customerrors.ERR_PARAM_EMPTY,
					}, "REPOSITORY", nil)
					return "", "", customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
				}

				var user db.User
				if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve user", map[string]any{
						"method":     "SetUpTwoFactorAuth",
						"userID":     userID,
						"errorType": customerrors.ERR_USER_NOT_FOUND,
					}, "REPOSITORY", err)
					return "", "", customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("failed to retrieve user")
				}

				if user.TwoFactorEnabled {
					r.logger.Log(zapcore.ErrorLevel, traceID, "2FA already enabled", map[string]any{
						"method":     "SetUpTwoFactorAuth",
						"userID":     userID,
						"errorType": customerrors.ERR_2FA_ALREADY_ENABLED,
					}, "REPOSITORY", nil)
					return "", "", customerrors.ERR_2FA_ALREADY_ENABLED, fmt.Errorf("2FA already enabled")
				}

				key, err := totp.Generate(totp.GenerateOpts{
					Issuer:      "XcodePlatform",
					AccountName: user.Email,
				})
				if err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to generate TOTP key", map[string]any{
						"method":     "SetUpTwoFactorAuth",
						"userID":     userID,
						"errorType": customerrors.ERR_2FA_SETUP_FAILED,
					}, "REPOSITORY", err)
					return "", "", customerrors.ERR_2FA_SETUP_FAILED, fmt.Errorf("failed to generate TOTP key")
				}

				otpSecret := key.Secret()
				otpURI := key.String()

				qrCode, err := qrcode.New(otpURI, qrcode.Medium)
				if err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to generate QR code", map[string]any{
						"method":     "SetUpTwoFactorAuth",
						"userID":     userID,
						"errorType": customerrors.ERR_2FA_SETUP_FAILED,
					}, "REPOSITORY", err)
					return "", "", customerrors.ERR_2FA_SETUP_FAILED, fmt.Errorf("failed to generate QR code")
				}

				user.TwoFactorSecret = otpSecret

				if err := r.db.Save(&user).Error; err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to save user", map[string]any{
						"method":     "SetUpTwoFactorAuth",
						"userID":     userID,
						"errorType": customerrors.ERR_2FA_SETUP_FAILED,
					}, "REPOSITORY", err)
					return "", "", customerrors.ERR_2FA_SETUP_FAILED, fmt.Errorf("failed to save user")
				}

				qrCodeImage := qrCode.Image(256)
				var qrCodeImageBytes bytes.Buffer
				if err := png.Encode(&qrCodeImageBytes, qrCodeImage); err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to encode QR code", map[string]any{
						"method":     "SetUpTwoFactorAuth",
						"userID":     userID,
						"errorType": customerrors.ERR_2FA_SETUP_FAILED,
					}, "REPOSITORY", err)
					return "", "", customerrors.ERR_2FA_SETUP_FAILED, fmt.Errorf("failed to encode QR code")
				}

				qrCodeImageBase64 := base64.StdEncoding.EncodeToString(qrCodeImageBytes.Bytes())

				r.logger.Log(zapcore.InfoLevel, traceID, "2FA setup completed", map[string]any{
					"method": "SetUpTwoFactorAuth",
					"userID": userID,
				}, "REPOSITORY", nil)
				return qrCodeImageBase64, otpSecret, "", nil
}

func (r *UserRepository) DisableTwoFactorAuth(userID string) (string, error) {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting DisableTwoFactorAuth", map[string]any{
					"method": "DisableTwoFactorAuth",
					"userID": userID,
				}, "REPOSITORY", nil)

				if userID == "" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID", map[string]any{
						"method":     "DisableTwoFactorAuth",
						"errorType": customerrors.ERR_PARAM_EMPTY,
					}, "REPOSITORY", nil)
					return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
				}

				var user db.User
				if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve user", map[string]any{
						"method":     "DisableTwoFactorAuth",
						"userID":     userID,
						"errorType": customerrors.ERR_USER_NOT_FOUND,
					}, "REPOSITORY", err)
					return customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("failed to retrieve user")
				}

				if !user.TwoFactorEnabled {
					r.logger.Log(zapcore.ErrorLevel, traceID, "2FA not enabled", map[string]any{
						"method":     "DisableTwoFactorAuth",
						"userID":     userID,
						"errorType": customerrors.ERR_2FA_NOT_ENABLED,
					}, "REPOSITORY", nil)
					return customerrors.ERR_2FA_NOT_ENABLED, fmt.Errorf("2FA not enabled")
				}

				if err := r.db.Model(&user).Updates(map[string]interface{}{
					"two_factor_enabled": false,
					"two_factor_secret":  "",
				}).Error; err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to disable 2FA", map[string]any{
						"method":     "DisableTwoFactorAuth",
						"userID":     userID,
						"errorType": customerrors.ERR_2FA_DISABLE_FAILED,
					}, "REPOSITORY", err)
					return customerrors.ERR_2FA_DISABLE_FAILED, fmt.Errorf("failed to disable 2FA")
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "2FA disabled successfully", map[string]any{
					"method": "DisableTwoFactorAuth",
					"userID": userID,
				}, "REPOSITORY", nil)
				return "", nil
}

func (r *UserRepository) GetTwoFactorAuthStatus(email string) (bool, string, error) {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting GetTwoFactorAuthStatus", map[string]any{
					"method": "GetTwoFactorAuthStatus",
					"email":  email,
				}, "REPOSITORY", nil)

				if email == "" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Empty email", map[string]any{
						"method":     "GetTwoFactorAuthStatus",
						"errorType": customerrors.ERR_PARAM_EMPTY,
					}, "REPOSITORY", nil)
					return false, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("email cannot be empty")
				}

				var user db.User
				if err := r.db.Where("email = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve user", map[string]any{
						"method":     "GetTwoFactorAuthStatus",
						"email":      email,
						"errorType": customerrors.ERR_2FA_STATUS_CHECK_FAILED,
					}, "REPOSITORY", err)
					return false, customerrors.ERR_2FA_STATUS_CHECK_FAILED, fmt.Errorf("failed to retrieve user")
				}

				if user.AuthType != "email" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "2FA not supported for OAuth", map[string]any{
						"method":     "GetTwoFactorAuthStatus",
						"email":      email,
						"errorType": customerrors.ERR_GOOGLELOGIN_NO2FA,
					}, "REPOSITORY", nil)
					return false, customerrors.ERR_GOOGLELOGIN_NO2FA, fmt.Errorf("two factor cannot be enabled on oauth")
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "2FA status retrieved", map[string]any{
					"method":          "GetTwoFactorAuthStatus",
					"email":           email,
					"twoFactorEnabled": user.TwoFactorEnabled,
				}, "REPOSITORY", nil)
				return user.TwoFactorEnabled, "", nil
}

func (r *UserRepository) ValidateTwoFactorAuth(userID, code string) (bool, string, error) {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting ValidateTwoFactorAuth", map[string]any{
					"method": "ValidateTwoFactorAuth",
					"userID": userID,
				}, "REPOSITORY", nil)

				if userID == "" || code == "" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID or code", map[string]any{
						"method":     "ValidateTwoFactorAuth",
						"errorType": customerrors.ERR_PARAM_EMPTY,
					}, "REPOSITORY", nil)
					return false, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("userID or code cannot be empty")
				}

				user, _, err := r.GetUserByUserID(userID)
				if err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve user", map[string]any{
						"method":     "ValidateTwoFactorAuth",
						"userID":     userID,
						"errorType": customerrors.ERR_USER_NOT_FOUND,
					}, "REPOSITORY", err)
					return false, customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("failed to retrieve user")
				}

				valid := totp.Validate(code, user.TwoFactorSecret)
				if !valid {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Invalid 2FA code", map[string]any{
						"method":     "ValidateTwoFactorAuth",
						"userID":     userID,
						"errorType": customerrors.ERR_2FA_CODE_INVALID,
					}, "REPOSITORY", nil)
					return false, customerrors.ERR_2FA_CODE_INVALID, fmt.Errorf("invalid 2FA code")
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "2FA code validated successfully", map[string]any{
					"method": "ValidateTwoFactorAuth",
					"userID": userID,
				}, "REPOSITORY", nil)
				return true, "", nil
}

func (r *UserRepository) VerifyTwoFactorAuth(userID, code string) (bool, string, error) {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting VerifyTwoFactorAuth", map[string]any{
					"method": "VerifyTwoFactorAuth",
					"userID": userID,
				}, "REPOSITORY", nil)

				if userID == "" || code == "" {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Empty user ID or code", map[string]any{
						"method":     "VerifyTwoFactorAuth",
						"errorType": customerrors.ERR_PARAM_EMPTY,
					}, "REPOSITORY", nil)
					return false, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("userID or code cannot be empty")
				}

				user, _, err := r.GetUserByUserID(userID)
				if err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to retrieve user", map[string]any{
						"method":     "VerifyTwoFactorAuth",
						"userID":     userID,
						"errorType": customerrors.ERR_USER_NOT_FOUND,
					}, "REPOSITORY", err)
					return false, customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("failed to retrieve user")
				}

				valid := totp.Validate(code, user.TwoFactorSecret)
				if !valid {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Invalid 2FA code", map[string]any{
						"method":     "VerifyTwoFactorAuth",
						"userID":     userID,
						"errorType": customerrors.ERR_2FA_CODE_INVALID,
					}, "REPOSITORY", nil)
					return false, customerrors.ERR_2FA_CODE_INVALID, fmt.Errorf("invalid 2FA code")
				}

				if err := r.db.Model(&user).Updates(map[string]interface{}{
					"two_factor_enabled": true,
				}).Error; err != nil {
					r.logger.Log(zapcore.ErrorLevel, traceID, "Failed to enable 2FA", map[string]any{
						"method":     "VerifyTwoFactorAuth",
						"userID":     userID,
						"errorType": customerrors.ERR_2FA_SETUP_FAILED,
					}, "REPOSITORY", err)
					return false, customerrors.ERR_2FA_SETUP_FAILED, fmt.Errorf("failed to enable 2FA")
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "2FA verified and enabled", map[string]any{
					"method": "VerifyTwoFactorAuth",
					"userID": userID,
				}, "REPOSITORY", nil)
				return true, "", nil
}

func (r *UserRepository) UserAvailable(username string) bool {
				traceID := uuid.New().String()
				r.logger.Log(zapcore.InfoLevel, traceID, "Starting UserAvailable", map[string]any{
					"method":   "UserAvailable",
					"username": username,
				}, "REPOSITORY", nil)

				var user db.User
				err := r.db.Where("user_name = ? AND deleted_at IS NULL", strings.ToLower(username)).First(&user).Error

				if err == gorm.ErrRecordNotFound {
					r.logger.Log(zapcore.InfoLevel, traceID, "Username available", map[string]any{
						"method":   "UserAvailable",
						"username": username,
					}, "REPOSITORY", nil)
					return true
				}

				r.logger.Log(zapcore.InfoLevel, traceID, "Username taken", map[string]any{
					"method":   "UserAvailable",
					"username": username,
				}, "REPOSITORY", nil)
				return false
}