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

	"github.com/google/uuid"
	AuthUserAdminService "github.com/lijuuu/GlobalProtoXcode/AuthUserAdminService"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserRepository struct {
	db     *gorm.DB
	config *configs.Config
}

func NewUserRepository(db *gorm.DB, config *configs.Config) *UserRepository {
	if db == nil || config == nil {
		log.Fatal("database or config cannot be nil")
	}
	return &UserRepository{db: db, config: config}
}

func (r *UserRepository) CreateUser(req *AuthUserAdminService.RegisterUserRequest) (string, string, error) {
	if req == nil {
		return "", customerrors.ERR_PARAM_EMPTY, fmt.Errorf("registration request cannot be nil")
	}
	if req.Password != req.ConfirmPassword {
		return "", customerrors.ERR_REG_PASSWORD_MISMATCH, fmt.Errorf("the passwords you entered do not match")
	}
	if !IsValidEmail(req.Email) {
		return "", customerrors.ERR_REG_INVALID_EMAIL, fmt.Errorf("please enter a valid email address")
	}
	if !IsValidPassword(req.Password) {
		return "", customerrors.ERR_REG_INVALID_PASSWORD, fmt.Errorf("password must be at least 8 characters long and include at least one uppercase letter and one number")
	}

	salt := uuid.New().String()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password+salt), bcrypt.DefaultCost)
	if err != nil {
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
		return "", customerrors.ERR_REG_CREATION_FAILED, fmt.Errorf("failed to create user")
	}

	return user.ID, "", nil
}

func (r *UserRepository) CreateGoogleUser(req *db.User) (string, string, error) {
	if err := r.db.Create(&req).Error; err != nil {
		return "", customerrors.ERR_REG_CREATION_FAILED, fmt.Errorf("failed to create user")
	}
	return "", "", nil
}

func (r *UserRepository) CheckUserPassword(userID, password string) (bool, string, error) {
	if userID == "" {
		return false, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	var user db.User
	if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("user not found")
		}
		return false, customerrors.ERR_CRED_CHECK_FAILED, fmt.Errorf("unable to verify credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(password+user.Salt)); err != nil {
		fmt.Println("error ", err)
		return false, customerrors.ERR_CRED_WRONG, fmt.Errorf("incorrect password")
	}
	return true, "", nil
}

func (r *UserRepository) CheckAdminPassword(password string) (bool, string, error) {
	if password == "" {
		return false, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("password cannot be empty")
	}
	if r.config.AdminPassword == "" {
		return false, customerrors.ERR_ADMIN_NOT_CONFIGURED, fmt.Errorf("admin password not configured")
	}
	if password != r.config.AdminPassword {
		return false, customerrors.ERR_CRED_WRONG, fmt.Errorf("invalid admin credentials")
	}
	return true, "", nil
}

func (r *UserRepository) GetUserByEmail(email string) (db.User, string, error) {
	if email == "" {
		return db.User{}, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("email cannot be empty")
	}
	var user db.User
	if err := r.db.Where("email = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return db.User{}, "", nil
		}
		return db.User{}, customerrors.ERR_CRED_CHECK_FAILED, fmt.Errorf("unable to retrieve user")
	}
	return user, "", nil
}

func (r *UserRepository) GetUserByUserID(userID string) (db.User, string, error) {
	if userID == "" {
		return db.User{}, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	var user db.User
	if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return db.User{}, "", nil
		}
		return db.User{}, customerrors.ERR_CRED_CHECK_FAILED, fmt.Errorf("unable to retrieve user")
	}
	return user, "", nil
}

func (r *UserRepository) UpdateUserOnTwoFactorAuth(user db.User) (string, error) {
	if err := r.db.Model(&user).Where("id = ? AND deleted_at IS NULL", user.ID).Updates(map[string]interface{}{
		"is_verified": false,
	}).Error; err != nil {
		return customerrors.ERR_PROFILE_UPDATE_FAILED, fmt.Errorf("unable to update profile")
	}
	return "", nil
}

func (r *UserRepository) UpdateProfile(req *AuthUserAdminService.UpdateProfileRequest) (string, error) {
	if req == nil {
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("update profile request cannot be nil")
	}
	if req.UserID == "" {
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
	// fmt.Println("before udpate ",user)
	if err := r.db.Model(&user).Where("id = ? AND deleted_at IS NULL", req.UserID).Updates(user).Error; err != nil {
		return customerrors.ERR_PROFILE_UPDATE_FAILED, fmt.Errorf("unable to update profile")
	}
	return "", nil
}

func (r *UserRepository) UpdateProfileImage(req *AuthUserAdminService.UpdateProfileImageRequest) (string, error) {
	if req == nil {
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("update profile image request cannot be nil")
	}
	if req.UserID == "" {
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", req.UserID).
		Updates(map[string]interface{}{
			"avatar_data": req.AvatarURL,
			"updated_at":  time.Now().Unix(),
		}).Error; err != nil {
		return customerrors.ERR_PROFILE_IMAGE_UPDATE_FAILED, fmt.Errorf("unable to update profile picture")
	}
	return "", nil
}

func (r *UserRepository) GetUserProfile(userID string) (*AuthUserAdminService.GetUserProfileResponse, string, error) {
	if userID == "" {
		return nil, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	var user db.User
	if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, customerrors.ERR_PROFILE_NOT_FOUND, fmt.Errorf("user profile not found")
		}
		return nil, customerrors.ERR_CRED_CHECK_FAILED, fmt.Errorf("unable to retrieve profile")
	}

	// fmt.Println(user)

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
	if userID == "" {
		return nil, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}

	var user db.User
	if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, customerrors.ERR_BAN_STATUS_NOT_FOUND, fmt.Errorf("user not found")
		}
		return nil, customerrors.ERR_BAN_STATUS_CHECK_FAILED, fmt.Errorf("unable to check ban status")
	}

	if !user.IsBanned {
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
				return nil, customerrors.ERR_BAN_UPDATE_FAILED, fmt.Errorf("unable to update ban status")
			}
			return &AuthUserAdminService.CheckBanStatusResponse{
				IsBanned: false,
				Message:  "User is not banned",
			}, "", nil
		}
		return nil, customerrors.ERR_BAN_STATUS_CHECK_FAILED, fmt.Errorf("unable to retrieve ban info")
	}

	if banHistory.BanExpiry != 0 && banHistory.BanExpiry < time.Now().Unix() {
		if err := r.db.Model(&user).Updates(map[string]interface{}{
			"is_banned": false,
			"ban_id":    nil,
		}).Error; err != nil {
			return nil, customerrors.ERR_BAN_UPDATE_FAILED, fmt.Errorf("unable to update ban status")
		}
		return &AuthUserAdminService.CheckBanStatusResponse{
			IsBanned: false,
			Message:  "Previous ban has expired",
		}, "", nil
	}

	return &AuthUserAdminService.CheckBanStatusResponse{
		IsBanned:      true,
		Reason:        banHistory.BanReason,
		BanExpiration: banHistory.BanExpiry,
		Message:       "User is currently banned",
	}, "", nil
}

func (r *UserRepository) FollowUser(followerID, followeeID string) (string, error) {
	if followerID == "" || followeeID == "" {
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("follower ID or followee ID cannot be empty")
	}
	if err := r.db.Transaction(func(tx *gorm.DB) error {
		return tx.Create(&db.Following{
			FollowerID: followerID,
			FolloweeID: followeeID,
		}).Error
	}); err != nil {
		return customerrors.ERR_FOLLOW_ACTION_FAILED, fmt.Errorf("failed to follow user")
	}
	return "", nil
}

func (r *UserRepository) UnfollowUser(followerID, followeeID string) (string, error) {
	if followerID == "" || followeeID == "" {
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("follower ID or followee ID cannot be empty")
	}
	if err := r.db.Transaction(func(tx *gorm.DB) error {
		return tx.Where("follower_id = ? AND followee_id = ?", followerID, followeeID).Delete(&db.Following{}).Error
	}); err != nil {
		return customerrors.ERR_UNFOLLOW_ACTION_FAILED, fmt.Errorf("failed to unfollow user")
	}
	return "", nil
}

func (r *UserRepository) GetFollowing(userID string) ([]*AuthUserAdminService.UserProfile, string, error) {
	if userID == "" {
		return nil, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	var following []db.Following
	if err := r.db.Where("follower_id = ?", userID).Find(&following).Error; err != nil {
		return nil, customerrors.ERR_FOLLOWING_LIST_FAILED, fmt.Errorf("failed to retrieve following list")
	}

	var followeeIDs []string
	for _, f := range following {
		followeeIDs = append(followeeIDs, f.FolloweeID)
	}

	var users []db.User
	if len(followeeIDs) > 0 {
		if err := r.db.Where("id IN (?) AND deleted_at IS NULL", followeeIDs).Find(&users).Error; err != nil {
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
	return profiles, "", nil
}

func (r *UserRepository) GetFollowers(userID string) ([]*AuthUserAdminService.UserProfile, string, error) {
	if userID == "" {
		return nil, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	var followers []db.Follower
	if err := r.db.Where("followee_id = ?", userID).Find(&followers).Error; err != nil {
		return nil, customerrors.ERR_FOLLOWERS_LIST_FAILED, fmt.Errorf("failed to retrieve followers")
	}

	var followerIDs []string
	for _, f := range followers {
		followerIDs = append(followerIDs, f.FollowerID)
	}

	var users []db.User
	if len(followerIDs) > 0 {
		if err := r.db.Where("id IN (?) AND deleted_at IS NULL", followerIDs).Find(&users).Error; err != nil {
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
	return profiles, "", nil
}

func (r *UserRepository) CreateUserAdmin(req *AuthUserAdminService.CreateUserAdminRequest) (string, string, error) {
	if req == nil {
		return "", customerrors.ERR_PARAM_EMPTY, fmt.Errorf("create admin request cannot be nil")
	}
	if req.Password != req.ConfirmPassword {
		return "", customerrors.ERR_ADMIN_CREATE_PASSWORD_MISMATCH, fmt.Errorf("passwords do not match")
	}
	if !IsValidEmail(req.Email) {
		return "", customerrors.ERR_ADMIN_CREATE_INVALID_EMAIL, fmt.Errorf("invalid email format")
	}
	if !IsValidPassword(req.Password) {
		return "", customerrors.ERR_ADMIN_CREATE_INVALID_PASSWORD, fmt.Errorf("invalid password format")
	}

	socials := &AuthUserAdminService.Socials{}
	if req.Socials != nil {
		socials = req.Socials
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
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
		return "", customerrors.ERR_ADMIN_CREATE_FAILED, fmt.Errorf("failed to create admin user")
	}

	return user.ID, "", nil
}

func (r *UserRepository) UpdateUserAdmin(req *AuthUserAdminService.UpdateUserAdminRequest) (string, error) {
	if req == nil {
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("update admin request cannot be nil")
	}
	if req.UserID == "" {
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	if req.Password != "" && !IsValidPassword(req.Password) {
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
			return customerrors.ERR_PASSWORD_HASH_FAILED, fmt.Errorf("failed to hash password")
		}
		user.HashedPassword = string(hashedPassword)
	}

	if err := r.db.Model(&user).Where("id = ? AND deleted_at IS NULL", req.UserID).Updates(user).Error; err != nil {
		return customerrors.ERR_ADMIN_UPDATE_FAILED, fmt.Errorf("failed to update admin user")
	}
	return "", nil
}

func (r *UserRepository) BanUser(userID, banReason string, banExpiry int64, banType string) (string, error) {
	if userID == "" {
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	uuid := uuid.New().String()
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Updates(map[string]interface{}{
			"is_banned": true,
			"ban_id":    uuid,
		}).Error; err != nil {
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
		return customerrors.ERR_BAN_USER_FAILED, fmt.Errorf("failed to record ban history")
	}

	return "", nil
}

func (r *UserRepository) UnbanUser(userID string) (string, error) {
	if userID == "" {
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Updates(map[string]interface{}{
			"is_banned": false,
		}).Error; err != nil {
		return customerrors.ERR_UNBAN_USER_FAILED, fmt.Errorf("unable to unban user")
	}
	return "", nil
}

func (r *UserRepository) VerifyAdminUser(userID string) (string, error) {
	if userID == "" {
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Updates(map[string]interface{}{
			"is_verified": true,
			"updated_at":  time.Now().Unix(),
		}).Error; err != nil {
		return customerrors.ERR_ADMIN_VERIFY_FAILED, fmt.Errorf("failed to verify user")
	}
	return "", nil
}

func (r *UserRepository) UnverifyUser(userID string) (string, error) {
	if userID == "" {
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Updates(map[string]interface{}{
			"is_verified": false,
			"updated_at":  time.Now().Unix(),
		}).Error; err != nil {
		return customerrors.ERR_ADMIN_UNVERIFY_FAILED, fmt.Errorf("failed to unverify user")
	}
	return "", nil
}

func (r *UserRepository) SoftDeleteUserAdmin(userID string) (string, error) {
	if userID == "" {
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Update("deleted_at", time.Now()).Error; err != nil {
		return customerrors.ERR_ADMIN_DELETE_FAILED, fmt.Errorf("failed to delete user")
	}
	return "", nil
}

func (r *UserRepository) GetAllUsers(req *AuthUserAdminService.GetAllUsersRequest) ([]*AuthUserAdminService.UserProfile, int32, string, error) {
	if req == nil {
		return nil, 0, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("get all users request cannot be nil")
	}
	var users []db.User
	query := r.db.Where("deleted_at IS NULL")
	if req.RoleFilter != "" {
		query = query.Where("role = ?", req.RoleFilter)
	}
	if req.StatusFilter != "" {
		query = query.Where("status = ?", req.StatusFilter)
	}

	var totalCount int64
	if err := query.Model(&db.User{}).Count(&totalCount).Error; err != nil {
		return nil, 0, customerrors.ERR_USERS_LIST_FAILED, fmt.Errorf("failed to count users")
	}

	if err := query.Find(&users).Error; err != nil {
		return nil, 0, customerrors.ERR_USERS_LIST_FAILED, fmt.Errorf("failed to retrieve users")
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
	return profiles, int32(totalCount), "", nil
}

func (r *UserRepository) ChangePassword(email, hashedPassword string) (string, error) {
	if email == "" || hashedPassword == "" {
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("email or password cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("email = ? AND deleted_at IS NULL", email).
		Updates(map[string]interface{}{
			"hashed_password": hashedPassword,
			"updated_at":      time.Now().Unix(),
		}).Error; err != nil {
		return customerrors.ERR_PW_CHANGE_MISMATCH, fmt.Errorf("unable to update password")
	}
	return "", nil
}

func (r *UserRepository) IsUserVerified(userID string) (bool, string, error) {
	if userID == "" {
		return false, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	var user db.User
	if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("user not found")
		}
		return false, customerrors.ERR_CRED_CHECK_FAILED, fmt.Errorf("failed to check verification status")
	}
	return user.IsVerified, "", nil
}

func (r *UserRepository) IsAdmin(userID string) (bool, string, error) {
	if userID == "" {
		return false, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	var user db.User
	if err := r.db.Where("id = ? AND role = ? AND deleted_at IS NULL", userID, "ADMIN").First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, "", nil
		}
		return false, customerrors.ERR_CRED_CHECK_FAILED, fmt.Errorf("failed to check admin status")
	}
	return true, "", nil
}

func (r *UserRepository) GetUserFor2FA(userID string) (*db.User, string, error) {
	if userID == "" {
		return nil, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	var user db.User
	if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("user not found")
		}
		return nil, customerrors.ERR_CRED_CHECK_FAILED, fmt.Errorf("failed to retrieve user for 2FA")
	}
	return &user, "", nil
}

func (r *UserRepository) CreateVerification(userID, email, token string) (string, error) {
	if userID == "" || email == "" || token == "" {
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
		return customerrors.ERR_TOKEN_CREATION_FAILED, fmt.Errorf("failed to create verification record")
	}
	return "", nil
}

func (r *UserRepository) VerifyUserToken(email, token string) (bool, string, error) {
	if email == "" || token == "" {
		return false, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("email or token cannot be empty")
	}

	var user db.User
	if err := r.db.Where("email = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("account not found")
		}
		return false, customerrors.ERR_VERIFY_CHECK_FAILED, fmt.Errorf("unable to verify account")
	}

	if user.IsVerified {
		return false, customerrors.ERR_ALREADY_VERIFIED, fmt.Errorf("user already verified")
	}

	var verification db.Verification
	if err := r.db.Where("email = ? AND token = ? AND expiry_at > ? AND used = ?", email, token, time.Now().Unix(), false).First(&verification).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, customerrors.ERR_VERIFY_TOKEN_INVALID, fmt.Errorf("invalid or expired verification code")
		}
		return false, customerrors.ERR_VERIFY_CHECK_FAILED, fmt.Errorf("unable to verify account")
	}

	if err := r.db.Model(&verification).Update("used", true).Error; err != nil {
		return false, customerrors.ERR_TOKEN_VERIFICATION_FAILED, fmt.Errorf("failed to mark token as used")
	}
	if err := r.db.Model(&db.User{}).Where("email = ?", email).Update("is_verified", true).Error; err != nil {
		return false, customerrors.ERR_PROFILE_UPDATE_FAILED, fmt.Errorf("failed to update verification status")
	}
	return true, "", nil
}

func (r *UserRepository) ResendEmailVerification(email string) (string, int64, string, error) {
	if email == "" {
		return "", 0, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("email cannot be empty")
	}
	var user db.User
	if err := r.db.Where("email = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", 0, customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("account not found")
		}
		return "", 0, customerrors.ERR_EMAIL_RESEND_FAILED, fmt.Errorf("unable to send verification code")
	}

	if user.IsVerified {
		return "", 0, customerrors.ERR_ALREADY_VERIFIED, fmt.Errorf("user already verified")
	}

	var existingVerification db.Verification
	if err := r.db.Where("user_id = ? AND expiry_at > ? AND used = ?", user.ID, time.Now().Unix(), false).First(&existingVerification).Error; err == nil {
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
		return "", 0, customerrors.ERR_TOKEN_CREATION_FAILED, fmt.Errorf("failed to create verification")
	}

	if err := r.SendVerificationEmail(user.Email, otp); err != nil {
		log.Printf("Failed to send verification email: %v", err)
	}

	return otp, verification.ExpiryAt, "", nil
}

func (r *UserRepository) CreateForgotPasswordToken(email, token string) (string, string, error) {
	if email == "" || token == "" {
		return "", customerrors.ERR_PARAM_EMPTY, fmt.Errorf("email or token cannot be empty")
	}
	var user db.User
	if err := r.db.Where("email = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("user not found")
		}
		return "", customerrors.ERR_PW_FORGOT_INIT_FAILED, fmt.Errorf("failed to retrieve user")
	}

	if err := r.db.Where("user_id = ? AND expiry_at > ? AND used = ?", user.ID, time.Now().Unix(), false).Delete(&db.ForgotPassword{}).Error; err != nil {
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
		return "", customerrors.ERR_TOKEN_CREATION_FAILED, fmt.Errorf("failed to create reset token")
	}

	if r.config.APPURL != "" {
		resetLink := fmt.Sprintf("http://localhost:5173/reset-password?token=%s&email=%s", token, user.Email)
		if err := r.SendForgotPasswordEmail(user.Email, resetLink); err != nil {
			log.Printf("Failed to send password reset email: %v", err)
		}
	}

	return user.ID, "", nil
}

func (r *UserRepository) VerifyForgotPasswordToken(userID, token string) (bool, string, error) {
	if userID == "" || token == "" {
		return false, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID or token cannot be empty")
	}
	var forgot db.ForgotPassword
	if err := r.db.Where("user_id = ? AND token = ? AND expiry_at > ? AND used = ?", userID, token, time.Now().Unix(), false).First(&forgot).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, "", nil
		}
		return false, customerrors.ERR_TOKEN_VERIFICATION_FAILED, fmt.Errorf("failed to verify reset token")
	}

	if err := r.db.Model(&forgot).Update("used", true).Error; err != nil {
		return false, customerrors.ERR_TOKEN_VERIFICATION_FAILED, fmt.Errorf("failed to mark reset token as used")
	}
	return true, "", nil
}

func (r *UserRepository) FinishForgotPassword(email, token, newPassword string) (string, error) {
	if email == "" || token == "" || newPassword == "" {
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("email, token, or new password cannot be empty")
	}

	var user db.User
	if err := r.db.Where("email = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("no account found")
		}
		return customerrors.ERR_PW_RESET_MISMATCH, fmt.Errorf("unable to process password reset")
	}

	var forgotPassword db.ForgotPassword
	if err := r.db.Where("user_id = ? AND token = ? AND expiry_at > ? AND used = ?", user.ID, token, time.Now().Unix(), false).First(&forgotPassword).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return customerrors.ERR_VERIFY_TOKEN_INVALID, fmt.Errorf("invalid or expired reset token")
		}
		return customerrors.ERR_TOKEN_VERIFICATION_FAILED, fmt.Errorf("unable to verify reset token")
	}

	salt := uuid.New().String()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword+salt), bcrypt.DefaultCost)
	if err != nil {
		return customerrors.ERR_PASSWORD_HASH_FAILED, fmt.Errorf("unable to process new password")
	}

	tx := r.db.Begin()
	if err := tx.Error; err != nil {
		return customerrors.ERR_PW_RESET_MISMATCH, fmt.Errorf("unable to process password reset")
	}

	if err := tx.Model(&user).Updates(map[string]interface{}{
		"hashed_password": string(hashedPassword),
		"salt":            salt,
		"updated_at":      time.Now().Unix(),
	}).Error; err != nil {
		tx.Rollback()
		return customerrors.ERR_PW_RESET_MISMATCH, fmt.Errorf("unable to update password")
	}

	if err := tx.Model(&forgotPassword).Updates(map[string]interface{}{
		"used": true,
	}).Error; err != nil {
		tx.Rollback()
		return customerrors.ERR_PW_RESET_MISMATCH, fmt.Errorf("unable to complete password reset")
	}

	if err := tx.Commit().Error; err != nil {
		return customerrors.ERR_PW_RESET_MISMATCH, fmt.Errorf("unable to complete password reset")
	}

	return "", nil
}

func (r *UserRepository) ChangeAuthenticatedPassword(userID, oldPassword, newPassword string) (string, error) {
	if userID == "" || oldPassword == "" || newPassword == "" {
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID, old password, or new password cannot be empty")
	}
	user, _, err := r.GetUserByUserID(userID)
	if err != nil {
		return customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("failed to retrieve user")
	}

	if user.HashedPassword == "" {
		return customerrors.ERR_NO_EXISTING_PASSWORD, fmt.Errorf("no existing password found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(oldPassword+user.Salt)); err != nil {
		return customerrors.ERR_CRED_WRONG, fmt.Errorf("invalid old password")
	}

	if !IsValidPassword(newPassword) {
		return customerrors.ERR_PW_CHANGE_INVALID_PASSWORD, fmt.Errorf("invalid new password format")
	}

	hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword+user.Salt), bcrypt.DefaultCost)
	if err != nil {
		return customerrors.ERR_PASSWORD_HASH_FAILED, fmt.Errorf("failed to hash password")
	}

	return r.ChangePassword(user.Email, string(hashedNewPassword))
}

// Helper functions
func (r *UserRepository) SendVerificationEmail(to, otp string) error {
	if to == "" || otp == "" {
		return fmt.Errorf("email or OTP cannot be empty")
	}
	return utils.SendOTPEmail(to, "user", otp, 30)
}

func (r *UserRepository) SendForgotPasswordEmail(to, resetLink string) error {
	if to == "" || resetLink == "" {
		return fmt.Errorf("email or reset link cannot be empty")
	}
	return utils.SendForgotPasswordEmail(to, resetLink)
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
	if userID == "" {
		return nil, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}
	var bans []db.BanHistory
	if err := r.db.Where("user_id = ?", userID).Find(&bans).Error; err != nil {
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
	return history, "", nil
}

func (r *UserRepository) SearchUsers(query, pageToken string, limit int32) ([]*AuthUserAdminService.UserProfile, string, string, error) {
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

	if err := queryBuilder.Limit(int(limit) + 1).Find(&users).Error; err != nil {
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

	return profiles, nextPageToken, "", nil
}

func (r *UserRepository) LogoutUser(userID string) (string, error) {
	if userID == "" {
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}

	var user db.User
	if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		return customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("failed to retrieve user")
	}

	if !user.TwoFactorEnabled {
		return "", nil
	}

	if err := r.db.Model(&user).Update("is_verified", false).Error; err != nil {
		return customerrors.ERR_PROFILE_UPDATE_FAILED, fmt.Errorf("failed to toggle verification")
	}

	return "", nil
}

func (r *UserRepository) SetUpTwoFactorAuth(userID string) (string, string, string, error) {
	if userID == "" {
		return "", "", customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}

	var user db.User
	if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		return "", "", customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("failed to retrieve user")
	}

	if user.TwoFactorEnabled {
		return "", "", customerrors.ERR_2FA_ALREADY_ENABLED, fmt.Errorf("2FA already enabled")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "XcodePlatform",
		AccountName: user.Email,
	})
	if err != nil {
		return "", "", customerrors.ERR_2FA_SETUP_FAILED, fmt.Errorf("failed to generate TOTP key")
	}

	otpSecret := key.Secret()
	otpURI := key.String()

	qrCode, err := qrcode.New(otpURI, qrcode.Medium)
	if err != nil {
		return "", "", customerrors.ERR_2FA_SETUP_FAILED, fmt.Errorf("failed to generate QR code")
	}

	user.TwoFactorSecret = otpSecret
	// user.TwoFactorEnabled = true

	if err := r.db.Save(&user).Error; err != nil {
		return "", "", customerrors.ERR_2FA_SETUP_FAILED, fmt.Errorf("failed to save user")
	}

	qrCodeImage := qrCode.Image(256)
	var qrCodeImageBytes bytes.Buffer
	if err := png.Encode(&qrCodeImageBytes, qrCodeImage); err != nil {
		return "", "", customerrors.ERR_2FA_SETUP_FAILED, fmt.Errorf("failed to encode QR code")
	}

	qrCodeImageBase64 := base64.StdEncoding.EncodeToString(qrCodeImageBytes.Bytes())
	return qrCodeImageBase64, otpSecret, "", nil
}

func (r *UserRepository) DisableTwoFactorAuth(userID string) (string, error) {
	if userID == "" {
		return customerrors.ERR_PARAM_EMPTY, fmt.Errorf("user ID cannot be empty")
	}

	var user db.User
	if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		return customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("failed to retrieve user")
	}

	if !user.TwoFactorEnabled {
		return customerrors.ERR_2FA_NOT_ENABLED, fmt.Errorf("2FA not enabled")
	}

	if err := r.db.Model(&user).Updates(map[string]interface{}{
		"two_factor_enabled": false,
		"two_factor_secret":  "",
	}).Error; err != nil {
		return customerrors.ERR_2FA_DISABLE_FAILED, fmt.Errorf("failed to disable 2FA")
	}

	return "", nil
}

func (r *UserRepository) GetTwoFactorAuthStatus(email string) (bool, string, error) {
	if email == "" {
		return false, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("email cannot be empty")
	}

	var user db.User
	if err := r.db.Where("email = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
		return false, customerrors.ERR_2FA_STATUS_CHECK_FAILED, fmt.Errorf("failed to retrieve user")
	}

	if user.AuthType != "email" {
		return false, customerrors.ERR_GOOGLELOGIN_NO2FA, fmt.Errorf("two factor cannot be enabled on oauth")
	}

	return user.TwoFactorEnabled, "", nil
}

func (r *UserRepository) ValidateTwoFactorAuth(userID, code string) (bool, string, error) {
	if userID == "" || code == "" {
		return false, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("userID or code cannot be empty")
	}

	user, _, err := r.GetUserByUserID(userID)
	if err != nil {
		return false, customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("failed to retrieve user")
	}

	valid := totp.Validate(code, user.TwoFactorSecret)
	if !valid {
		return false, customerrors.ERR_2FA_CODE_INVALID, fmt.Errorf("invalid 2FA code")
	}

	return true, "", nil
}

func (r *UserRepository) VerifyTwoFactorAuth(userID, code string) (bool, string, error) {
	if userID == "" || code == "" {
		return false, customerrors.ERR_PARAM_EMPTY, fmt.Errorf("userID or code cannot be empty")
	}

	user, _, err := r.GetUserByUserID(userID)
	if err != nil {
		return false, customerrors.ERR_USER_NOT_FOUND, fmt.Errorf("failed to retrieve user")
	}

	valid := totp.Validate(code, user.TwoFactorSecret)
	if !valid {
		return false, customerrors.ERR_2FA_CODE_INVALID, fmt.Errorf("invalid 2FA code")
	}

	//toggle TwoFactorEnabled to true after successful validation
	if err := r.db.Model(&user).Updates(map[string]interface{}{
		"two_factor_enabled": true,
	}).Error; err != nil {
		return false, customerrors.ERR_2FA_SETUP_FAILED, fmt.Errorf("failed to enable 2FA")
	}

	return true, "", nil
}

func (r *UserRepository) UserAvailable(username string) bool {
	var user db.User
	err := r.db.Where("user_name = ? AND deleted_at IS NULL", strings.ToLower(username)).First(&user).Error

	fmt.Println("err in usernameavailabel check", err)

	//if record is not found, username is available (return false)
	//if record is found, username is taken (return true)
	return err == gorm.ErrRecordNotFound
}
