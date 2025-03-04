package repository

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"xcode/db"
	"xcode/utils"

	configs "xcode/configs"

	"github.com/google/uuid"
	AuthUserAdminService "github.com/lijuuu/GlobalProtoXcode/AuthUserAdminService"
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

func (r *UserRepository) CreateUser(req *AuthUserAdminService.RegisterUserRequest) (string, error) {
	if req == nil {
		return "", errors.New("registration request cannot be nil")
	}
	if req.Password != req.ConfirmPassword {
		return "", errors.New("The passwords you entered do not match. Please try again.")
	}
	if !IsValidEmail(req.Email) {
		return "", errors.New("Please enter a valid email address.")
	}
	if !IsValidPassword(req.Password) {
		return "", errors.New("Password must be at least 8 characters long and include at least one uppercase letter and one number.")
	}

	salt := uuid.New().String()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password+salt), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %v", err)
	}

	user := db.User{
		ID:             uuid.New().String(),
		UserName:       strings.Split(req.Email, "@")[0],
		CreatedAt:      time.Now().Unix(),
		FirstName:      req.FirstName,
		LastName:       req.LastName,
		Email:          req.Email,
		Salt:           salt,
		HashedPassword: string(hashedPassword),
	}

	if err := r.db.Create(&user).Error; err != nil {
		return "", fmt.Errorf("failed to create user: %v", err)
	}

	otp := GenerateOTP(6)
	verification := db.Verification{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Email:     user.Email,
		Token:     otp,
		CreatedAt: time.Now().Unix(),
		ExpiryAt:  time.Now().Add(30 * time.Minute).Unix(),
		Used:      false,
	}
	if err := r.db.Create(&verification).Error; err != nil {
		return "", fmt.Errorf("failed to create verification record: %v", err)
	}

	go r.SendVerificationEmail(user.Email, otp)

	return user.ID, nil
}

func (r *UserRepository) CheckUserPassword(userID, password string) (bool, error) {
	if userID == "" {
		return false, errors.New("user ID cannot be empty")
	}
	var user db.User
	if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, errors.New("user not found")
		}
		return false, errors.New("Unable to verify your credentials. Please try again.")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(password+user.Salt)); err != nil {
		return false, errors.New("Incorrect password. Please try again.")
	}
	return true, nil
}

func (r *UserRepository) CheckAdminPassword(password string) (bool, error) {
	if password == "" {
		return false, errors.New("password cannot be empty")
	}
	if r.config.AdminPassword == "" {
		return false, errors.New("admin password not configured")
	}
	if password != r.config.AdminPassword {
		return false, errors.New("Invalid admin credentials. Please check your password and try again.")
	}
	return true, nil
}

func (r *UserRepository) GetUserByEmail(email string) (db.User, error) {
	if email == "" {
		return db.User{}, errors.New("email cannot be empty")
	}
	var user db.User
	if err := r.db.Where("email = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return db.User{}, nil
		}
		return db.User{}, errors.New("Unable to retrieve user information. Please try again.")
	}
	return user, nil
}

func (r *UserRepository) UpdateProfile(req *AuthUserAdminService.UpdateProfileRequest) error {
	if req == nil {
		return errors.New("update profile request cannot be nil")
	}
	if req.UserID == "" {
		return errors.New("user ID cannot be empty")
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
		PrimaryLanguageID: req.PrimaryLanguageID,
		MuteNotifications: req.MuteNotifications,
		Github:            socials.Github,
		Twitter:           socials.Twitter,
		Linkedin:          socials.Linkedin,
		UpdatedAt:         time.Now().Unix(),
	}
	if err := r.db.Model(&user).Where("id = ? AND deleted_at IS NULL", req.UserID).Updates(user).Error; err != nil {
		return errors.New("Unable to update your profile. Please try again later.")
	}
	return nil
}

func (r *UserRepository) UpdateProfileImage(req *AuthUserAdminService.UpdateProfileImageRequest) error {
	if req == nil {
		return errors.New("update profile image request cannot be nil")
	}
	if req.UserID == "" {
		return errors.New("user ID cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", req.UserID).
		Updates(map[string]interface{}{
			"avatar_data": req.AvatarURL,
			"updated_at":  time.Now().Unix(),
		}).Error; err != nil {
		return errors.New("Unable to update your profile picture. Please try again.")
	}
	return nil
}

func (r *UserRepository) GetUserProfile(userID string) (*AuthUserAdminService.GetUserProfileResponse, error) {
	if userID == "" {
		return nil, errors.New("user ID cannot be empty")
	}
	var user db.User
	if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.New("User profile not found.")
		}
		return nil, errors.New("Unable to retrieve user profile. Please try again later.")
	}

	return &AuthUserAdminService.GetUserProfileResponse{
		UserProfile: &AuthUserAdminService.UserProfile{
			UserID:            user.ID,
			UserName:          user.UserName,
			FirstName:         user.FirstName,
			LastName:          user.LastName,
			AvatarURL:         user.AvatarData,
			Email:             user.Email,
			Role:              user.Role,
			Country:           user.Country,
			IsBanned:          user.IsBanned,
			IsVerified:        user.IsVerified,
			PrimaryLanguageID: user.PrimaryLanguageID,
			MuteNotifications: user.MuteNotifications,
			Socials: &AuthUserAdminService.Socials{
				Github:   user.Github,
				Twitter:  user.Twitter,
				Linkedin: user.Linkedin,
			},
			CreatedAt:         user.CreatedAt,
		},
	}, nil
}

func (r *UserRepository) CheckBanStatus(userID string) (*AuthUserAdminService.CheckBanStatusResponse, error) {
	if userID == "" {
		return nil, errors.New("user ID cannot be empty")
	}
	var user db.User
	if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to check ban status: %v", err)
	}

	resp := &AuthUserAdminService.CheckBanStatusResponse{
		IsBanned: user.IsBanned,
		Reason:   user.BanReason,
		Message:  "Ban status checked",
	}
	if user.BanExpiration != 0 {
		resp.BanExpiration = user.BanExpiration
	}
	return resp, nil
}

func (r *UserRepository) FollowUser(followerID, followeeID string) error {
	if followerID == "" || followeeID == "" {
		return errors.New("follower ID or followee ID cannot be empty")
	}
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&db.Following{
			FollowerID: followerID,
			FolloweeID: followeeID,
		}).Error; err != nil {
			return fmt.Errorf("failed to create following relationship: %v", err)
		}
		return nil
	})
}

func (r *UserRepository) UnfollowUser(followerID, followeeID string) error {
	if followerID == "" || followeeID == "" {
		return errors.New("follower ID or followee ID cannot be empty")
	}
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("follower_id = ? AND followee_id = ?", followerID, followeeID).Delete(&db.Following{}).Error; err != nil {
			return fmt.Errorf("failed to delete following relationship: %v", err)
		}
		return nil
	})
}

func (r *UserRepository) GetFollowing(userID string) ([]*AuthUserAdminService.UserProfile, error) {
	if userID == "" {
		return nil, errors.New("user ID cannot be empty")
	}
	var following []db.Following
	if err := r.db.Where("follower_id = ?", userID).Find(&following).Error; err != nil {
		return nil, fmt.Errorf("failed to get following: %v", err)
	}

	var followeeIDs []string
	for _, f := range following {
		followeeIDs = append(followeeIDs, f.FolloweeID)
	}

	var users []db.User
	if len(followeeIDs) > 0 {
		if err := r.db.Where("id IN (?) AND deleted_at IS NULL", followeeIDs).Find(&users).Error; err != nil {
			return nil, fmt.Errorf("failed to retrieve followees: %v", err)
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
	return profiles, nil
}

func (r *UserRepository) GetFollowers(userID string) ([]*AuthUserAdminService.UserProfile, error) {
	if userID == "" {
		return nil, errors.New("user ID cannot be empty")
	}
	var followers []db.Follower
	if err := r.db.Where("followee_id = ?", userID).Find(&followers).Error; err != nil {
		return nil, fmt.Errorf("failed to get followers: %v", err)
	}

	var followerIDs []string
	for _, f := range followers {
		followerIDs = append(followerIDs, f.FollowerID)
	}

	var users []db.User
	if len(followerIDs) > 0 {
		if err := r.db.Where("id IN (?) AND deleted_at IS NULL", followerIDs).Find(&users).Error; err != nil {
			return nil, fmt.Errorf("failed to retrieve followers: %v", err)
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
	return profiles, nil
}

func (r *UserRepository) CreateUserAdmin(req *AuthUserAdminService.CreateUserAdminRequest) (string, error) {
	if req == nil {
		return "", errors.New("create admin request cannot be nil")
	}
	if req.Password != req.ConfirmPassword {
		return "", errors.New("passwords do not match")
	}
	if !IsValidEmail(req.Email) {
		return "", errors.New("invalid email format")
	}
	if !IsValidPassword(req.Password) {
		return "", errors.New("password must be at least 8 characters, include an uppercase letter, and a digit")
	}

	socials := &AuthUserAdminService.Socials{} // Default empty socials
	if req.Socials != nil {
		socials = req.Socials
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %v", err)
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
		return "", fmt.Errorf("failed to create admin user: %v", err)
	}

	return user.ID, nil
}

func (r *UserRepository) UpdateUserAdmin(req *AuthUserAdminService.UpdateUserAdminRequest) error {
	if req == nil {
		return errors.New("update admin request cannot be nil")
	}
	if req.UserID == "" {
		return errors.New("user ID cannot be empty")
	}
	if req.Password != "" {
		if !IsValidPassword(req.Password) {
			return errors.New("invalid password format: must be at least 8 characters, include an uppercase letter, and a digit")
		}
	}

	socials := &AuthUserAdminService.Socials{} // Default empty socials
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
			return fmt.Errorf("failed to hash password: %v", err)
		}
		user.HashedPassword = string(hashedPassword)
	}

	if err := r.db.Model(&user).Where("id = ? AND deleted_at IS NULL", req.UserID).Updates(user).Error; err != nil {
		return fmt.Errorf("failed to update admin user: %v", err)
	}
	return nil
}

func (r *UserRepository) BanUser(userID, banReason string, banExpiry int64, banType string) error {
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Updates(map[string]interface{}{
			"is_banned": true,
		}).Error; err != nil {
		return errors.New("Unable to process ban request. Please try again.")
	}

	banHistory := db.BanHistory{
		ID:        uuid.New().String(),
		UserID:    userID,
		BanType:   banType,
		BannedAt:  time.Now().Unix(),
		BanReason: banReason,
		BanExpiry: banExpiry,
	}

	if err := r.db.Create(&banHistory).Error; err != nil {
		return fmt.Errorf("failed to record ban history: %v", err)
	}

	return nil
}

func (r *UserRepository) UnbanUser(userID string) error {
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Updates(map[string]interface{}{
			"is_banned": false,
		}).Error; err != nil {
		return errors.New("Unable to unban user. Please try again.")
	}
	return nil
}

func (r *UserRepository) VerifyAdminUser(userID string) error {
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Updates(map[string]interface{}{
			"is_verified": true,
			"updated_at":  time.Now().Unix(),
		}).Error; err != nil {
		return fmt.Errorf("failed to verify user: %v", err)
	}
	return nil
}

func (r *UserRepository) UnverifyUser(userID string) error {
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Updates(map[string]interface{}{
			"is_verified": false,
			"updated_at":  time.Now().Unix(),
		}).Error; err != nil {
		return fmt.Errorf("failed to unverify user: %v", err)
	}
	return nil
}

func (r *UserRepository) SoftDeleteUserAdmin(userID string) error {
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Update("deleted_at", time.Now()).Error; err != nil {
		return fmt.Errorf("failed to soft delete user: %v", err)
	}
	return nil
}

func (r *UserRepository) GetAllUsers(req *AuthUserAdminService.GetAllUsersRequest) ([]*AuthUserAdminService.UserProfile, int32, error) {
	if req == nil {
		return nil, 0, errors.New("get all users request cannot be nil")
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
		return nil, 0, fmt.Errorf("failed to count users: %v", err)
	}

	if err := query.Find(&users).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to retrieve users: %v", err)
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
	return profiles, int32(totalCount), nil
}

func (r *UserRepository) ChangePassword(userID, hashedPassword string) error {
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}
	if hashedPassword == "" {
		return errors.New("password cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Updates(map[string]interface{}{
			"password":   hashedPassword,
			"updated_at": time.Now().Unix(),
		}).Error; err != nil {
		return errors.New("Unable to update your password. Please try again later.")
	}
	return nil
}

func (r *UserRepository) IsUserVerified(userID string) (bool, error) {
	if userID == "" {
		return false, errors.New("user ID cannot be empty")
	}
	var user db.User
	if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, errors.New("user not found")
		}
		return false, fmt.Errorf("failed to check verification status: %v", err)
	}
	return user.IsVerified, nil
}

func (r *UserRepository) IsAdmin(userID string) (bool, error) {
	if userID == "" {
		return false, errors.New("user ID cannot be empty")
	}
	var user db.User
	if err := r.db.Where("id = ? AND role = ? AND deleted_at IS NULL", userID, "ADMIN").First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, fmt.Errorf("failed to check admin status: %v", err)
	}
	return true, nil
}

func (r *UserRepository) GetUserFor2FA(userID string) (*db.User, error) {
	if userID == "" {
		return nil, errors.New("user ID cannot be empty")
	}
	var user db.User
	if err := r.db.Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("failed to retrieve user for 2FA: %v", err)
	}
	return &user, nil
}

func (r *UserRepository) Update2FAStatus(userID string, enable bool) error {
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}
	if err := r.db.Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).Update("is_2fa_enabled", enable).Error; err != nil {
		return fmt.Errorf("failed to update 2FA status: %v", err)
	}
	return nil
}

func (r *UserRepository) CreateVerification(userID, email, token string) error {
	if userID == "" || email == "" || token == "" {
		return errors.New("user ID, email, or token cannot be empty")
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
		return fmt.Errorf("failed to create verification record: %v", err)
	}
	return nil
}

func (r *UserRepository) VerifyUserToken(email, token string) (bool, error) {
	if email == "" || token == "" {
		return false, errors.New("email or token cannot be empty")
	}

	var user db.User
	if err := r.db.Where("email = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, errors.New("Account not found. Please check your information and try again.")
		}
		return false, errors.New("Unable to verify your account. Please try again.")
	}

	if user.IsVerified {
		return false, errors.New("The user already verified")
	}

	var verification db.Verification
	if err := r.db.Where("email = ? AND token = ? AND expiry_at > ? AND used = ?", email, token, time.Now().Unix(), false).First(&verification).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, errors.New("Invalid or expired verification code. Please request a new one.")
		}
		return false, errors.New("Unable to verify your account. Please try again.")
	}

	if err := r.db.Model(&verification).Update("used", true).Error; err != nil {
		return false, fmt.Errorf("failed to mark token as used: %v", err)
	}
	if err := r.db.Model(&db.User{}).Where("email = ?", email).Update("is_verified", true).Error; err != nil {
		return false, fmt.Errorf("failed to update verification status: %v", err)
	}
	return true, nil
}

func (r *UserRepository) ResendEmailVerification(email string) (string, error) {
	if email == "" {
		return "", errors.New("email cannot be empty")
	}
	var user db.User
	if err := r.db.Where("email = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", errors.New("Account not found. Please check your information and try again.")
		}
		return "", errors.New("Unable to send verification code. Please try again later.")
	}

	if user.IsVerified {
		return "", errors.New("The user already verified")
	}

	var existingVerification db.Verification
	if err := r.db.Where("user_id = ? AND expiry_at > ? AND used = ?", user.ID, time.Now().Unix(), false).First(&existingVerification).Error; err == nil {
		return "", errors.New("A valid email verification already exists and is not expired.")
	}

	if existingVerification.ExpiryAt > time.Now().Unix() {
		return "", errors.New("A valid email verification already exists and is not expired.")
	}

	otp := GenerateOTP(6)
	verification := db.Verification{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Email:     user.Email,
		Token:     otp,
		CreatedAt: time.Now().Unix(),
		ExpiryAt:  time.Now().Add(30 * time.Minute).Unix(),
		Used:      false,
	}
	if err := r.db.Create(&verification).Error; err != nil {
		return "", fmt.Errorf("failed to create new email verification: %v", err)
	}

	if err := r.SendVerificationEmail(user.Email, otp); err != nil {
		log.Printf("Failed to send verification email: %v", err)
	}

	return otp, nil
}

func (r *UserRepository) CreateForgotPasswordToken(email, token string) (string, error) {
	if email == "" || token == "" {
		return "", errors.New("email or token cannot be empty")
	}
	var user db.User
	if err := r.db.Where("email = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", errors.New("user not found")
		}
		return "", fmt.Errorf("failed to retrieve user: %v", err)
	}

	if err := r.db.Where("user_id = ? AND expiry_at > ? AND used = ?", user.ID, time.Now(), false).Delete(&db.ForgotPassword{}).Error; err != nil {
		return "", fmt.Errorf("failed to clear existing reset token: %v", err)
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
		return "", fmt.Errorf("failed to create reset token: %v", err)
	}

	if r.config.APPURL == "" {
		log.Printf("APPURL not configured, skipping email send")
	} else {
		resetLink := fmt.Sprintf("%s/auth/finish-forgot-password?token=%s", r.config.APPURL, token)
		if err := r.SendForgotPasswordEmail(user.Email, resetLink); err != nil {
			log.Printf("Failed to send password reset email: %v", err)
		}
	}

	return user.ID, nil
}

func (r *UserRepository) VerifyForgotPasswordToken(userID, token string) (bool, error) {
	if userID == "" || token == "" {
		return false, errors.New("user ID or token cannot be empty")
	}
	var forgot db.ForgotPassword
	if err := r.db.Where("user_id = ? AND token = ? AND expiry_at > ? AND used = ?", userID, token, time.Now(), false).First(&forgot).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, fmt.Errorf("failed to verify reset token: %v", err)
	}

	if err := r.db.Model(&forgot).Update("used", true).Error; err != nil {
		return false, fmt.Errorf("failed to mark reset token as used: %v", err)
	}
	return true, nil
}

func (r *UserRepository) FinishForgotPassword(userID, token, newPassword string) error {
	if userID == "" || token == "" || newPassword == "" {
		return errors.New("user ID, token, or new password cannot be empty")
	}
	verified, err := r.VerifyForgotPasswordToken(userID, token)
	if err != nil {
		return fmt.Errorf("failed to verify password reset token: %v", err)
	}
	if !verified {
		return errors.New("invalid or expired password reset token")
	}

	if !IsValidPassword(newPassword) {
		return errors.New("invalid password format: must be at least 8 characters, include an uppercase letter, and a digit")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	return r.ChangePassword(userID, string(hashedPassword))
}

func (r *UserRepository) ChangeAuthenticatedPassword(userID, oldPassword, newPassword string) error {
	if userID == "" || oldPassword == "" || newPassword == "" {
		return errors.New("user ID, old password, or new password cannot be empty")
	}
	user, err := r.GetUserByEmail(userID)
	if err != nil {
		return fmt.Errorf("failed to retrieve user: %v", err)
	}

	if user.HashedPassword == "" {
		return errors.New("no existing password found for user")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(oldPassword)); err != nil {
		return errors.New("invalid old password")
	}

	if !IsValidPassword(newPassword) {
		return errors.New("invalid password format: must be at least 8 characters, include an uppercase letter, and a digit")
	}

	hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	return r.ChangePassword(userID, string(hashedNewPassword))
}

// Helper functions
func (r *UserRepository) SendVerificationEmail(to, otp string) error {
	if to == "" || otp == "" {
		return errors.New("email or OTP cannot be empty")
	}
	return utils.SendOTPEmail(to, "user", otp, 30)
}

func (r *UserRepository) SendForgotPasswordEmail(to, resetLink string) error {
	if to == "" || resetLink == "" {
		return errors.New("email or reset link cannot be empty")
	}
	return utils.SendForgotPasswordEmail(to, resetLink)
}

func GenerateOTP(length int) string {
	if length <= 0 {
		length = 6 // Default length
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

func (r *UserRepository) GetBanHistory(userID string) ([]*AuthUserAdminService.BanHistory, error) {
	if userID == "" {
		return nil, errors.New("user ID cannot be empty")
	}
	var bans []db.BanHistory
	if err := r.db.Where("user_id = ? AND deleted_at IS NULL", userID).Find(&bans).Error; err != nil {
		return nil, fmt.Errorf("failed to retrieve ban history: %v", err)
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
	return history, nil
}

func (r *UserRepository) SearchUsers(query string) ([]*AuthUserAdminService.UserProfile, error) {
	var users []db.User
	queryBuilder := r.db.Where("deleted_at IS NULL")
	if query != "" {
		queryBuilder = queryBuilder.Where("first_name ILIKE ? OR last_name ILIKE ? OR email ILIKE ?", "%"+query+"%", "%"+query+"%", "%"+query+"%")
	}
	if err := queryBuilder.Find(&users).Error; err != nil {
		return nil, fmt.Errorf("failed to retrieve users: %v", err)
	}

	var profiles []*AuthUserAdminService.UserProfile
	for _, u := range users {
		profiles = append(profiles, &AuthUserAdminService.UserProfile{
			UserID:            u.ID,
			UserName:          "",
			FirstName:         u.FirstName,
			LastName:          u.LastName,
			AvatarURL:         u.AvatarData,
			Email:             u.Email,
			Role:              u.Role,
			Country:           u.Country,
			IsBanned:          u.IsBanned,
			PrimaryLanguageID: u.PrimaryLanguageID,
			MuteNotifications: u.MuteNotifications,
			Socials: &AuthUserAdminService.Socials{
				Github:   u.Github,
				Twitter:  u.Twitter,
				Linkedin: u.Linkedin,
			},
			CreatedAt: u.CreatedAt,
		})
	}
	return profiles, nil
}
