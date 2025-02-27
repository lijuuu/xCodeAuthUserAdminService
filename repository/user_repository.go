package repository

import (
	"context"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

type UserRepository struct {
	db     *gorm.DB
	config *configs.Config
}

func NewUserRepository(db *gorm.DB, config *configs.Config) *UserRepository {
	return &UserRepository{db: db, config: config}
}

func (r *UserRepository) CreateUser(ctx context.Context, req *AuthUserAdminService.RegisterUserRequest) (string, error) {
	// Validate input
	if req.Password != req.ConfirmPassword {
		return "", status.Errorf(codes.InvalidArgument, "passwords do not match")
	}
	if !IsValidEmail(req.Email) {
		return "", status.Errorf(codes.InvalidArgument, "invalid email format")
	}
	if !IsValidPassword(req.Password) {
		return "", status.Errorf(codes.InvalidArgument, "password must be at least 8 characters, include an uppercase letter, and a digit")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to hash password: %v", err)
	}

	salt := uuid.New().String()

	user := db.User{
		ID:                uuid.New().String(),
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		Country:           req.Country,
		Role:              req.Role,
		PrimaryLanguageID: req.PrimaryLanguageID,
		Email:             req.Email,
		AuthType:          req.AuthType,
		Salt:              salt,
		HashedPassword:    string(hashedPassword) + salt,
		MuteNotifications: req.MuteNotifications,
		Github:            req.Socials.Github,
		Twitter:           req.Socials.Twitter,
		Linkedin:          req.Socials.Linkedin,
	}

	if err := r.db.WithContext(ctx).Create(&user).Error; err != nil {
		return "", status.Errorf(codes.Internal, "failed to create user: %v", err)
	}

	// Generate and send verification OTP
	otp := GenerateOTP(6)
	verification := db.Verification{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Email:     user.Email,
		Token:     otp,
		CreatedAt: time.Now().Unix(),
		ExpiryAt:  time.Now().Add(30 * time.Minute).Unix(), // OTP valid for 30 minutes
		Used:      false,
	}
	if err := r.db.WithContext(ctx).Create(&verification).Error; err != nil {
		return "", status.Errorf(codes.Internal, "failed to create verification record: %v", err)
	}

	// Send verification email using SMTP configured in config
	if err := r.SendVerificationEmail(user.Email, otp); err != nil {
		log.Printf("Failed to send verification email: %v", err)
		// Optionally, log for retry or notify admin, but proceed to allow registration
	}

	return user.ID, nil
}

func (r *UserRepository) CheckUserPassword(ctx context.Context, userID, password string) (bool, error) {
	var user db.User
	if err := r.db.WithContext(ctx).Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		return false, status.Errorf(codes.Internal, "failed to retrieve user: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(password+user.Salt)); err != nil {
		return false, status.Errorf(codes.Unauthenticated, "invalid credentials: %v", err)
	}
	return true, nil
}

func (r *UserRepository) CheckAdminPassword(ctx context.Context, password string) (bool, error) {
	if password != r.config.AdminPassword {
		return false, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}
	return true, nil
}

func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (string, string, string, bool, error) {
	var user db.User
	if err := r.db.WithContext(ctx).Where("email = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", "", "", false, nil
		}
		return "", "", "", false, status.Errorf(codes.Internal, "failed to retrieve user: %v", err)
	}
	return user.ID, user.HashedPassword, user.Role, user.IsVerified, nil
}

func (r *UserRepository) UpdateProfile(ctx context.Context, req *AuthUserAdminService.UpdateProfileRequest) error {
	user := db.User{
		ID:                req.UserID,
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		Country:           req.Country,
		PrimaryLanguageID: req.PrimaryLanguageID,
		MuteNotifications: req.MuteNotifications,
		Github:            req.Socials.Github,
		Twitter:           req.Socials.Twitter,
		Linkedin:          req.Socials.Linkedin,
		UpdatedAt:         time.Now().Unix(),
	}
	if err := r.db.WithContext(ctx).Model(&user).Where("id = ? AND deleted_at IS NULL", req.UserID).Updates(user).Error; err != nil {
		return status.Errorf(codes.Internal, "failed to update profile: %v", err)
	}
	return nil
}

func (r *UserRepository) UpdateProfileImage(ctx context.Context, req *AuthUserAdminService.UpdateProfileImageRequest) error {
	if err := r.db.WithContext(ctx).Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", req.UserID).
		Updates(map[string]interface{}{
			"avatar_data": req.AvatarURL,
			"updated_at":  time.Now().Unix(),
		}).Error; err != nil {
		return status.Errorf(codes.Internal, "failed to update profile image: %v", err)
	}
	return nil
}

func (r *UserRepository) GetUserProfile(ctx context.Context, userID string) (*AuthUserAdminService.GetUserProfileResponse, error) {
	var user db.User
	if err := r.db.WithContext(ctx).Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, status.Errorf(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to retrieve user profile: %v", err)
	}

	return &AuthUserAdminService.GetUserProfileResponse{
		UserProfile: &AuthUserAdminService.UserProfile{
			UserID:            user.ID,
			FirstName:         user.FirstName,
			LastName:          user.LastName,
			Email:             user.Email,
			Role:              user.Role,
			Status:            user.Status,
			Country:           user.Country,
			PrimaryLanguageID: user.PrimaryLanguageID,
			Socials: &AuthUserAdminService.Socials{
				Github:   user.Github,
				Twitter:  user.Twitter,
				Linkedin: user.Linkedin,
			},
		},
	}, nil
}

func (r *UserRepository) CheckBanStatus(ctx context.Context, userID string) (*AuthUserAdminService.CheckBanStatusResponse, error) {
	var user db.User
	if err := r.db.WithContext(ctx).Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, status.Errorf(codes.Internal, "failed to check ban status: %v", err)
	}

	resp := &AuthUserAdminService.CheckBanStatusResponse{
		IsBanned: user.IsBanned,
		Reason:   user.BanReason,
		Message:  "Ban status checked",
	}
	if user.BanExpiration != nil {
		resp.BanExpiration = *user.BanExpiration
	}
	return resp, nil
}

func (r *UserRepository) FollowUser(ctx context.Context, followerID, followeeID string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&db.Following{
			FollowerID: followerID,
			FolloweeID: followeeID,
		}).Error; err != nil {
			return status.Errorf(codes.Internal, "failed to create following relationship: %v", err)
		}

		// if err := tx.Create(&db.Follower{
		// 	FollowerID: followerID,
		// 	FolloweeID: followeeID,
		// }).Error; err != nil {
		// 	return status.Errorf(codes.Internal, "failed to create follower relationship: %v", err)
		// }
		return nil
	})
}

func (r *UserRepository) UnfollowUser(ctx context.Context, followerID, followeeID string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("follower_id = ? AND followee_id = ?", followerID, followeeID).Delete(&db.Following{}).Error; err != nil {
			return status.Errorf(codes.Internal, "failed to delete following relationship: %v", err)
		}

		// if err := tx.Where("follower_id = ? AND followee_id = ?", followerID, followeeID).Delete(&db.Follower{}).Error; err != nil {
		// 	return status.Errorf(codes.Internal, "failed to delete follower relationship: %v", err)
		// }
		return nil
	})
}

func (r *UserRepository) GetFollowing(ctx context.Context, userID string) ([]*AuthUserAdminService.UserProfile, error) {
	var following []db.Following
	if err := r.db.WithContext(ctx).Where("follower_id = ?", userID).Find(&following).Error; err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get following: %v", err)
	}

	var followeeIDs []string
	for _, f := range following {
		followeeIDs = append(followeeIDs, f.FolloweeID)
	}

	var users []db.User
	if err := r.db.WithContext(ctx).Where("id IN (?) AND deleted_at IS NULL", followeeIDs).Find(&users).Error; err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve followees: %v", err)
	}

	var profiles []*AuthUserAdminService.UserProfile
	for _, u := range users {
		profiles = append(profiles, &AuthUserAdminService.UserProfile{
			UserID:    u.ID,
			FirstName: u.FirstName,
			LastName:  u.LastName,
			Email:     u.Email,
			Role:      u.Role,
			Status:    u.Status,
			Socials:   &AuthUserAdminService.Socials{Github: u.Github, Twitter: u.Twitter, Linkedin: u.Linkedin},
		})
	}
	return profiles, nil
}

func (r *UserRepository) GetFollowers(ctx context.Context, userID string) ([]*AuthUserAdminService.UserProfile, error) {
	var followers []db.Follower
	if err := r.db.WithContext(ctx).Where("followee_id = ?", userID).Find(&followers).Error; err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get followers: %v", err)
	}

	var followerIDs []string
	for _, f := range followers {
		followerIDs = append(followerIDs, f.FollowerID)
	}

	var users []db.User
	if err := r.db.WithContext(ctx).Where("id IN (?) AND deleted_at IS NULL", followerIDs).Find(&users).Error; err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve followers: %v", err)
	}

	var profiles []*AuthUserAdminService.UserProfile
	for _, u := range users {
		profiles = append(profiles, &AuthUserAdminService.UserProfile{
			UserID:    u.ID,
			FirstName: u.FirstName,
			LastName:  u.LastName,
			Email:     u.Email,
			Role:      u.Role,
			Status:    u.Status,
			Socials:   &AuthUserAdminService.Socials{Github: u.Github, Twitter: u.Twitter, Linkedin: u.Linkedin},
		})
	}
	return profiles, nil
}

func (r *UserRepository) CreateUserAdmin(ctx context.Context, req *AuthUserAdminService.CreateUserAdminRequest) (string, error) {
	if req.Password != req.ConfirmPassword {
		return "", status.Errorf(codes.InvalidArgument, "passwords do not match")
	}
	if !IsValidEmail(req.Email) {
		return "", status.Errorf(codes.InvalidArgument, "invalid email format")
	}
	if !IsValidPassword(req.Password) {
		return "", status.Errorf(codes.InvalidArgument, "password must be at least 8 characters, include an uppercase letter, and a digit")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return "", status.Errorf(codes.Internal, "failed to hash password: %v", err)
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
		Github:            req.Socials.Github,
		Twitter:           req.Socials.Twitter,
		Linkedin:          req.Socials.Linkedin,
	}

	if err := r.db.WithContext(ctx).Create(&user).Error; err != nil {
		return "", status.Errorf(codes.Internal, "failed to create admin user: %v", err)
	}

	return user.ID, nil
}

func (r *UserRepository) UpdateUserAdmin(ctx context.Context, req *AuthUserAdminService.UpdateUserAdminRequest) error {
	if req.Password != "" {
		if !IsValidPassword(req.Password) {
			return status.Errorf(codes.InvalidArgument, "invalid password format: must be at least 8 characters, include an uppercase letter, and a digit")
		}
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
		Github:            req.Socials.Github,
		Twitter:           req.Socials.Twitter,
		Linkedin:          req.Socials.Linkedin,
		UpdatedAt:         time.Now().Unix(),
	}
	if req.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to hash password: %v", err)
		}
		user.HashedPassword = string(hashedPassword)
	}

	if err := r.db.WithContext(ctx).Model(&user).Where("id = ? AND deleted_at IS NULL", req.UserID).Updates(user).Error; err != nil {
		return status.Errorf(codes.Internal, "failed to update admin user: %v", err)
	}
	return nil
}

func (r *UserRepository) BanUser(ctx context.Context, userID string, banReason string, banExpiry int64,banType string) error {
	if err := r.db.WithContext(ctx).Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Updates(map[string]interface{}{
			"is_banned":      true,
		}).Error; err != nil {
		return status.Errorf(codes.Internal, "failed to ban user: %v", err)
	}

	// Record the ban in the BanHistory table
	banHistory := db.BanHistory{
		ID:        uuid.New().String(),
		UserID:    userID,
		BanType:   banType,
		BannedAt:  time.Now().Unix(),
		BanReason: banReason,
		BanExpiry: banExpiry,
	}

	if err := r.db.WithContext(ctx).Create(&banHistory).Error; err != nil {
		return status.Errorf(codes.Internal, "failed to record ban history: %v", err)
	}

	return nil
}

func (r *UserRepository) UnbanUser(ctx context.Context, userID string) error {
	if err := r.db.WithContext(ctx).Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Updates(map[string]interface{}{
			"is_banned":      false,
		}).Error; err != nil {
		return status.Errorf(codes.Internal, "failed to unban user: %v", err)
	}
	return nil
}

func (r *UserRepository) VerifyAdminUser(ctx context.Context, userID string) error {
	if err := r.db.WithContext(ctx).Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Updates(map[string]interface{}{
			"is_verified": true,
			"updated_at":  time.Now().Unix(),
		}).Error; err != nil {
		return status.Errorf(codes.Internal, "failed to verify user: %v", err)
	}
	return nil
}

func (r *UserRepository) UnverifyUser(ctx context.Context, userID string) error {
	if err := r.db.WithContext(ctx).Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Updates(map[string]interface{}{
			"is_verified": false,
			"updated_at":  time.Now().Unix(),
		}).Error; err != nil {
		return status.Errorf(codes.Internal, "failed to unverify user: %v", err)
	}
	return nil
}

func (r *UserRepository) SoftDeleteUserAdmin(ctx context.Context, userID string) error {
	if err := r.db.WithContext(ctx).Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Update("deleted_at", time.Now()).Error; err != nil {
		return status.Errorf(codes.Internal, "failed to soft delete user: %v", err)
	}
	return nil
}

func (r *UserRepository) GetAllUsers(ctx context.Context, req *AuthUserAdminService.GetAllUsersRequest) ([]*AuthUserAdminService.UserProfile, int32, error) {
	var users []db.User
	query := r.db.WithContext(ctx).Where("deleted_at IS NULL")
	if req.RoleFilter != "" {
		query = query.Where("role = ?", req.RoleFilter)
	}
	if req.StatusFilter != "" {
		query = query.Where("status = ?", req.StatusFilter)
	}

	var totalCount int64
	if err := query.Model(&db.User{}).Count(&totalCount).Error; err != nil {
		return nil, 0, status.Errorf(codes.Internal, "failed to count users: %v", err)
	}

	//Limit(int(req.Limit)).Offset(int((req.Page - 1) * req.Limit))

	if err := query.Find(&users).Error; err != nil {
		return nil, 0, status.Errorf(codes.Internal, "failed to retrieve users: %v", err)
	}

	var profiles []*AuthUserAdminService.UserProfile
	for _, u := range users {
		profiles = append(profiles, &AuthUserAdminService.UserProfile{
			UserID:    u.ID,
			FirstName: u.FirstName,
			LastName:  u.LastName,
			Email:     u.Email,
			Role:      u.Role,
			Status:    u.Status,
			Socials:   &AuthUserAdminService.Socials{Github: u.Github, Twitter: u.Twitter, Linkedin: u.Linkedin},
		})
	}
	return profiles, int32(totalCount), nil
}

func (r *UserRepository) ChangePassword(ctx context.Context, userID, hashedPassword string) error {
	if err := r.db.WithContext(ctx).Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).
		Updates(map[string]interface{}{
			"password":   hashedPassword,
			"updated_at": time.Now().Unix(),
		}).Error; err != nil {
		return status.Errorf(codes.Internal, "failed to update password: %v", err)
	}
	return nil
}

func (r *UserRepository) IsUserVerified(ctx context.Context, userID string) (bool, error) {
	var user db.User
	if err := r.db.WithContext(ctx).Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, status.Errorf(codes.NotFound, "user not found")
		}
		return false, status.Errorf(codes.Internal, "failed to check verification status: %v", err)
	}
	return user.IsVerified, nil
}

func (r *UserRepository) IsAdmin(ctx context.Context, userID string) (bool, error) {
	var user db.User
	if err := r.db.WithContext(ctx).Where("id = ? AND role = ? AND deleted_at IS NULL", userID, "ADMIN").First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, status.Errorf(codes.Internal, "failed to check admin status: %v", err)
	}
	return true, nil
}

func (r *UserRepository) GetUserFor2FA(ctx context.Context, userID string) (*db.User, error) {
	var user db.User
	if err := r.db.WithContext(ctx).Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, status.Errorf(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to retrieve user for 2FA: %v", err)
	}
	return &user, nil
}

func (r *UserRepository) Update2FAStatus(ctx context.Context, userID string, enable bool) error {
	if err := r.db.WithContext(ctx).Model(&db.User{}).Where("id = ? AND deleted_at IS NULL", userID).Update("is_2fa_enabled", enable).Error; err != nil {
		return status.Errorf(codes.Internal, "failed to update 2FA status: %v", err)
	}
	return nil
}

func (r *UserRepository) CreateVerification(ctx context.Context, userID, email, token string) error {
	verification := db.Verification{
		UserID:    userID,
		Email:     email,
		Token:     token,
		CreatedAt: time.Now().Unix(),
		ExpiryAt:  time.Now().Add(30 * time.Minute).Unix(),
		Used:      false,
	}
	if err := r.db.WithContext(ctx).Create(&verification).Error; err != nil {
		return status.Errorf(codes.Internal, "failed to create verification record: %v", err)
	}
	return nil
}

func (r *UserRepository) VerifyUserToken(ctx context.Context, email, token string) (bool, error) {
	var verification db.Verification
	if err := r.db.WithContext(ctx).Where("email = ? AND token = ? AND expiry_at > ? AND used = ?", email, token, time.Now(), false).First(&verification).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, status.Errorf(codes.Internal, "failed to verify token: %v", err)
	}

	if err := r.db.WithContext(ctx).Model(&verification).Update("used", true).Error; err != nil {
		return false, status.Errorf(codes.Internal, "failed to mark token as used: %v", err)
	}
	if err := r.db.WithContext(ctx).Model(&db.User{}).Where("email = ?", email).Update("is_verified", true).Error; err != nil {
		return false, status.Errorf(codes.Internal, "failed to update verification status: %v", err)
	}
	return true, nil
}

func (r *UserRepository) ResendOTP(ctx context.Context, userID string) (string, error) {
	var user db.User
	if err := r.db.WithContext(ctx).Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", status.Errorf(codes.NotFound, "user not found")
		}
		return "", status.Errorf(codes.Internal, "failed to retrieve user: %v", err)
	}

	if err := r.db.WithContext(ctx).Where("user_id = ? AND expiry_at > ? AND used = ?", userID, time.Now(), false).Delete(&db.Verification{}).Error; err != nil {
		return "", status.Errorf(codes.Internal, "failed to clear existing OTP: %v", err)
	}

	otp := GenerateOTP(6)
	verification := db.Verification{
		ID:        uuid.New().String(),
		UserID:    userID,
		Email:     user.Email,
		Token:     otp,
		CreatedAt: time.Now().Unix(),
		ExpiryAt:  time.Now().Add(30 * time.Minute).Unix(),
		Used:      false,
	}
	if err := r.db.WithContext(ctx).Create(&verification).Error; err != nil {
		return "", status.Errorf(codes.Internal, "failed to create new OTP: %v", err)
	}

	if err := r.SendVerificationEmail(user.Email, otp); err != nil {
		log.Printf("Failed to send verification email: %v", err)
		// return "", status.Errorf(codes.Internal, "failed to send verification email: %v", err)
	}

	return otp, nil
}

func (r *UserRepository) CreateForgotPasswordToken(ctx context.Context, email, token string) (string, error) {
	var user db.User
	if err := r.db.WithContext(ctx).Where("email = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", status.Errorf(codes.NotFound, "user not found")
		}
		return "", status.Errorf(codes.Internal, "failed to retrieve user: %v", err)
	}

	if err := r.db.WithContext(ctx).Where("user_id = ? AND expiry_at > ? AND used = ?", user.ID, time.Now(), false).Delete(&db.ForgotPassword{}).Error; err != nil {
		return "", status.Errorf(codes.Internal, "failed to clear existing reset token: %v", err)
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
	if err := r.db.WithContext(ctx).Create(&forgot).Error; err != nil {
		return "", status.Errorf(codes.Internal, "failed to create reset token: %v", err)
	}

	resetLink := fmt.Sprintf("%s/auth/finish-forgot-password?token=%s", r.config.APPURL, token)
	if err := r.SendForgotPasswordEmail(user.Email, resetLink); err != nil {
		log.Printf("Failed to send password reset email: %v", err)
		// Log for retry or notify admin, but proceed to allow recovery
	}

	return user.ID, nil
}

func (r *UserRepository) VerifyForgotPasswordToken(ctx context.Context, userID, token string) (bool, error) {
	var forgot db.ForgotPassword
	if err := r.db.WithContext(ctx).Where("user_id = ? AND token = ? AND expiry_at > ? AND used = ?", userID, token, time.Now(), false).First(&forgot).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, status.Errorf(codes.Internal, "failed to verify reset token: %v", err)
	}

	if err := r.db.WithContext(ctx).Model(&forgot).Update("used", true).Error; err != nil {
		return false, status.Errorf(codes.Internal, "failed to mark reset token as used: %v", err)
	}
	return true, nil
}

func (r *UserRepository) FinishForgotPassword(ctx context.Context, userID, token, newPassword string) error {
	verified, err := r.VerifyForgotPasswordToken(ctx, userID, token)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to verify password reset token: %v", err)
	}
	if !verified {
		return status.Errorf(codes.InvalidArgument, "invalid or expired password reset token")
	}

	if !IsValidPassword(newPassword) {
		return status.Errorf(codes.InvalidArgument, "invalid password format: must be at least 8 characters, include an uppercase letter, and a digit")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to hash password: %v", err)
	}

	return r.ChangePassword(ctx, userID, string(hashedPassword))
}

func (r *UserRepository) ChangeAuthenticatedPassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	_, hashedOldPassword, _, _, err := r.GetUserByEmail(ctx, userID)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to retrieve user: %v", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedOldPassword), []byte(oldPassword)); err != nil {
		return status.Errorf(codes.Unauthenticated, "invalid old password")
	}

	if !IsValidPassword(newPassword) {
		return status.Errorf(codes.InvalidArgument, "invalid password format: must be at least 8 characters, include an uppercase letter, and a digit")
	}

	hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to hash password: %v", err)
	}

	return r.ChangePassword(ctx, userID, string(hashedNewPassword))
}

// Helper functions
func (r *UserRepository) SendVerificationEmail(to, otp string) error {
	return utils.SendOTPEmail(to, "user", otp, 30)
}

func (r *UserRepository) SendForgotPasswordEmail(to, resetLink string) error {
	return utils.SendForgotPasswordEmail(to, resetLink)
}

func GenerateOTP(length int) string {
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


func (r *UserRepository) GetBanHistory(ctx context.Context, userID string) ([]*AuthUserAdminService.BanHistory, error) {
	var bans []db.BanHistory
	if err := r.db.WithContext(ctx).Where("user_id = ? AND deleted_at IS NULL", userID).Find(&bans).Error; err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve ban history: %v", err)
	}

	var history []*AuthUserAdminService.BanHistory
	for _, ban := range bans {
		history = append(history, &AuthUserAdminService.BanHistory{
			Id: ban.ID,
			UserID: ban.UserID,
			BanType: ban.BanType,
			BannedAt: ban.BannedAt, 
			BanReason: ban.BanReason,
			BanExpiry: ban.BanExpiry,
		})
	}

// 	message BanHistory {
//     string id = 1;
//     string userID = 2;
//     string bannedAt = 3;
//     string banType = 4;
//     string banReason = 5;
//     string banExpiry = 6;
//     int64 createdAt = 7;
// }
	return history, nil
}

func (r *UserRepository) SearchUsers(ctx context.Context, query string) ([]*AuthUserAdminService.UserProfile, error) {
	var users []db.User
	if err := r.db.WithContext(ctx).Where("deleted_at IS NULL").Find(&users).Error; err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve users: %v", err)
	}

	var profiles []*AuthUserAdminService.UserProfile
	for _, u := range users {
		profiles = append(profiles, &AuthUserAdminService.UserProfile{
			UserID:            u.ID,
			UserName:          "", // Assuming UserName is not available in db.User
			FirstName:         u.FirstName,
			LastName:          u.LastName,
			AvatarURL:         u.AvatarData,
			Email:             u.Email,
			Role:              u.Role,
			Status:            u.Status,
			Country:           u.Country,
			IsBanned:          u.IsBanned,
			PrimaryLanguageID: u.PrimaryLanguageID,
			MuteNotifications: u.MuteNotifications,
			Socials: &AuthUserAdminService.Socials{
				Github:   u.Github,
				Twitter:  u.Twitter,
				Linkedin: u.Linkedin,
			},
			CreatedAt:         u.CreatedAt,
		})
	}
	return profiles, nil
}

