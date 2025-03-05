package service

import (
	"context"
	"fmt"
	"log"
	"time"

	"xcode/repository"
	"xcode/utils"

	configs "xcode/configs"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	authUserAdminService "github.com/lijuuu/GlobalProtoXcode/AuthUserAdminService"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthUserAdminService implements the AuthUserAdminServiceServer interface
type AuthUserAdminService struct {
	repo      *repository.UserRepository
	config    *configs.Config
	jwtSecret string
	authUserAdminService.UnimplementedAuthUserAdminServiceServer
}

// NewAuthUserAdminService initializes and returns a new AuthUserAdminService
func NewAuthUserAdminService(repo *repository.UserRepository, config *configs.Config, jwtSecret string) *AuthUserAdminService {
	fmt.Println(jwtSecret)
	return &AuthUserAdminService{
		repo:      repo,
		config:    config,
		jwtSecret: jwtSecret,
	}
}

// RegisterUser handles user registration and sends verification OTP
func (s *AuthUserAdminService) RegisterUser(ctx context.Context, req *authUserAdminService.RegisterUserRequest) (*authUserAdminService.RegisterUserResponse, error) {
	if req.Password != req.ConfirmPassword {
		return nil, status.Error(codes.InvalidArgument, "The passwords entered do not match. Please try again.")
	}
	if !repository.IsValidEmail(req.Email) {
		return nil, status.Error(codes.InvalidArgument, "Please provide a valid email address.")
	}
	if !repository.IsValidPassword(req.Password) {
		return nil, status.Error(codes.InvalidArgument, "Password must be at least 8 characters and include an uppercase letter and a number.")
	}

	userID, err := s.repo.CreateUser(req)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		return nil, status.Error(codes.Internal, "An error occurred while creating your account. Please try again later.")
	}

	return &authUserAdminService.RegisterUserResponse{
		UserID: userID,
		UserProfile: &authUserAdminService.UserProfile{
			UserID:    userID,
			FirstName: req.FirstName,
			LastName:  req.LastName,
			Email:     req.Email,
			Country:   req.Country,
		},
		Message: "Your account has been created successfully. Please check your email for the verification code.",
	}, nil
}

// LoginUser handles user login with JWT generation
func (s *AuthUserAdminService) LoginUser(ctx context.Context, req *authUserAdminService.LoginUserRequest) (*authUserAdminService.LoginUserResponse, error) {
	user, err := s.repo.GetUserByEmail(req.Email)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while verifying your credentials. Please try again.")
	}
	if user.ID == "" {
		return nil, status.Error(codes.NotFound, "No account exists with this email address. Please verify or register.")
	}

	banStatus, err := s.repo.CheckBanStatus(user.ID)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while checking your ban status. Please try again.")
	}
	if banStatus.IsBanned {
		return nil, status.Error(codes.Unauthenticated, "Your account has been banned. Please contact support.")
	}

	valid, err := s.repo.CheckUserPassword(user.ID, req.Password)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while verifying your password. Please try again.")
	}
	if !valid {
		return nil, status.Error(codes.InvalidArgument, "The password provided is incorrect. Please try again.")
	}

	if !user.IsVerified {
		return nil, status.Error(codes.Unauthenticated, "Your email address requires verification. Please check your inbox.")
	}

	// if user.TwoFactorEnabled {
	// 	// err = s.repo.UpdateUserOnTwoFactorAuth(user)
	// 	// if err != nil {
	// 	// 	return nil, status.Error(codes.Internal, "An error occurred while processing your account. Please try again.")
	// 	// }
	// 	return nil, status.Error(codes.Unauthenticated, "Your account requires two-factor authentication. Please check your sent your code along with the login request")
	// }

	rtoken, _, err := utils.GenerateJWT(user.ID, "USER", s.jwtSecret, 30*24*time.Hour)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while generating your login token. Please try again.")
	}

	atoken, expiresIn, err := utils.GenerateJWT(user.ID, "USER", s.jwtSecret, 7*24*time.Hour)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while generating your login token. Please try again.")
	}

	fmt.Println(user)

	return &authUserAdminService.LoginUserResponse{
		UserProfile: &authUserAdminService.UserProfile{
			UserID:    user.ID,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Email:             user.Email,
			Role:              user.Role,
			IsVerified:        user.IsVerified,
			IsBanned:          user.IsBanned,
			PrimaryLanguageID: user.PrimaryLanguageID,
			Country:           user.Country,
			TwoFactorEnabled:  user.TwoFactorEnabled,
			AvatarData:        user.AvatarData,
			UserName:          user.UserName,
			Socials: &authUserAdminService.Socials{
				Github:   user.Github,
				Twitter:  user.Twitter,
				Linkedin: user.Linkedin,
			},
			CreatedAt: user.CreatedAt,
		},
		RefreshToken: rtoken,
		AccessToken:  atoken,
		ExpiresIn:    expiresIn,
		UserID:       user.ID,
		Message:      "Login successful. Welcome back.",
	}, nil
}

// LoginAdmin handles admin login with JWT generation
func (s *AuthUserAdminService) LoginAdmin(ctx context.Context, req *authUserAdminService.LoginAdminRequest) (*authUserAdminService.LoginAdminResponse, error) {
	user, err := s.repo.GetUserByEmail(req.Email)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while verifying your admin credentials. Please try again.")
	}
	if user.ID == "" {
		return nil, status.Error(codes.NotFound, "No admin account exists with this email address.")
	}
	if user.Role != "ADMIN" {
		return nil, status.Error(codes.PermissionDenied, "This account does not have administrative privileges.")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(req.Password + user.Salt)); err != nil {
		return nil, status.Error(codes.Unauthenticated, "The admin password provided is incorrect. Please try again.")
	}

	if !user.IsVerified {
		return nil, status.Error(codes.Unauthenticated, "This admin account requires verification. Please contact support.")
	}

	atoken, expiresIn, err := utils.GenerateJWT(user.ID, "ADMIN", s.jwtSecret, 30*24*time.Hour)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while generating your admin token. Please try again.")
	}

	return &authUserAdminService.LoginAdminResponse{
		AccessToken:  atoken,
		ExpiresIn:    expiresIn,
		AdminID:      user.ID,
		Message:      "Admin login successful. Welcome back.",
	}, nil
}

// TokenRefresh refreshes an access token
func (s *AuthUserAdminService) TokenRefresh(ctx context.Context, req *authUserAdminService.TokenRefreshRequest) (*authUserAdminService.TokenRefreshResponse, error) {
	claims := &utils.Claims{}
	token, err := jwt.ParseWithClaims(req.RefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.jwtSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, status.Error(codes.Unauthenticated, "Your session has expired. Please log in again.")
	}

	newToken, expiresIn, err := utils.GenerateJWT(claims.ID, claims.Role, s.jwtSecret, 7*24*time.Hour)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while refreshing your session. Please log in again.")
	}

	return &authUserAdminService.TokenRefreshResponse{
		AccessToken: newToken,
		ExpiresIn:   expiresIn,
		UserID:      claims.ID,
	}, nil
}

// LogoutUser handles user logout (placeholder, as JWT is stateless)
func (s *AuthUserAdminService) LogoutUser(ctx context.Context, req *authUserAdminService.LogoutRequest) (*authUserAdminService.LogoutResponse, error) {



	return &authUserAdminService.LogoutResponse{
		Message: "You have been logged out successfully.",
	}, nil
}

// ResendOTP resends a verification OTP
func (s *AuthUserAdminService) ResendEmailVerification(ctx context.Context, req *authUserAdminService.ResendEmailVerificationRequest) (*authUserAdminService.ResendEmailVerificationResponse, error) {
	_, err := s.repo.ResendEmailVerification(req.Email)
	if err != nil {

		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &authUserAdminService.ResendEmailVerificationResponse{
		Message: "A new verification email has been sent to your email address.",
	}, nil
}

// VerifyUser verifies a user with an OTP
func (s *AuthUserAdminService) VerifyUser(ctx context.Context, req *authUserAdminService.VerifyUserRequest) (*authUserAdminService.VerifyUserResponse, error) {
	verified, err := s.repo.VerifyUserToken(req.Email, req.Token)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if !verified {
		return nil, status.Error(codes.InvalidArgument, "The verification code is invalid or has expired. Please request a new one.")
	}
	return &authUserAdminService.VerifyUserResponse{
		Message: "Your account has been successfully verified. You may now log in.",
	}, nil
}

// SetTwoFactorAuth enables/disables 2FA
func (s *AuthUserAdminService) ToggleTwoFactorAuth(ctx context.Context, req *authUserAdminService.ToggleTwoFactorAuthRequest) (*authUserAdminService.ToggleTwoFactorAuthResponse, error) {
	user, err := s.repo.GetUserProfile(req.UserID)
	if err != nil {
		return nil, status.Error(codes.NotFound, "Your account could not be found. Please log in again.")
	}

	if !user.UserProfile.IsVerified {
		return nil, status.Error(codes.PermissionDenied, "Your account has not been verified. Please verify your account.")
	}

	valid, err := s.repo.CheckUserPassword(req.UserID, req.Password)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while verifying your password. Please try again.")
	}
	if !valid {
		return nil, status.Error(codes.Unauthenticated, "The password provided is incorrect. Please try again.")
	}

	err = s.repo.Update2FAStatus(req.UserID, req.TwoFactorAuth)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while updating two-factor authentication. Please try again.")
	}

	isEnabled := "enabled"
	if !req.TwoFactorAuth {
		isEnabled = "disabled"
	}
	return &authUserAdminService.ToggleTwoFactorAuthResponse{
		Message: fmt.Sprintf("Two-factor authentication has been %s for your account.", isEnabled),
	}, nil
}

// ForgotPassword initiates password recovery
func (s *AuthUserAdminService) ForgotPassword(ctx context.Context, req *authUserAdminService.ForgotPasswordRequest) (*authUserAdminService.ForgotPasswordResponse, error) {
	if !repository.IsValidEmail(req.Email) {
		return nil, status.Error(codes.InvalidArgument, "Please provide a valid email address.")
	}

	token := uuid.New().String()
	_, err := s.repo.CreateForgotPasswordToken(req.Email, token)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while initiating password recovery. Please try again.")
	}

	return &authUserAdminService.ForgotPasswordResponse{
		Message: "Password recovery instructions have been sent to your email.",
		Token:   token,
	}, nil
}

// FinishForgotPassword completes the password reset process
func (s *AuthUserAdminService) FinishForgotPassword(ctx context.Context, req *authUserAdminService.FinishForgotPasswordRequest) (*authUserAdminService.FinishForgotPasswordResponse, error) {
	if req.NewPassword != req.ConfirmPassword {
		return nil, status.Error(codes.InvalidArgument, "The new passwords do not match. Please try again.")
	}
	if !repository.IsValidPassword(req.NewPassword) {
		return nil, status.Error(codes.InvalidArgument, "Password must be at least 8 characters and include an uppercase letter and a number.")
	}

	err := s.repo.FinishForgotPassword(req.Email, req.Token, req.NewPassword)
	if err != nil {
		return nil, err
	}

	return &authUserAdminService.FinishForgotPasswordResponse{
		Message: "Your password has been reset successfully.",
	}, nil
}

// ChangePassword allows authenticated users to change their password
func (s *AuthUserAdminService) ChangePassword(ctx context.Context, req *authUserAdminService.ChangePasswordRequest) (*authUserAdminService.ChangePasswordResponse, error) {
	if req.NewPassword != req.ConfirmPassword {
		return nil, status.Error(codes.InvalidArgument, "The new passwords do not match. Please try again.")
	}
	if !repository.IsValidPassword(req.NewPassword) {
		return nil, status.Error(codes.InvalidArgument, "Password must be at least 8 characters and include an uppercase letter and a number.")
	}

	err := s.repo.ChangeAuthenticatedPassword(req.UserID, req.OldPassword, req.NewPassword)
	if err != nil {
		return nil, err
	}

	return &authUserAdminService.ChangePasswordResponse{
		Message: "Your password has been updated successfully.",
	}, nil
}

// UpdateProfile updates user profile
func (s *AuthUserAdminService) UpdateProfile(ctx context.Context, req *authUserAdminService.UpdateProfileRequest) (*authUserAdminService.UpdateProfileResponse, error) {
	err := s.repo.UpdateProfile(req)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while updating your profile. Please try again.")
	}
	return &authUserAdminService.UpdateProfileResponse{
		UserProfile: &authUserAdminService.UserProfile{
			UserID:            req.UserID,
			FirstName:         req.FirstName,
			LastName:          req.LastName,
			PrimaryLanguageID: req.PrimaryLanguageID,
			Country:           req.Country,
			UserName:          req.UserName,
			Socials: &authUserAdminService.Socials{
				Github:   req.Socials.Github,
				Twitter:  req.Socials.Twitter,
				Linkedin: req.Socials.Linkedin,
			},
		},
		Message: "Your profile has been updated successfully.",
	}, nil
}

// UpdateProfileImage updates the user's profile image
func (s *AuthUserAdminService) UpdateProfileImage(ctx context.Context, req *authUserAdminService.UpdateProfileImageRequest) (*authUserAdminService.UpdateProfileImageResponse, error) {
	err := s.repo.UpdateProfileImage(req)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while updating your profile image. Please try again.")
	}
	return &authUserAdminService.UpdateProfileImageResponse{
		Message:   "Your profile image has been updated successfully.",
		AvatarURL: req.AvatarURL,
	}, nil
}

// GetUserProfile retrieves a user's profile
func (s *AuthUserAdminService) GetUserProfile(ctx context.Context, req *authUserAdminService.GetUserProfileRequest) (*authUserAdminService.GetUserProfileResponse, error) {
	resp, err := s.repo.GetUserProfile(req.UserID)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// CheckBanStatus checks if a user is banned
func (s *AuthUserAdminService) CheckBanStatus(ctx context.Context, req *authUserAdminService.CheckBanStatusRequest) (*authUserAdminService.CheckBanStatusResponse, error) {
	resp, err := s.repo.CheckBanStatus(req.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while checking ban status. Please try again.")
	}
	if resp == nil {
		return nil, status.Error(codes.NotFound, "The specified user could not be found.")
	}
	return resp, nil
}

// FollowUser adds a follow relationship
func (s *AuthUserAdminService) FollowUser(ctx context.Context, req *authUserAdminService.FollowUserRequest) (*authUserAdminService.FollowUserResponse, error) {
	err := s.repo.FollowUser(req.FollowerID, req.FolloweeID)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while following the user. Please try again.")
	}
	return &authUserAdminService.FollowUserResponse{
		Message: "You are now following this user.",
	}, nil
}

// UnfollowUser removes a follow relationship
func (s *AuthUserAdminService) UnfollowUser(ctx context.Context, req *authUserAdminService.UnfollowUserRequest) (*authUserAdminService.UnfollowUserResponse, error) {
	err := s.repo.UnfollowUser(req.FollowerID, req.FolloweeID)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while unfollowing the user. Please try again.")
	}
	return &authUserAdminService.UnfollowUserResponse{
		Message: "You have unfollowed this user.",
	}, nil
}

// GetFollowing retrieves users a given user is following
func (s *AuthUserAdminService) GetFollowing(ctx context.Context, req *authUserAdminService.GetFollowingRequest) (*authUserAdminService.GetFollowingResponse, error) {
	profiles, err := s.repo.GetFollowing(req.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while retrieving followed users. Please try again.")
	}
	return &authUserAdminService.GetFollowingResponse{
		Users: profiles,
	}, nil
}

// GetFollowers retrieves users following a given user
func (s *AuthUserAdminService) GetFollowers(ctx context.Context, req *authUserAdminService.GetFollowersRequest) (*authUserAdminService.GetFollowersResponse, error) {
	profiles, err := s.repo.GetFollowers(req.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while retrieving followers. Please try again.")
	}
	return &authUserAdminService.GetFollowersResponse{
		Users: profiles,
	}, nil
}

// CreateUserAdmin creates a new admin user
func (s *AuthUserAdminService) CreateUserAdmin(ctx context.Context, req *authUserAdminService.CreateUserAdminRequest) (*authUserAdminService.CreateUserAdminResponse, error) {
	if req.Password != req.ConfirmPassword {
		return nil, status.Error(codes.InvalidArgument, "The passwords entered do not match. Please try again.")
	}
	if !repository.IsValidEmail(req.Email) {
		return nil, status.Error(codes.InvalidArgument, "Please provide a valid email address.")
	}
	if !repository.IsValidPassword(req.Password) {
		return nil, status.Error(codes.InvalidArgument, "Password must be at least 8 characters and include an uppercase letter and a number.")
	}

	userID, err := s.repo.CreateUserAdmin(req)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while creating the admin account. Please try again.")
	}
	return &authUserAdminService.CreateUserAdminResponse{
		UserID:  userID,
		Message: "The admin account has been created successfully.",
	}, nil
}

// UpdateUserAdmin updates an admin user
func (s *AuthUserAdminService) UpdateUserAdmin(ctx context.Context, req *authUserAdminService.UpdateUserAdminRequest) (*authUserAdminService.UpdateUserAdminResponse, error) {
	isAdmin, err := s.repo.IsAdmin(req.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while verifying admin status. Please try again.")
	}
	if !isAdmin {
		return nil, status.Error(codes.PermissionDenied, "Administrative privileges are required to perform this action.")
	}

	if req.Password != "" {
		if !repository.IsValidPassword(req.Password) {
			return nil, status.Error(codes.InvalidArgument, "Password must be at least 8 characters and include an uppercase letter and a number.")
		}
	}

	err = s.repo.UpdateUserAdmin(req)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while updating the admin account. Please try again.")
	}
	return &authUserAdminService.UpdateUserAdminResponse{
		Message: "The admin account has been updated successfully.",
	}, nil
}

// BlockUser sets a user as banned
func (s *AuthUserAdminService) BanUser(ctx context.Context, req *authUserAdminService.BanUserRequest) (*authUserAdminService.BanUserResponse, error) {

	err := s.repo.BanUser(req.UserID, req.BanReason, req.BanExpiry, req.BanType)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while banning the user. Please try again.")
	}
	return &authUserAdminService.BanUserResponse{
		Message: "The user has been banned successfully.",
	}, nil
}

// UnblockUser removes a user's ban
func (s *AuthUserAdminService) UnbanUser(ctx context.Context, req *authUserAdminService.UnbanUserRequest) (*authUserAdminService.UnbanUserResponse, error) {

	err := s.repo.UnbanUser(req.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while unbanning the user. Please try again.")
	}
	return &authUserAdminService.UnbanUserResponse{
		Message: "The user has been unbanned successfully.",
	}, nil
}

// VerifyAdminUser verifies a user (admin action)
func (s *AuthUserAdminService) VerifyAdminUser(ctx context.Context, req *authUserAdminService.VerifyAdminUserRequest) (*authUserAdminService.VerifyAdminUserResponse, error) {
	err := s.repo.VerifyAdminUser(req.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while verifying the user. Please try again.")
	}
	return &authUserAdminService.VerifyAdminUserResponse{
		Message: "The user has been verified successfully.",
	}, nil
}

// UnverifyUser un-verifies a user (admin action)
func (s *AuthUserAdminService) UnverifyUser(ctx context.Context, req *authUserAdminService.UnverifyUserAdminRequest) (*authUserAdminService.UnverifyUserAdminResponse, error) {

	err := s.repo.UnverifyUser(req.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while unverifying the user. Please try again.")
	}
	return &authUserAdminService.UnverifyUserAdminResponse{
		Message: "The user’s verification has been removed successfully.",
	}, nil
}

// SoftDeleteUserAdmin soft deletes a user
func (s *AuthUserAdminService) SoftDeleteUserAdmin(ctx context.Context, req *authUserAdminService.SoftDeleteUserAdminRequest) (*authUserAdminService.SoftDeleteUserAdminResponse, error) {
	isAdmin, err := s.repo.IsAdmin(req.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while verifying admin status. Please try again.")
	}
	if !isAdmin {
		return nil, status.Error(codes.PermissionDenied, "Administrative privileges are required to delete a user.")
	}

	err = s.repo.SoftDeleteUserAdmin(req.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while deleting the user. Please try again.")
	}
	return &authUserAdminService.SoftDeleteUserAdminResponse{
		Message: "The user has been soft-deleted successfully.",
	}, nil
}

// GetAllUsers retrieves a paginated list of users
func (s *AuthUserAdminService) GetAllUsers(ctx context.Context, req *authUserAdminService.GetAllUsersRequest) (*authUserAdminService.GetAllUsersResponse, error) {
	profiles, totalCount, err := s.repo.GetAllUsers(req)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while retrieving users. Please try again.")
	}
	return &authUserAdminService.GetAllUsersResponse{
		Users:      profiles,
		TotalCount: totalCount,
		Message:    "User list retrieved successfully.",
	}, nil
}

func (s *AuthUserAdminService) BanHistory(ctx context.Context, req *authUserAdminService.BanHistoryRequest) (*authUserAdminService.BanHistoryResponse, error) {
	history, err := s.repo.GetBanHistory(req.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while retrieving ban history. Please try again.")
	}
	return &authUserAdminService.BanHistoryResponse{
		Bans:    history,
		Message: "Ban history retrieved successfully.",
	}, nil
}

func (s *AuthUserAdminService) SearchUsers(ctx context.Context, req *authUserAdminService.SearchUsersRequest) (*authUserAdminService.SearchUsersResponse, error) {
	users, nextPageToken, err := s.repo.SearchUsers(req.Query, req.PageToken, req.Limit)
	if err != nil {
		return nil, status.Error(codes.Internal, "An error occurred while searching for users. Please try again.")
	}
	return &authUserAdminService.SearchUsersResponse{
		Users:       users,
		NextPageToken: nextPageToken,
		Message: "User search completed successfully.",
	}, nil
}
