package service

import (
	"context"
	"fmt"
	"log"
	"time"

	"xcode/repository"
	"xcode/utils"

	configs "xcode/configs"
	"xcode/customerrors"

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
	return &AuthUserAdminService{
		repo:      repo,
		config:    config,
		jwtSecret: jwtSecret,
	}
}

// createGrpcError constructs a gRPC error with structured message
func (s *AuthUserAdminService) createGrpcError(code codes.Code, message string, errorType string, cause error) error {
	var details string
	if cause != nil {
		details = cause.Error()
	} else {
		details = message
	}
	// Format: "ErrorType: <type>, Code: <code>, Details: <details>"
	errorMessage := fmt.Sprintf("ErrorType: %s, Code: %d, Details: %s", errorType, code, details)
	return status.Error(code, errorMessage)
}

// RegisterUser handles user registration and sends verification OTP
func (s *AuthUserAdminService) RegisterUser(ctx context.Context, req *authUserAdminService.RegisterUserRequest) (*authUserAdminService.RegisterUserResponse, error) {
	if req.Password != req.ConfirmPassword {
		return nil, s.createGrpcError(codes.InvalidArgument, "The passwords entered do not match", customerrors.ERR_REG_PASSWORD_MISMATCH, nil)
	}
	if !repository.IsValidEmail(req.Email) {
		return nil, s.createGrpcError(codes.InvalidArgument, "Please provide a valid email address", customerrors.ERR_REG_INVALID_EMAIL, nil)
	}
	if !repository.IsValidPassword(req.Password) {
		return nil, s.createGrpcError(codes.InvalidArgument, "Password must be at least 8 characters and include an uppercase letter and a number", customerrors.ERR_REG_INVALID_PASSWORD, nil)
	}

	userID, errorType, err := s.repo.CreateUser(req)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		return nil, s.createGrpcError(codes.Internal, "An error occurred while creating your account", errorType, err)
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
		Message: "Your account has been created successfully. Please verify your email.",
	}, nil
}

// LoginUser handles user login with JWT generation
func (s *AuthUserAdminService) LoginUser(ctx context.Context, req *authUserAdminService.LoginUserRequest) (*authUserAdminService.LoginUserResponse, error) {
	user, errorType, err := s.repo.GetUserByEmail(req.Email)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while verifying your credentials", errorType, err)
	}
	if user.ID == "" {
		return nil, s.createGrpcError(codes.NotFound, "No account exists with this email address", customerrors.ERR_USER_NOT_FOUND, nil)
	}

	banStatus, errorType, err := s.repo.CheckBanStatus(user.ID)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while checking your ban status", errorType, err)
	}
	if banStatus.IsBanned {
		return nil, s.createGrpcError(codes.Unauthenticated, "Your account has been banned", customerrors.ERR_LOGIN_ACCOUNT_BANNED, nil)
	}

	valid, errorType, err := s.repo.CheckUserPassword(user.ID, req.Password)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while verifying your password", errorType, err)
	}
	if !valid {
		return nil, s.createGrpcError(codes.InvalidArgument, "The password provided is incorrect", customerrors.ERR_LOGIN_CRED_WRONG, nil)
	}

	if !user.IsVerified {
		return nil, s.createGrpcError(codes.Unauthenticated, "Your email address requires verification", customerrors.ERR_LOGIN_NOT_VERIFIED, nil)
	}

	isEnabled, errorType, err := s.repo.GetTwoFactorAuthStatus(user.Email)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while checking 2FA status", errorType, err)
	}

	if isEnabled {
		valid, errorType, err := s.repo.VerifyTwoFactorAuth(user.Email, req.TwoFactorCode)
		if err != nil {
			return nil, s.createGrpcError(codes.Internal, "An error occurred while verifying OTP", errorType, err)
		}
		if !valid {
			return nil, s.createGrpcError(codes.InvalidArgument, "The OTP provided is incorrect", customerrors.ERR_LOGIN_2FA_CODE_INVALID, nil)
		}
	}


	rtoken, _, err := utils.GenerateJWT(user.ID, "USER", s.jwtSecret, 7*24*time.Hour)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while generating your refresh token", customerrors.ERR_LOGIN_TOKEN_GEN_FAILED, err)
	}

	atoken, expiresIn, err := utils.GenerateJWT(user.ID, "USER", s.jwtSecret, 1*24*time.Hour)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while generating your access token", customerrors.ERR_LOGIN_TOKEN_GEN_FAILED, err)
	}

	return &authUserAdminService.LoginUserResponse{
		UserProfile: &authUserAdminService.UserProfile{
			UserID:            user.ID,
			FirstName:         user.FirstName,
			LastName:          user.LastName,
			Email:             user.Email,
			Role:              user.Role,
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
	user, errorType, err := s.repo.GetUserByEmail(req.Email)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while verifying your admin credentials", errorType, err)
	}
	if user.ID == "" {
		return nil, s.createGrpcError(codes.NotFound, "No admin account exists with this email address", customerrors.ERR_ADMIN_LOGIN_NOT_FOUND, nil)
	}
	if user.Role != "ADMIN" {
		return nil, s.createGrpcError(codes.PermissionDenied, "This account does not have administrative privileges", customerrors.ERR_ADMIN_LOGIN_NO_PRIVILEGES, nil)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(req.Password+user.Salt)); err != nil {
		return nil, s.createGrpcError(codes.Unauthenticated, "The admin password provided is incorrect", customerrors.ERR_ADMIN_LOGIN_CRED_WRONG, nil)
	}

	if !user.IsVerified {
		return nil, s.createGrpcError(codes.Unauthenticated, "This admin account requires verification", customerrors.ERR_ADMIN_LOGIN_NOT_VERIFIED, nil)
	}

	atoken, expiresIn, err := utils.GenerateJWT(user.ID, "ADMIN", s.jwtSecret, 1*24*time.Hour)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while generating your admin token", customerrors.ERR_ADMIN_LOGIN_TOKEN_FAILED, err)
	}

	return &authUserAdminService.LoginAdminResponse{
		AccessToken: atoken,
		ExpiresIn:   expiresIn,
		AdminID:     user.ID,
		Message:     "Admin login successful. Welcome back.",
	}, nil
}

// TokenRefresh refreshes an access token
func (s *AuthUserAdminService) TokenRefresh(ctx context.Context, req *authUserAdminService.TokenRefreshRequest) (*authUserAdminService.TokenRefreshResponse, error) {
	claims := &utils.Claims{}
	token, err := jwt.ParseWithClaims(req.RefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.jwtSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, s.createGrpcError(codes.Unauthenticated, "Your session has expired", customerrors.ERR_TOKEN_REFRESH_INVALID, err)
	}

	newToken, expiresIn, err := utils.GenerateJWT(claims.ID, claims.Role, s.jwtSecret, 1*24*time.Hour)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while refreshing your session", customerrors.ERR_TOKEN_REFRESH_FAILED, err)
	}

	return &authUserAdminService.TokenRefreshResponse{
		AccessToken: newToken,
		ExpiresIn:   expiresIn,
		UserID:      claims.ID,
	}, nil
}

// LogoutUser handles user logout (placeholder, as JWT is stateless)
func (s *AuthUserAdminService) LogoutUser(ctx context.Context, req *authUserAdminService.LogoutRequest) (*authUserAdminService.LogoutResponse, error) {
	errorType, err := s.repo.LogoutUser(req.UserID)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while logging out", errorType, err)
	}

	return &authUserAdminService.LogoutResponse{
		Message: "You have been logged out successfully.",
	}, nil
}

// ResendEmailVerification resends a verification OTP
func (s *AuthUserAdminService) ResendEmailVerification(ctx context.Context, req *authUserAdminService.ResendEmailVerificationRequest) (*authUserAdminService.ResendEmailVerificationResponse, error) {
	_, expiryAt, errorType, err := s.repo.ResendEmailVerification(req.Email)
	if err != nil {
		return nil, s.createGrpcError(codes.InvalidArgument, "Something went wrong while sending the verification email", errorType, err)
	}
	return &authUserAdminService.ResendEmailVerificationResponse{
		Message:  "A new verification email has been sent to your email address.",
		ExpiryAt: expiryAt,
	}, nil
}

// VerifyUser verifies a user with an OTP
func (s *AuthUserAdminService) VerifyUser(ctx context.Context, req *authUserAdminService.VerifyUserRequest) (*authUserAdminService.VerifyUserResponse, error) {
	verified, errorType, err := s.repo.VerifyUserToken(req.Email, req.Token)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while verifying the user", errorType, err)
	}
	if !verified {
		return nil, s.createGrpcError(codes.InvalidArgument, "The verification code is invalid or has expired", customerrors.ERR_VERIFY_TOKEN_INVALID, nil)
	}
	return &authUserAdminService.VerifyUserResponse{
		Message: "Your account has been successfully verified. You may now log in.",
	}, nil
}

// ForgotPassword initiates password recovery
func (s *AuthUserAdminService) ForgotPassword(ctx context.Context, req *authUserAdminService.ForgotPasswordRequest) (*authUserAdminService.ForgotPasswordResponse, error) {
	if !repository.IsValidEmail(req.Email) {
		return nil, s.createGrpcError(codes.InvalidArgument, "Please provide a valid email address", customerrors.ERR_PW_FORGOT_INVALID_EMAIL, nil)
	}

	token := uuid.New().String()
	_, errorType, err := s.repo.CreateForgotPasswordToken(req.Email, token)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while initiating password recovery", errorType, err)
	}

	return &authUserAdminService.ForgotPasswordResponse{
		Message: "Password recovery instructions have been sent to your email.",
		Token:   token,
	}, nil
}

// FinishForgotPassword completes the password reset process
func (s *AuthUserAdminService) FinishForgotPassword(ctx context.Context, req *authUserAdminService.FinishForgotPasswordRequest) (*authUserAdminService.FinishForgotPasswordResponse, error) {
	if req.NewPassword != req.ConfirmPassword {
		return nil, s.createGrpcError(codes.InvalidArgument, "The new passwords do not match", customerrors.ERR_PW_RESET_MISMATCH, nil)
	}
	if !repository.IsValidPassword(req.NewPassword) {
		return nil, s.createGrpcError(codes.InvalidArgument, "Password must be at least 8 characters and include an uppercase letter and a number", customerrors.ERR_PW_RESET_INVALID_PASSWORD, nil)
	}

	errorType, err := s.repo.FinishForgotPassword(req.Email, req.Token, req.NewPassword)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while resetting the password", errorType, err)
	}

	return &authUserAdminService.FinishForgotPasswordResponse{
		Message: "Your password has been reset successfully.",
	}, nil
}

// ChangePassword allows authenticated users to change their password
func (s *AuthUserAdminService) ChangePassword(ctx context.Context, req *authUserAdminService.ChangePasswordRequest) (*authUserAdminService.ChangePasswordResponse, error) {
	if req.NewPassword != req.ConfirmPassword {
		return nil, s.createGrpcError(codes.InvalidArgument, "The new passwords do not match", customerrors.ERR_PW_CHANGE_MISMATCH, nil)
	}
	if !repository.IsValidPassword(req.NewPassword) {
		return nil, s.createGrpcError(codes.InvalidArgument, "Password must be at least 8 characters and include an uppercase letter and a number", customerrors.ERR_PW_CHANGE_INVALID_PASSWORD, nil)
	}

	errorType, err := s.repo.ChangeAuthenticatedPassword(req.UserID, req.OldPassword, req.NewPassword)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while changing the password", errorType, err)
	}

	return &authUserAdminService.ChangePasswordResponse{
		Message: "Your password has been updated successfully.",
	}, nil
}

// UpdateProfile updates user profile
func (s *AuthUserAdminService) UpdateProfile(ctx context.Context, req *authUserAdminService.UpdateProfileRequest) (*authUserAdminService.UpdateProfileResponse, error) {
	errorType, err := s.repo.UpdateProfile(req)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while updating your profile", errorType, err)
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
	errorType, err := s.repo.UpdateProfileImage(req)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while updating your profile image", errorType, err)
	}
	return &authUserAdminService.UpdateProfileImageResponse{
		Message:   "Your profile image has been updated successfully.",
		AvatarURL: req.AvatarURL,
	}, nil
}

// GetUserProfile retrieves a user's profile
func (s *AuthUserAdminService) GetUserProfile(ctx context.Context, req *authUserAdminService.GetUserProfileRequest) (*authUserAdminService.GetUserProfileResponse, error) {
	resp, errorType, err := s.repo.GetUserProfile(req.UserID)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while retrieving the user profile", errorType, err)
	}
	return resp, nil
}

// CheckBanStatus checks if a user is banned
func (s *AuthUserAdminService) CheckBanStatus(ctx context.Context, req *authUserAdminService.CheckBanStatusRequest) (*authUserAdminService.CheckBanStatusResponse, error) {
	resp, errorType, err := s.repo.CheckBanStatus(req.UserID)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while checking ban status", errorType, err)
	}
	if resp == nil {
		return nil, s.createGrpcError(codes.NotFound, "The specified user could not be found", customerrors.ERR_BAN_STATUS_NOT_FOUND, nil)
	}
	return resp, nil
}

// FollowUser adds a follow relationship
func (s *AuthUserAdminService) FollowUser(ctx context.Context, req *authUserAdminService.FollowUserRequest) (*authUserAdminService.FollowUserResponse, error) {
	errorType, err := s.repo.FollowUser(req.FollowerID, req.FolloweeID)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while following the user", errorType, err)
	}
	return &authUserAdminService.FollowUserResponse{
		Message: "You are now following this user.",
	}, nil
}

// UnfollowUser removes a follow relationship
func (s *AuthUserAdminService) UnfollowUser(ctx context.Context, req *authUserAdminService.UnfollowUserRequest) (*authUserAdminService.UnfollowUserResponse, error) {
	errorType, err := s.repo.UnfollowUser(req.FollowerID, req.FolloweeID)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while unfollowing the user", errorType, err)
	}
	return &authUserAdminService.UnfollowUserResponse{
		Message: "You have unfollowed this user.",
	}, nil
}

// GetFollowing retrieves users a given user is following
func (s *AuthUserAdminService) GetFollowing(ctx context.Context, req *authUserAdminService.GetFollowingRequest) (*authUserAdminService.GetFollowingResponse, error) {
	profiles, errorType, err := s.repo.GetFollowing(req.UserID)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while retrieving followed users", errorType, err)
	}
	return &authUserAdminService.GetFollowingResponse{
		Users: profiles,
	}, nil
}

// GetFollowers retrieves users following a given user
func (s *AuthUserAdminService) GetFollowers(ctx context.Context, req *authUserAdminService.GetFollowersRequest) (*authUserAdminService.GetFollowersResponse, error) {
	profiles, errorType, err := s.repo.GetFollowers(req.UserID)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while retrieving followers", errorType, err)
	}
	return &authUserAdminService.GetFollowersResponse{
		Users: profiles,
	}, nil
}

// CreateUserAdmin creates a new admin user
func (s *AuthUserAdminService) CreateUserAdmin(ctx context.Context, req *authUserAdminService.CreateUserAdminRequest) (*authUserAdminService.CreateUserAdminResponse, error) {
	if req.Password != req.ConfirmPassword {
		return nil, s.createGrpcError(codes.InvalidArgument, "The passwords entered do not match", customerrors.ERR_ADMIN_CREATE_PASSWORD_MISMATCH, nil)
	}
	if !repository.IsValidEmail(req.Email) {
		return nil, s.createGrpcError(codes.InvalidArgument, "Please provide a valid email address", customerrors.ERR_ADMIN_CREATE_INVALID_EMAIL, nil)
	}
	if !repository.IsValidPassword(req.Password) {
		return nil, s.createGrpcError(codes.InvalidArgument, "Password must be at least 8 characters and include an uppercase letter and a number", customerrors.ERR_ADMIN_CREATE_INVALID_PASSWORD, nil)
	}

	userID, errorType, err := s.repo.CreateUserAdmin(req)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while creating the admin account", errorType, err)
	}
	return &authUserAdminService.CreateUserAdminResponse{
		UserID:  userID,
		Message: "The admin account has been created successfully.",
	}, nil
}

// UpdateUserAdmin updates an admin user
func (s *AuthUserAdminService) UpdateUserAdmin(ctx context.Context, req *authUserAdminService.UpdateUserAdminRequest) (*authUserAdminService.UpdateUserAdminResponse, error) {
	isAdmin, errorType, err := s.repo.IsAdmin(req.UserID)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while verifying admin status", errorType, err)
	}
	if !isAdmin {
		return nil, s.createGrpcError(codes.PermissionDenied, "Administrative privileges are required to perform this action", customerrors.ERR_ADMIN_UPDATE_NO_PRIVILEGES, nil)
	}

	if req.Password != "" {
		if !repository.IsValidPassword(req.Password) {
			return nil, s.createGrpcError(codes.InvalidArgument, "Password must be at least 8 characters and include an uppercase letter and a number", customerrors.ERR_ADMIN_UPDATE_INVALID_PASSWORD, nil)
		}
	}

	errorType, err = s.repo.UpdateUserAdmin(req)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while updating the admin account", errorType, err)
	}
	return &authUserAdminService.UpdateUserAdminResponse{
		Message: "The admin account has been updated successfully.",
	}, nil
}

// BanUser sets a user as banned
func (s *AuthUserAdminService) BanUser(ctx context.Context, req *authUserAdminService.BanUserRequest) (*authUserAdminService.BanUserResponse, error) {
	errorType, err := s.repo.BanUser(req.UserID, req.BanReason, req.BanExpiry, req.BanType)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while banning the user", errorType, err)
	}
	return &authUserAdminService.BanUserResponse{
		Message: "The user has been banned successfully.",
	}, nil
}

// UnbanUser removes a user's ban
func (s *AuthUserAdminService) UnbanUser(ctx context.Context, req *authUserAdminService.UnbanUserRequest) (*authUserAdminService.UnbanUserResponse, error) {
	errorType, err := s.repo.UnbanUser(req.UserID)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while unbanning the user", errorType, err)
	}
	return &authUserAdminService.UnbanUserResponse{
		Message: "The user has been unbanned successfully.",
	}, nil
}

// VerifyAdminUser verifies a user (admin action)
func (s *AuthUserAdminService) VerifyAdminUser(ctx context.Context, req *authUserAdminService.VerifyAdminUserRequest) (*authUserAdminService.VerifyAdminUserResponse, error) {
	errorType, err := s.repo.VerifyAdminUser(req.UserID)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while verifying the user", errorType, err)
	}
	return &authUserAdminService.VerifyAdminUserResponse{
		Message: "The user has been verified successfully.",
	}, nil
}

// UnverifyUser un-verifies a user (admin action)
func (s *AuthUserAdminService) UnverifyUser(ctx context.Context, req *authUserAdminService.UnverifyUserAdminRequest) (*authUserAdminService.UnverifyUserAdminResponse, error) {
	errorType, err := s.repo.UnverifyUser(req.UserID)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while unverifying the user", errorType, err)
	}
	return &authUserAdminService.UnverifyUserAdminResponse{
		Message: "The user’s verification has been removed successfully.",
	}, nil
}

// SoftDeleteUserAdmin soft deletes a user
func (s *AuthUserAdminService) SoftDeleteUserAdmin(ctx context.Context, req *authUserAdminService.SoftDeleteUserAdminRequest) (*authUserAdminService.SoftDeleteUserAdminResponse, error) {
	isAdmin, errorType, err := s.repo.IsAdmin(req.UserID)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while verifying admin status", errorType, err)
	}
	if !isAdmin {
		return nil, s.createGrpcError(codes.PermissionDenied, "Administrative privileges are required to delete a user", customerrors.ERR_ADMIN_DELETE_NO_PRIVILEGES, nil)
	}

	errorType, err = s.repo.SoftDeleteUserAdmin(req.UserID)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while deleting the user", errorType, err)
	}
	return &authUserAdminService.SoftDeleteUserAdminResponse{
		Message: "The user has been soft-deleted successfully.",
	}, nil
}

// GetAllUsers retrieves a paginated list of users
func (s *AuthUserAdminService) GetAllUsers(ctx context.Context, req *authUserAdminService.GetAllUsersRequest) (*authUserAdminService.GetAllUsersResponse, error) {
	profiles, totalCount, errorType, err := s.repo.GetAllUsers(req)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while retrieving users", errorType, err)
	}
	return &authUserAdminService.GetAllUsersResponse{
		Users:      profiles,
		TotalCount: totalCount,
		Message:    "User list retrieved successfully.",
	}, nil
}

// BanHistory retrieves ban history for a user
func (s *AuthUserAdminService) BanHistory(ctx context.Context, req *authUserAdminService.BanHistoryRequest) (*authUserAdminService.BanHistoryResponse, error) {
	history, errorType, err := s.repo.GetBanHistory(req.UserID)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while retrieving ban history", errorType, err)
	}
	return &authUserAdminService.BanHistoryResponse{
		Bans:    history,
		Message: "Ban history retrieved successfully.",
	}, nil
}

// SearchUsers searches for users with pagination
func (s *AuthUserAdminService) SearchUsers(ctx context.Context, req *authUserAdminService.SearchUsersRequest) (*authUserAdminService.SearchUsersResponse, error) {
	users, nextPageToken, errorType, err := s.repo.SearchUsers(req.Query, req.PageToken, req.Limit)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while searching for users", errorType, err)
	}
	return &authUserAdminService.SearchUsersResponse{
		Users:         users,
		NextPageToken: nextPageToken,
		Message:       "User search completed successfully.",
	}, nil
}

// SetUpTwoFactorAuth enables 2FA for a user
func (s *AuthUserAdminService) SetUpTwoFactorAuth(ctx context.Context, req *authUserAdminService.SetUpTwoFactorAuthRequest) (*authUserAdminService.SetUpTwoFactorAuthResponse, error) {
	qrCodeImage, otpSecret, errorType, err := s.repo.SetUpTwoFactorAuth(req.UserID)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while setting up two factor authentication", errorType, err)
	}
	return &authUserAdminService.SetUpTwoFactorAuthResponse{
		Message: "Two factor authentication setup successfully",
		Image:   qrCodeImage,
		Secret:  otpSecret,
	}, nil
}

// DisableTwoFactorAuth disables 2FA for a user
func (s *AuthUserAdminService) DisableTwoFactorAuth(ctx context.Context, req *authUserAdminService.DisableTwoFactorAuthRequest) (*authUserAdminService.DisableTwoFactorAuthResponse, error) {
	valid, errorType, err := s.repo.CheckUserPassword(req.UserID, req.Password)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while checking user credentials", errorType, err)
	}
	if !valid {
		return nil, s.createGrpcError(codes.PermissionDenied, "The provided password is incorrect", customerrors.ERR_2FA_DISABLE_CRED_WRONG, nil)
	}

	errorType, err = s.repo.DisableTwoFactorAuth(req.UserID)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while disabling two factor authentication", errorType, err)
	}
	return &authUserAdminService.DisableTwoFactorAuthResponse{
		Message: "Two factor authentication has been disabled successfully",
	}, nil
}

// GetTwoFactorAuthStatus retrieves the 2FA status for a user
func (s *AuthUserAdminService) GetTwoFactorAuthStatus(ctx context.Context, req *authUserAdminService.GetTwoFactorAuthStatusRequest) (*authUserAdminService.GetTwoFactorAuthStatusResponse, error) {
	isEnabled, errorType, err := s.repo.GetTwoFactorAuthStatus(req.Email)
	if err != nil {
		return nil, s.createGrpcError(codes.Internal, "An error occurred while retrieving two factor authentication status", errorType, err)
	}
	return &authUserAdminService.GetTwoFactorAuthStatusResponse{
		IsEnabled: isEnabled,
	}, nil
}
