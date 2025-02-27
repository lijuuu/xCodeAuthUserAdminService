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

// extractUserIDFromContext extracts the user ID from the gRPC context (e.g., from JWT metadata)
// func (s *AuthUserAdminService) extractUserIDFromContext(ctx context.Context) (string, error) {
// 	md, ok := metadata.FromIncomingContext(ctx)
// 	if !ok || len(md["userID"]) == 0 {
// 		return "", status.Errorf(codes.Unauthenticated, "authorization token missing")
// 	}

// 	return md["userID"][0], nil
// }

// RegisterUser handles user registration and sends verification OTP
func (s *AuthUserAdminService) RegisterUser(ctx context.Context, req *authUserAdminService.RegisterUserRequest) (*authUserAdminService.RegisterUserResponse, error) {
	if req.Password != req.ConfirmPassword {
		return nil, status.Errorf(codes.InvalidArgument, "passwords do not match")
	}
	if !repository.IsValidEmail(req.Email) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid email format")
	}
	if !repository.IsValidPassword(req.Password) {
		return nil, status.Errorf(codes.InvalidArgument, "password must be at least 8 characters, include an uppercase letter, and a digit")
	}

	userID, err := s.repo.CreateUser(ctx, req)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to register user: %v", err)
	}

	return &authUserAdminService.RegisterUserResponse{
		UserID:  userID,
		Message: "User registered successfully. Please verify your email with the OTP sent.",
	}, nil
}

// LoginUser handles user login with JWT generation
func (s *AuthUserAdminService) LoginUser(ctx context.Context, req *authUserAdminService.LoginUserRequest) (*authUserAdminService.LoginUserResponse, error) {
	userID, _, role, isVerified, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve user: %v", err)
	}
	if userID == "" {
		return nil, status.Errorf(codes.NotFound, "user not found")
	}

	// if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password)); err != nil {
	// 	return nil, status.Errorf(codes.Unauthenticated, "invalid credentials: %v", err)
	// }

	valid, err := s.repo.CheckUserPassword(ctx, userID, req.Password)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check user password: %v", err)
	}
	if !valid {
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	if !isVerified {
		return nil, status.Errorf(codes.Unauthenticated, "user not verified")
	}

	token, expiresIn, err := utils.GenerateJWT(userID, role, s.jwtSecret, 30*24*time.Hour)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate token: %v", err)
	}

	return &authUserAdminService.LoginUserResponse{
		RefreshToken: token,
		ExpiresIn:    expiresIn,
		UserID:       userID,
		Message:      "Login successful",
	}, nil
}

// LoginAdmin handles admin login with JWT generation
func (s *AuthUserAdminService) LoginAdmin(ctx context.Context, req *authUserAdminService.LoginAdminRequest) (*authUserAdminService.LoginAdminResponse, error) {
	userID, hashedPassword, role, isVerified, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve user: %v", err)
	}
	if userID == "" {
		return nil, status.Errorf(codes.NotFound, "admin not found")
	}
	if role != "ADMIN" {
		return nil, status.Errorf(codes.Unauthenticated, "not an admin user")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password)); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials: %v", err)
	}

	if !isVerified {
		return nil, status.Errorf(codes.Unauthenticated, "admin not verified")
	}

	token, expiresIn, err := utils.GenerateJWT(userID, role, s.jwtSecret, 30*24*time.Hour)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate token: %v", err)
	}

	return &authUserAdminService.LoginAdminResponse{
		RefreshToken: token,
		ExpiresIn:    expiresIn,
		AdminID:      userID,
		Message:      "Admin login successful",
	}, nil
}

// TokenRefresh refreshes an access token
func (s *AuthUserAdminService) TokenRefresh(ctx context.Context, req *authUserAdminService.TokenRefreshRequest) (*authUserAdminService.TokenRefreshResponse, error) {
	claims := &utils.Claims{}
	token, err := jwt.ParseWithClaims(req.RefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.jwtSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, status.Errorf(codes.Unauthenticated, "invalid refresh token: %v", err)
	}

	newToken, expiresIn, err := utils.GenerateJWT(claims.ID, claims.Role, s.jwtSecret, 7*24*time.Hour)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate token: %v", err)
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
		Message: "User logged out successfully",
	}, nil
}

// ResendOTP resends a verification OTP
func (s *AuthUserAdminService) ResendOTP(ctx context.Context, req *authUserAdminService.ResendOTPRequest) (*authUserAdminService.ResendOTPResponse, error) {
	_, err := s.repo.ResendOTP(ctx, req.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to resend OTP: %v", err)
	}
	return &authUserAdminService.ResendOTPResponse{
		Message: "OTP resent successfully",
	}, nil
}

// VerifyUser verifies a user with an OTP
func (s *AuthUserAdminService) VerifyUser(ctx context.Context, req *authUserAdminService.VerifyUserRequest) (*authUserAdminService.VerifyUserResponse, error) {
	verified, err := s.repo.VerifyUserToken(ctx, req.Email, req.Token)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to verify user: %v", err)
	}
	if !verified {
		return nil, status.Errorf(codes.InvalidArgument, "invalid or expired verification token")
	}
	return &authUserAdminService.VerifyUserResponse{
		Message: "User verified successfully",
	}, nil
}

// SetTwoFactorAuth enables/disables 2FA
func (s *AuthUserAdminService) ToggleTwoFactorAuth(ctx context.Context, req *authUserAdminService.ToggleTwoFactorAuthRequest) (*authUserAdminService.ToggleTwoFactorAuthResponse, error) {

	// Check if user exists
	_, err := s.repo.GetUserProfile(ctx, req.UserID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "user not found: %v", err)
	}

	// if err := bcrypt.CompareHashAndPassword([]byte(usr.), []byte(req.Password)); err != nil {
	// 	return nil, status.Errorf(codes.Unauthenticated, "invalid credentials: %v", err)
	// }

	valid, err := s.repo.CheckUserPassword(ctx, req.UserID, req.Password)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check user password: %v", err)
	}
	if !valid {
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	err = s.repo.Update2FAStatus(ctx, req.UserID, req.TwoFactorAuth)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update 2FA status: %v", err)
	}

	return &authUserAdminService.ToggleTwoFactorAuthResponse{
		Message: fmt.Sprintf("2FA has been %s successfully", map[bool]string{true: "enabled", false: "disabled"}[req.TwoFactorAuth]),
	}, nil
}

// ForgotPassword initiates password recovery
func (s *AuthUserAdminService) ForgotPassword(ctx context.Context, req *authUserAdminService.ForgotPasswordRequest) (*authUserAdminService.ForgotPasswordResponse, error) {
	if !repository.IsValidEmail(req.Email) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid email format")
	}

	// Generate a unique token
	token := uuid.New().String()
	_, err := s.repo.CreateForgotPasswordToken(ctx, req.Email, token)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to initiate password recovery: %v", err)
	}

	return &authUserAdminService.ForgotPasswordResponse{
		Message: "Password recovery initiated. Check your email for reset instructions.",
		Token:   token, // Return the token for the reset link
	}, nil
}

// FinishForgotPassword completes the password reset process
func (s *AuthUserAdminService) FinishForgotPassword(ctx context.Context, req *authUserAdminService.FinishForgotPasswordRequest) (*authUserAdminService.FinishForgotPasswordResponse, error) {
	if req.NewPassword != req.ConfirmPassword {
		return nil, status.Errorf(codes.InvalidArgument, "passwords do not match")
	}
	if !repository.IsValidPassword(req.NewPassword) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid password format: must be at least 8 characters, include an uppercase letter, and a digit")
	}

	err := s.repo.FinishForgotPassword(ctx, req.UserID, req.Token, req.NewPassword)
	if err != nil {
		return nil, err
	}

	return &authUserAdminService.FinishForgotPasswordResponse{
		Message: "Password reset successfully",
	}, nil
}

// ChangePassword allows authenticated users to change their password
func (s *AuthUserAdminService) ChangePassword(ctx context.Context, req *authUserAdminService.ChangePasswordRequest) (*authUserAdminService.ChangePasswordResponse, error) {
	if req.NewPassword != req.ConfirmPassword {
		return nil, status.Errorf(codes.InvalidArgument, "passwords do not match")
	}
	if !repository.IsValidPassword(req.NewPassword) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid password format: must be at least 8 characters, include an uppercase letter, and a digit")
	}

	err := s.repo.ChangeAuthenticatedPassword(ctx, req.UserID, req.OldPassword, req.NewPassword)
	if err != nil {
		return nil, err
	}

	return &authUserAdminService.ChangePasswordResponse{
		Message: "Password changed successfully",
	}, nil
}

// UpdateProfile updates user profile
func (s *AuthUserAdminService) UpdateProfile(ctx context.Context, req *authUserAdminService.UpdateProfileRequest) (*authUserAdminService.UpdateProfileResponse, error) {

	err := s.repo.UpdateProfile(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update profile: %v", err)
	}
	return &authUserAdminService.UpdateProfileResponse{
		Message: "Profile updated successfully",
	}, nil
}

// UpdateProfileImage updates the user's profile image
func (s *AuthUserAdminService) UpdateProfileImage(ctx context.Context, req *authUserAdminService.UpdateProfileImageRequest) (*authUserAdminService.UpdateProfileImageResponse, error) {
	err := s.repo.UpdateProfileImage(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update profile image: %v", err)
	}
	return &authUserAdminService.UpdateProfileImageResponse{
		Message:   "Profile image updated successfully",
		AvatarURL: req.AvatarURL,
	}, nil
}

// GetUserProfile retrieves a user's profile
func (s *AuthUserAdminService) GetUserProfile(ctx context.Context, req *authUserAdminService.GetUserProfileRequest) (*authUserAdminService.GetUserProfileResponse, error) {
	resp, err := s.repo.GetUserProfile(ctx, req.UserID)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// CheckBanStatus checks if a user is banned
func (s *AuthUserAdminService) CheckBanStatus(ctx context.Context, req *authUserAdminService.CheckBanStatusRequest) (*authUserAdminService.CheckBanStatusResponse, error) {
	resp, err := s.repo.CheckBanStatus(ctx, req.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check ban status: %v", err)
	}
	if resp == nil {
		return nil, status.Errorf(codes.NotFound, "user not found")
	}
	return resp, nil
}

// FollowUser adds a follow relationship
func (s *AuthUserAdminService) FollowUser(ctx context.Context, req *authUserAdminService.FollowUserRequest) (*authUserAdminService.FollowUserResponse, error) {
	err := s.repo.FollowUser(ctx, req.FollowerID, req.FolloweeID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to follow user: %v", err)
	}
	return &authUserAdminService.FollowUserResponse{
		Message: "User followed successfully",
	}, nil
}

// UnfollowUser removes a follow relationship
func (s *AuthUserAdminService) UnfollowUser(ctx context.Context, req *authUserAdminService.UnfollowUserRequest) (*authUserAdminService.UnfollowUserResponse, error) {
	err := s.repo.UnfollowUser(ctx, req.FollowerID, req.FolloweeID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unfollow user: %v", err)
	}
	return &authUserAdminService.UnfollowUserResponse{
		Message: "User unfollowed successfully",
	}, nil
}

// GetFollowing retrieves users a given user is following
func (s *AuthUserAdminService) GetFollowing(ctx context.Context, req *authUserAdminService.GetFollowingRequest) (*authUserAdminService.GetFollowingResponse, error) {
	profiles, err := s.repo.GetFollowing(ctx, req.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get following: %v", err)
	}
	return &authUserAdminService.GetFollowingResponse{
		Users: profiles,
	}, nil
}

// GetFollowers retrieves users following a given user
func (s *AuthUserAdminService) GetFollowers(ctx context.Context, req *authUserAdminService.GetFollowersRequest) (*authUserAdminService.GetFollowersResponse, error) {
	profiles, err := s.repo.GetFollowers(ctx, req.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get followers: %v", err)
	}
	return &authUserAdminService.GetFollowersResponse{
		Users: profiles,
	}, nil
}

// CreateUserAdmin creates a new admin user
func (s *AuthUserAdminService) CreateUserAdmin(ctx context.Context, req *authUserAdminService.CreateUserAdminRequest) (*authUserAdminService.CreateUserAdminResponse, error) {
	if req.Password != req.ConfirmPassword {
		return nil, status.Errorf(codes.InvalidArgument, "passwords do not match")
	}
	if !repository.IsValidEmail(req.Email) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid email format")
	}
	if !repository.IsValidPassword(req.Password) {
		return nil, status.Errorf(codes.InvalidArgument, "password must be at least 8 characters, include an uppercase letter, and a digit")
	}

	userID, err := s.repo.CreateUserAdmin(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create admin user: %v", err)
	}
	return &authUserAdminService.CreateUserAdminResponse{
		UserID:  userID,
		Message: "Admin user created successfully",
	}, nil
}

// UpdateUserAdmin updates an admin user
func (s *AuthUserAdminService) UpdateUserAdmin(ctx context.Context, req *authUserAdminService.UpdateUserAdminRequest) (*authUserAdminService.UpdateUserAdminResponse, error) {
	isAdmin, err := s.repo.IsAdmin(ctx, req.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check admin status: %v", err)
	}
	if !isAdmin {
		return nil, status.Errorf(codes.PermissionDenied, "admin privileges required")
	}

	if req.Password != "" {
		if !repository.IsValidPassword(req.Password) {
			return nil, status.Errorf(codes.InvalidArgument, "invalid password format: must be at least 8 characters, include an uppercase letter, and a digit")
		}
	}

	err = s.repo.UpdateUserAdmin(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update admin user: %v", err)
	}
	return &authUserAdminService.UpdateUserAdminResponse{
		Message: "Admin user updated successfully",
	}, nil
}

// BlockUser sets a user as banned
func (s *AuthUserAdminService) BanUser(ctx context.Context, req *authUserAdminService.BanUserRequest) (*authUserAdminService.BanUserResponse, error) {
	isAdmin, err := s.repo.IsAdmin(ctx, req.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check admin status: %v", err)
	}
	if !isAdmin {
		return nil, status.Errorf(codes.PermissionDenied, "admin privileges required")
	}

	err = s.repo.BanUser(ctx, req.UserID, req.BanReason, req.BanExpiry, req.BanType)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to ban user: %v", err)
	}
	return &authUserAdminService.BanUserResponse{
		Message: "User banned successfully",
	}, nil
}

// UnblockUser removes a user's ban
func (s *AuthUserAdminService) UnbanUser(ctx context.Context, req *authUserAdminService.UnbanUserRequest) (*authUserAdminService.UnbanUserResponse, error) {
	isAdmin, err := s.repo.IsAdmin(ctx, req.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check admin status: %v", err)
	}
	if !isAdmin {
		return nil, status.Errorf(codes.PermissionDenied, "admin privileges required")
	}

	err = s.repo.UnbanUser(ctx, req.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unban user: %v", err)
	}
	return &authUserAdminService.UnbanUserResponse{
		Message: "User unbanned successfully",
	}, nil
}

// VerifyAdminUser verifies a user (admin action)
func (s *AuthUserAdminService) VerifyAdminUser(ctx context.Context, req *authUserAdminService.VerifyAdminUserRequest) (*authUserAdminService.VerifyAdminUserResponse, error) {
	isAdmin, err := s.repo.IsAdmin(ctx, req.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check admin status: %v", err)
	}
	if !isAdmin {
		return nil, status.Errorf(codes.PermissionDenied, "admin privileges required")
	}

	err = s.repo.VerifyAdminUser(ctx, req.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to verify user: %v", err)
	}
	return &authUserAdminService.VerifyAdminUserResponse{
		Message: "User verified successfully",
	}, nil
}

// UnverifyUser un-verifies a user (admin action)
func (s *AuthUserAdminService) UnverifyUser(ctx context.Context, req *authUserAdminService.UnverifyUserAdminRequest) (*authUserAdminService.UnverifyUserAdminResponse, error) {
	isAdmin, err := s.repo.IsAdmin(ctx, req.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check admin status: %v", err)
	}
	if !isAdmin {
		return nil, status.Errorf(codes.PermissionDenied, "admin privileges required")
	}

	err = s.repo.UnverifyUser(ctx, req.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unverify user: %v", err)
	}
	return &authUserAdminService.UnverifyUserAdminResponse{
		Message: "User unverified successfully",
	}, nil
}

// SoftDeleteUserAdmin soft deletes a user
func (s *AuthUserAdminService) SoftDeleteUserAdmin(ctx context.Context, req *authUserAdminService.SoftDeleteUserAdminRequest) (*authUserAdminService.SoftDeleteUserAdminResponse, error) {
	isAdmin, err := s.repo.IsAdmin(ctx, req.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check admin status: %v", err)
	}
	if !isAdmin {
		return nil, status.Errorf(codes.PermissionDenied, "admin privileges required")
	}

	err = s.repo.SoftDeleteUserAdmin(ctx, req.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to soft delete user: %v", err)
	}
	return &authUserAdminService.SoftDeleteUserAdminResponse{
		Message: "User soft deleted successfully",
	}, nil
}

// GetAllUsers retrieves a paginated list of users
func (s *AuthUserAdminService) GetAllUsers(ctx context.Context, req *authUserAdminService.GetAllUsersRequest) (*authUserAdminService.GetAllUsersResponse, error) {

	profiles, totalCount, err := s.repo.GetAllUsers(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get users: %v", err)
	}
	return &authUserAdminService.GetAllUsersResponse{
		Users:      profiles,
		TotalCount: totalCount,
		Message:    "Users retrieved successfully",
	}, nil
}


func (s *AuthUserAdminService)BanHistory(ctx context.Context, req *authUserAdminService.BanHistoryRequest) (*authUserAdminService.BanHistoryResponse, error) {
	
	history, err := s.repo.GetBanHistory(ctx, req.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get ban history: %v", err)
	}
	return &authUserAdminService.BanHistoryResponse{
		Bans: history,
		Message: "Ban history retrieved successfully",
	}, nil
}

func (s *AuthUserAdminService)SearchUsers(ctx context.Context, req *authUserAdminService.SearchUsersRequest) (*authUserAdminService.SearchUsersResponse, error) {
	
	users, err := s.repo.SearchUsers(ctx, req.Query)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to search users: %v", err)
	}
	return &authUserAdminService.SearchUsersResponse{
		Users: users,
		Message: "Users searched successfully",
	}, nil
}

