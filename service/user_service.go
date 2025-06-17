package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"xcode/cache"
	"xcode/db"
	"xcode/repository"
	"xcode/utils"

	configs "xcode/configs"
	"xcode/customerrors"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	zap_betterstack "xcode/logger"

	"go.uber.org/zap/zapcore"

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
	cache     cache.RedisCache
	logger    *zap_betterstack.BetterStackLogStreamer
	config    *configs.Config
	jwtSecret string
	googleCfg *oauth2.Config
	authUserAdminService.UnimplementedAuthUserAdminServiceServer
}

// NewAuthUserAdminService initializes and returns a new AuthUserAdminService
func NewAuthUserAdminService(repo *repository.UserRepository, cache cache.RedisCache, config *configs.Config, jwtSecret string, logger *zap_betterstack.BetterStackLogStreamer) *AuthUserAdminService {
	googleCfg := &oauth2.Config{
		ClientID:     config.GoogleClientID,
		ClientSecret: config.GoogleClientSecret,
		RedirectURL:  config.GoogleRedirectURL,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}
	return &AuthUserAdminService{
		repo:      repo,
		cache:     cache,
		config:    config,
		logger:    logger,
		jwtSecret: jwtSecret,
		googleCfg: googleCfg,
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
	errorMessage := fmt.Sprintf("ErrorType: %s, Code: %d, Details: %s", errorType, code, details)
	return status.Error(code, errorMessage)
}

// RegisterUser handles user registration and sends verification OTP
func (s *AuthUserAdminService) RegisterUser(ctx context.Context, req *authUserAdminService.RegisterUserRequest) (*authUserAdminService.RegisterUserResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting RegisterUser", map[string]any{
		"method":    "RegisterUser",
		"email":     req.Email,
		"operation": "create_user",
	}, "SERVICE", nil)

	if req.Password != req.ConfirmPassword {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Password mismatch", map[string]any{
			"method":    "RegisterUser",
			"email":     req.Email,
			"errorType": customerrors.ERR_REG_PASSWORD_MISMATCH,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.InvalidArgument, "The passwords entered do not match", customerrors.ERR_REG_PASSWORD_MISMATCH, nil)
	}
	if !repository.IsValidEmail(req.Email) {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Invalid email", map[string]any{
			"method":    "RegisterUser",
			"email":     req.Email,
			"errorType": customerrors.ERR_REG_INVALID_EMAIL,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.InvalidArgument, "Please provide a valid email address", customerrors.ERR_REG_INVALID_EMAIL, nil)
	}
	if !repository.IsValidPassword(req.Password) {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Invalid password format", map[string]any{
			"method":    "RegisterUser",
			"email":     req.Email,
			"errorType": customerrors.ERR_REG_INVALID_PASSWORD,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.InvalidArgument, "Password must be at least 8 characters and include an uppercase letter and a number", customerrors.ERR_REG_INVALID_PASSWORD, nil)
	}

	userID, errorType, err := s.repo.CreateUser(req)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to create user", map[string]any{
			"method":    "RegisterUser",
			"email":     req.Email,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while creating your account", errorType, err)
	}

	// Invalidate non-admin caches for new user
	cacheKeys := []string{
		fmt.Sprintf("user_profile:id:%s", userID),
		fmt.Sprintf("ban_status:%s", userID),
		fmt.Sprintf("following:%s", userID),
		fmt.Sprintf("followers:%s", userID),
	}
	for _, key := range cacheKeys {
		if err := s.cache.Delete(key); err != nil {
			// Skip logging cache deletion failures to avoid flooding
		}
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "User registered successfully", map[string]any{
		"method": "RegisterUser",
		"userID": userID,
		"email":  req.Email,
	}, "SERVICE", nil)

	return &authUserAdminService.RegisterUserResponse{
		UserID: userID,
		UserProfile: &authUserAdminService.UserProfile{
			UserID:    userID,
			FirstName: req.FirstName,
			LastName:  req.LastName,
			Email:     req.Email,
			Country:   strings.ToUpper(req.Country),
		},
		Message: "Your account has been created successfully. Please verify your email.",
	}, nil
}

// LoginWithGoogle handles Google OAuth login
func (s *AuthUserAdminService) LoginWithGoogle(ctx context.Context, req *authUserAdminService.GoogleLoginRequest) (*authUserAdminService.LoginUserResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting LoginWithGoogle", map[string]any{
		"method":    "LoginWithGoogle",
		"operation": "google_login",
	}, "SERVICE", nil)

	token, err := s.googleCfg.Client(ctx, &oauth2.Token{AccessToken: req.IdToken}).Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Invalid Google token", map[string]any{
			"method":    "LoginWithGoogle",
			"errorType": customerrors.ERR_GOOGLE_TOKEN_INVALID,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.InvalidArgument, "Invalid Google token", customerrors.ERR_GOOGLE_TOKEN_INVALID, err)
	}
	defer token.Body.Close()

	var googleUser struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := json.NewDecoder(token.Body).Decode(&googleUser); err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to parse Google user info", map[string]any{
			"method":    "LoginWithGoogle",
			"errorType": customerrors.ERR_GOOGLE_TOKEN_INVALID,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.Internal, "Failed to parse Google user info", customerrors.ERR_GOOGLE_TOKEN_INVALID, err)
	}

	user, errorType, err := s.repo.GetUserByEmail(googleUser.Email)
	if err != nil && errorType != "" {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Error retrieving user", map[string]any{
			"method":    "LoginWithGoogle",
			"email":     googleUser.Email,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "Error retrieving user", errorType, err)
	}

	if user.ID != "" {
		if user.AuthType != "google" {
			s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Login method conflict", map[string]any{
				"method":    "LoginWithGoogle",
				"email":     googleUser.Email,
				"errorType": customerrors.ERR_LOGIN_METHOD_CONFLICT,
			}, "SERVICE", nil)
			return nil, s.createGrpcError(codes.AlreadyExists, "Account exists with different login method. Please use email or other methods.", customerrors.ERR_LOGIN_METHOD_CONFLICT, nil)
		}
		banStatusResp, errorType, err := s.repo.CheckBanStatus(user.ID)
		if err != nil {
			s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Error checking ban status", map[string]any{
				"method":    "LoginWithGoogle",
				"userID":    user.ID,
				"errorType": errorType,
			}, "SERVICE", err)
			return nil, s.createGrpcError(codes.Internal, "Error checking ban status", errorType, err)
		}
		if banStatusResp.IsBanned {
			s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Account banned", map[string]any{
				"method":    "LoginWithGoogle",
				"userID":    user.ID,
				"errorType": customerrors.ERR_LOGIN_ACCOUNT_BANNED,
			}, "SERVICE", nil)
			return nil, s.createGrpcError(codes.Unauthenticated, "Your account has been banned", customerrors.ERR_LOGIN_ACCOUNT_BANNED, nil)
		}
	} else {
		userId := uuid.New().String()
		registerReq := &db.User{
			ID:                userId,
			FirstName:         googleUser.GivenName,
			LastName:          googleUser.FamilyName,
			Email:             googleUser.Email,
			AuthType:          "google",
			Role:              "USER",
			PrimaryLanguageID: "js",
			Country:           "",
			MuteNotifications: false,
			TwoFactorEnabled:  false,
		}

		_, _, err := s.repo.CreateGoogleUser(registerReq)
		if err != nil {
			s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to create Google user", map[string]any{
				"method":    "LoginWithGoogle",
				"email":     googleUser.Email,
				"errorType": customerrors.ERR_REG_CREATION_FAILED,
			}, "SERVICE", err)
			return nil, s.createGrpcError(codes.Internal, "Failed to create user", customerrors.ERR_REG_CREATION_FAILED, err)
		}

		user, _, err = s.repo.GetUserByEmail(googleUser.Email)
		if err != nil {
			s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to retrieve newly created user", map[string]any{
				"method":    "LoginWithGoogle",
				"email":     googleUser.Email,
				"errorType": customerrors.ERR_REG_CREATION_FAILED,
			}, "SERVICE", err)
			return nil, s.createGrpcError(codes.Internal, "Failed to retrieve newly created user", customerrors.ERR_REG_CREATION_FAILED, err)
		}

		// Invalidate non-admin caches for new user
		cacheKeys := []string{
			fmt.Sprintf("user_profile:id:%s", user.ID),
			fmt.Sprintf("ban_status:%s", user.ID),
			fmt.Sprintf("following:%s", user.ID),
			fmt.Sprintf("followers:%s", user.ID),
		}
		for _, key := range cacheKeys {
			if err := s.cache.Delete(key); err != nil {
				// Skip logging cache deletion failures
			}
		}
	}

	rtoken, _, err := utils.GenerateJWT(user.ID, "USER", s.jwtSecret, 7*24*time.Hour)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to generate refresh token", map[string]any{
			"method":    "LoginWithGoogle",
			"userID":    user.ID,
			"errorType": customerrors.ERR_LOGIN_TOKEN_GEN_FAILED,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.Internal, "Failed to generate refresh token", customerrors.ERR_LOGIN_TOKEN_GEN_FAILED, err)
	}

	atoken, expiresIn, err := utils.GenerateJWT(user.ID, "USER", s.jwtSecret, 1*24*time.Hour)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to generate access token", map[string]any{
			"method":    "LoginWithGoogle",
			"userID":    user.ID,
			"errorType": customerrors.ERR_LOGIN_TOKEN_GEN_FAILED,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.Internal, "Failed to generate access token", customerrors.ERR_LOGIN_TOKEN_GEN_FAILED, err)
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Google login successful", map[string]any{
		"method": "LoginWithGoogle",
		"userID": user.ID,
		"email":  googleUser.Email,
	}, "SERVICE", nil)

	return &authUserAdminService.LoginUserResponse{
		UserProfile: &authUserAdminService.UserProfile{
			UserID:            user.ID,
			UserName:          user.UserName,
			FirstName:         user.FirstName,
			LastName:          user.LastName,
			Email:             user.Email,
			Role:              user.Role,
			PrimaryLanguageID: user.PrimaryLanguageID,
			Country:           user.Country,
			TwoFactorEnabled:  user.TwoFactorEnabled,
			AvatarData:        user.AvatarData,
			IsVerified:        user.IsVerified,
			Socials:           &authUserAdminService.Socials{},
			CreatedAt:         user.CreatedAt,
		},
		RefreshToken: rtoken,
		AccessToken:  atoken,
		ExpiresIn:    expiresIn,
		UserID:       user.ID,
		Message:      "Login with Google successful",
	}, nil
}

// LoginUser handles user login with JWT generation
func (s *AuthUserAdminService) LoginUser(ctx context.Context, req *authUserAdminService.LoginUserRequest) (*authUserAdminService.LoginUserResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting LoginUser", map[string]any{
		"method":    "LoginUser",
		"email":     req.Email,
		"operation": "email_login",
	}, "SERVICE", nil)

	user, errorType, err := s.repo.GetUserByEmail(req.Email)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Error retrieving user", map[string]any{
			"method":    "LoginUser",
			"email":     req.Email,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while verifying your credentials", errorType, err)
	}
	if user.ID == "" {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "User not found", map[string]any{
			"method":    "LoginUser",
			"email":     req.Email,
			"errorType": customerrors.ERR_USER_NOT_FOUND,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.NotFound, "No account exists with this email address", customerrors.ERR_USER_NOT_FOUND, nil)
	}

	if user.AuthType != "email" {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Login method conflict", map[string]any{
			"method":    "LoginUser",
			"email":     req.Email,
			"errorType": customerrors.ERR_LOGIN_METHOD_CONFLICT,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.AlreadyExists, "Account exists with different login method. Please use Google or other methods.", customerrors.ERR_LOGIN_METHOD_CONFLICT, nil)
	}

	banStatusResp, errorType, err := s.repo.CheckBanStatus(user.ID)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Error checking ban status", map[string]any{
			"method":    "LoginUser",
			"userID":    user.ID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while checking your ban status", errorType, err)
	}
	if banStatusResp.IsBanned {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Account banned", map[string]any{
			"method":    "LoginUser",
			"userID":    user.ID,
			"errorType": customerrors.ERR_LOGIN_ACCOUNT_BANNED,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.Unauthenticated, "Your account has been banned", customerrors.ERR_LOGIN_ACCOUNT_BANNED, nil)
	}

	valid, errorType, err := s.repo.CheckUserPassword(user.ID, req.Password)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Error verifying password", map[string]any{
			"method":    "LoginUser",
			"userID":    user.ID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while verifying your password", errorType, err)
	}
	if !valid {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Incorrect password", map[string]any{
			"method":    "LoginUser",
			"userID":    user.ID,
			"errorType": customerrors.ERR_LOGIN_CRED_WRONG,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.InvalidArgument, "The password provided is incorrect", customerrors.ERR_LOGIN_CRED_WRONG, nil)
	}

	if !user.IsVerified {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Email not verified", map[string]any{
			"method":    "LoginUser",
			"userID":    user.ID,
			"errorType": customerrors.ERR_LOGIN_NOT_VERIFIED,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.Unauthenticated, "Your email address requires verification", customerrors.ERR_LOGIN_NOT_VERIFIED, nil)
	}

	isEnabled, errorType, err := s.repo.GetTwoFactorAuthStatus(req.Email)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Error checking 2FA status", map[string]any{
			"method":    "LoginUser",
			"email":     req.Email,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while checking 2FA status", errorType, err)
	}

	if isEnabled {
		valid, errorType, err := s.repo.ValidateTwoFactorAuth(user.ID, req.TwoFactorCode)
		if err != nil {
			s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Error verifying 2FA OTP", map[string]any{
				"method":    "LoginUser",
				"email":     req.Email,
				"errorType": errorType,
			}, "SERVICE", err)
			return nil, s.createGrpcError(codes.NotFound, "An error occurred while verifying OTP", errorType, err)
		}
		if !valid {
			s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Invalid 2FA code", map[string]any{
				"method":    "LoginUser",
				"email":     req.Email,
				"errorType": customerrors.ERR_LOGIN_2FA_CODE_INVALID,
			}, "SERVICE", nil)
			return nil, s.createGrpcError(codes.InvalidArgument, "The OTP provided is incorrect", customerrors.ERR_LOGIN_2FA_CODE_INVALID, nil)
		}
	}

	rtoken, _, err := utils.GenerateJWT(user.ID, "USER", s.jwtSecret, 7*24*time.Hour)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to generate refresh token", map[string]any{
			"method":    "LoginUser",
			"userID":    user.ID,
			"errorType": customerrors.ERR_LOGIN_TOKEN_GEN_FAILED,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while generating your refresh token", customerrors.ERR_LOGIN_TOKEN_GEN_FAILED, err)
	}

	atoken, expiresIn, err := utils.GenerateJWT(user.ID, "USER", s.jwtSecret, 1*24*time.Hour)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to generate access token", map[string]any{
			"method":    "LoginUser",
			"userID":    user.ID,
			"errorType": customerrors.ERR_LOGIN_TOKEN_GEN_FAILED,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while generating your access token", customerrors.ERR_LOGIN_TOKEN_GEN_FAILED, err)
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "User login successful", map[string]any{
		"method": "LoginUser",
		"userID": user.ID,
		"email":  req.Email,
	}, "SERVICE", nil)

	return &authUserAdminService.LoginUserResponse{
		UserProfile: &authUserAdminService.UserProfile{
			UserID:            user.ID,
			FirstName:         user.FirstName,
			LastName:          user.LastName,
			Email:             user.Email,
			Role:              user.Role,
			PrimaryLanguageID: user.PrimaryLanguageID,
			Country:           strings.ToUpper(user.Country),
			TwoFactorEnabled:  user.TwoFactorEnabled,
			AvatarData:        user.AvatarData,
			UserName:          user.UserName,
			IsVerified:        user.IsVerified,
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
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting LoginAdmin", map[string]any{
		"method":    "LoginAdmin",
		"email":     req.Email,
		"operation": "admin_login",
	}, "SERVICE", nil)

	user, errorType, err := s.repo.GetUserByEmail(req.Email)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Error retrieving admin user", map[string]any{
			"method":    "LoginAdmin",
			"email":     req.Email,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while verifying your admin credentials", errorType, err)
	}
	if user.ID == "" {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Admin user not found", map[string]any{
			"method":    "LoginAdmin",
			"email":     req.Email,
			"errorType": customerrors.ERR_ADMIN_LOGIN_NOT_FOUND,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.NotFound, "No admin account exists with this email address", customerrors.ERR_ADMIN_LOGIN_NOT_FOUND, nil)
	}
	if user.Role != "ADMIN" {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "No admin privileges", map[string]any{
			"method":    "LoginAdmin",
			"email":     req.Email,
			"errorType": customerrors.ERR_ADMIN_LOGIN_NO_PRIVILEGES,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.PermissionDenied, "This account does not have administrative privileges", customerrors.ERR_ADMIN_LOGIN_NO_PRIVILEGES, nil)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(req.Password+user.Salt)); err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Incorrect admin password", map[string]any{
			"method":    "LoginAdmin",
			"email":     req.Email,
			"errorType": customerrors.ERR_ADMIN_LOGIN_CRED_WRONG,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.Unauthenticated, "The admin password provided is incorrect", customerrors.ERR_ADMIN_LOGIN_CRED_WRONG, nil)
	}

	if !user.IsVerified {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Admin not verified", map[string]any{
			"method":    "LoginAdmin",
			"email":     req.Email,
			"errorType": customerrors.ERR_ADMIN_LOGIN_NOT_VERIFIED,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.Unauthenticated, "This admin account requires verification", customerrors.ERR_ADMIN_LOGIN_NOT_VERIFIED, nil)
	}

	atoken, expiresIn, err := utils.GenerateJWT(user.ID, "ADMIN", s.jwtSecret, 1*24*time.Hour)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to generate admin token", map[string]any{
			"method":    "LoginAdmin",
			"email":     req.Email,
			"errorType": customerrors.ERR_ADMIN_LOGIN_TOKEN_FAILED,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while generating your admin token", customerrors.ERR_ADMIN_LOGIN_TOKEN_FAILED, err)
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Admin login successful", map[string]any{
		"method":  "LoginAdmin",
		"adminID": user.ID,
		"email":   req.Email,
	}, "SERVICE", nil)

	return &authUserAdminService.LoginAdminResponse{
		AccessToken: atoken,
		ExpiresIn:   expiresIn,
		AdminID:     user.ID,
		Message:     "Admin login successful. Welcome back.",
	}, nil
}

// TokenRefresh refreshes an access token
func (s *AuthUserAdminService) TokenRefresh(ctx context.Context, req *authUserAdminService.TokenRefreshRequest) (*authUserAdminService.TokenRefreshResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting TokenRefresh", map[string]any{
		"method":    "TokenRefresh",
		"operation": "token_refresh",
	}, "SERVICE", nil)

	claims := &utils.Claims{}
	token, err := jwt.ParseWithClaims(req.RefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.jwtSecret), nil
	})
	if err != nil || !token.Valid {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Invalid refresh token", map[string]any{
			"method":    "TokenRefresh",
			"errorType": customerrors.ERR_TOKEN_REFRESH_INVALID,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.Unauthenticated, "Your session has expired", customerrors.ERR_TOKEN_REFRESH_INVALID, err)
	}

	newToken, expiresIn, err := utils.GenerateJWT(claims.ID, claims.Role, s.jwtSecret, 1*24*time.Hour)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to generate new access token", map[string]any{
			"method":    "TokenRefresh",
			"userID":    claims.ID,
			"errorType": customerrors.ERR_TOKEN_REFRESH_FAILED,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while refreshing your session", customerrors.ERR_TOKEN_REFRESH_FAILED, err)
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Token refreshed successfully", map[string]any{
		"method": "TokenRefresh",
		"userID": claims.ID,
	}, "SERVICE", nil)

	return &authUserAdminService.TokenRefreshResponse{
		AccessToken: newToken,
		ExpiresIn:   expiresIn,
		UserID:      claims.ID,
	}, nil
}

// LogoutUser handles user logout (placeholder, as JWT is stateless)
func (s *AuthUserAdminService) LogoutUser(ctx context.Context, req *authUserAdminService.LogoutRequest) (*authUserAdminService.LogoutResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting LogoutUser", map[string]any{
		"method":    "LogoutUser",
		"userID":    req.UserID,
		"operation": "logout",
	}, "SERVICE", nil)

	errorType, err := s.repo.LogoutUser(req.UserID)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to logout user", map[string]any{
			"method":    "LogoutUser",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while logging out", errorType, err)
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "User logged out successfully", map[string]any{
		"method": "LogoutUser",
		"userID": req.UserID,
	}, "SERVICE", nil)

	return &authUserAdminService.LogoutResponse{
		Message: "You have been logged out successfully.",
	}, nil
}

// ResendEmailVerification resends a verification OTP
func (s *AuthUserAdminService) ResendEmailVerification(ctx context.Context, req *authUserAdminService.ResendEmailVerificationRequest) (*authUserAdminService.ResendEmailVerificationResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting ResendEmailVerification", map[string]any{
		"method":    "ResendEmailVerification",
		"email":     req.Email,
		"operation": "resend_verification",
	}, "SERVICE", nil)

	_, expiryAt, errorType, err := s.repo.ResendEmailVerification(req.Email)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to resend verification email", map[string]any{
			"method":    "ResendEmailVerification",
			"email":     req.Email,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.InvalidArgument, "Something went wrong while sending the verification email", errorType, err)
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Verification email resent successfully", map[string]any{
		"method": "ResendEmailVerification",
		"email":  req.Email,
	}, "SERVICE", nil)

	return &authUserAdminService.ResendEmailVerificationResponse{
		Message:  "A new verification email has been sent to your email address.",
		ExpiryAt: expiryAt,
	}, nil
}

// VerifyUser verifies a user with an OTP
func (s *AuthUserAdminService) VerifyUser(ctx context.Context, req *authUserAdminService.VerifyUserRequest) (*authUserAdminService.VerifyUserResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting VerifyUser", map[string]any{
		"method":    "VerifyUser",
		"email":     req.Email,
		"operation": "verify_user",
	}, "SERVICE", nil)

	verified, errorType, err := s.repo.VerifyUserToken(req.Email, req.Token)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Error verifying user", map[string]any{
			"method":    "VerifyUser",
			"email":     req.Email,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while verifying the user", errorType, err)
	}
	if !verified {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Invalid verification token", map[string]any{
			"method":    "VerifyUser",
			"email":     req.Email,
			"errorType": customerrors.ERR_VERIFY_TOKEN_INVALID,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.InvalidArgument, "The verification code is invalid or has expired", customerrors.ERR_VERIFY_TOKEN_INVALID, nil)
	}

	// Invalidate non-admin caches for verified user
	user, _, err := s.repo.GetUserByEmail(req.Email)
	if err == nil {
		cacheKeys := []string{
			fmt.Sprintf("user_profile:id:%s", user.ID),
			fmt.Sprintf("user_profile:username:%s", strings.ToLower(user.UserName)),
			fmt.Sprintf("ban_status:%s", user.ID),
			fmt.Sprintf("following:%s", user.ID),
			fmt.Sprintf("followers:%s", user.ID),
		}
		for _, key := range cacheKeys {
			if err := s.cache.Delete(key); err != nil {
				// Skip logging cache deletion failures
			}
		}
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "User verified successfully", map[string]any{
		"method": "VerifyUser",
		"email":  req.Email,
	}, "SERVICE", nil)

	return &authUserAdminService.VerifyUserResponse{
		Message: "Your account has been successfully verified. You may now log in.",
	}, nil
}

// ForgotPassword initiates password recovery
func (s *AuthUserAdminService) ForgotPassword(ctx context.Context, req *authUserAdminService.ForgotPasswordRequest) (*authUserAdminService.ForgotPasswordResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting ForgotPassword", map[string]any{
		"method":    "ForgotPassword",
		"email":     req.Email,
		"operation": "forgot_password",
	}, "SERVICE", nil)

	if !repository.IsValidEmail(req.Email) {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Invalid email", map[string]any{
			"method":    "ForgotPassword",
			"email":     req.Email,
			"errorType": customerrors.ERR_PW_FORGOT_INVALID_EMAIL,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.InvalidArgument, "Please provide a valid email address", customerrors.ERR_PW_FORGOT_INVALID_EMAIL, nil)
	}

	token := uuid.New().String()
	_, errorType, err := s.repo.CreateForgotPasswordToken(req.Email, token)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Error initiating password recovery", map[string]any{
			"method":    "ForgotPassword",
			"email":     req.Email,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while initiating password recovery", errorType, err)
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Password recovery initiated", map[string]any{
		"method": "ForgotPassword",
		"email":  req.Email,
	}, "SERVICE", nil)

	return &authUserAdminService.ForgotPasswordResponse{
		Message: "Password recovery instructions have been sent to your email.",
		Token:   token,
	}, nil
}

// FinishForgotPassword completes the password reset process
func (s *AuthUserAdminService) FinishForgotPassword(ctx context.Context, req *authUserAdminService.FinishForgotPasswordRequest) (*authUserAdminService.FinishForgotPasswordResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting FinishForgotPassword", map[string]any{
		"method":    "FinishForgotPassword",
		"email":     req.Email,
		"operation": "reset_password",
	}, "SERVICE", nil)

	if req.NewPassword != req.ConfirmPassword {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Password mismatch", map[string]any{
			"method":    "FinishForgotPassword",
			"email":     req.Email,
			"errorType": customerrors.ERR_PW_RESET_MISMATCH,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.InvalidArgument, "The new passwords do not match", customerrors.ERR_PW_RESET_MISMATCH, nil)
	}
	if !repository.IsValidPassword(req.NewPassword) {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Invalid password format", map[string]any{
			"method":    "FinishForgotPassword",
			"email":     req.Email,
			"errorType": customerrors.ERR_PW_RESET_INVALID_PASSWORD,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.InvalidArgument, "Password must be at least 8 characters and include an uppercase letter and a number", customerrors.ERR_PW_RESET_INVALID_PASSWORD, nil)
	}

	errorType, err := s.repo.FinishForgotPassword(req.Email, req.Token, req.NewPassword)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Error resetting password", map[string]any{
			"method":    "FinishForgotPassword",
			"email":     req.Email,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while resetting the password", errorType, err)
	}

	// Invalidate non-admin caches for user
	user, _, err := s.repo.GetUserByEmail(req.Email)
	if err == nil {
		cacheKeys := []string{
			fmt.Sprintf("user_profile:id:%s", user.ID),
			fmt.Sprintf("user_profile:username:%s", strings.ToLower(user.UserName)),
			fmt.Sprintf("ban_status:%s", user.ID),
			fmt.Sprintf("following:%s", user.ID),
			fmt.Sprintf("followers:%s", user.ID),
		}
		for _, key := range cacheKeys {
			if err := s.cache.Delete(key); err != nil {
				// Skip logging cache deletion failures
			}
		}
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Password reset successfully", map[string]any{
		"method": "FinishForgotPassword",
		"email":  req.Email,
	}, "SERVICE", nil)

	return &authUserAdminService.FinishForgotPasswordResponse{
		Message: "Your password has been reset successfully.",
	}, nil
}

// ChangePassword allows authenticated users to change their password
func (s *AuthUserAdminService) ChangePassword(ctx context.Context, req *authUserAdminService.ChangePasswordRequest) (*authUserAdminService.ChangePasswordResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting ChangePassword", map[string]any{
		"method":    "ChangePassword",
		"userID":    req.UserID,
		"operation": "change_password",
	}, "SERVICE", nil)

	if req.NewPassword != req.ConfirmPassword {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Password mismatch", map[string]any{
			"method":    "ChangePassword",
			"userID":    req.UserID,
			"errorType": customerrors.ERR_PW_CHANGE_MISMATCH,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.InvalidArgument, "The new passwords do not match", customerrors.ERR_PW_CHANGE_MISMATCH, nil)
	}
	if !repository.IsValidPassword(req.NewPassword) {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Invalid password format", map[string]any{
			"method":    "ChangePassword",
			"userID":    req.UserID,
			"errorType": customerrors.ERR_PW_CHANGE_INVALID_PASSWORD,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.InvalidArgument, "Password must be at least 8 characters and include an uppercase letter and a number", customerrors.ERR_PW_CHANGE_INVALID_PASSWORD, nil)
	}

	errorType, err := s.repo.ChangeAuthenticatedPassword(req.UserID, req.OldPassword, req.NewPassword)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Error changing password", map[string]any{
			"method":    "ChangePassword",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while changing the password", errorType, err)
	}

	// Invalidate non-admin caches
	cacheKeys := []string{
		fmt.Sprintf("user_profile:id:%s", req.UserID),
		fmt.Sprintf("ban_status:%s", req.UserID),
		fmt.Sprintf("following:%s", req.UserID),
		fmt.Sprintf("followers:%s", req.UserID),
	}
	for _, key := range cacheKeys {
		if err := s.cache.Delete(key); err != nil {
			// Skip logging cache deletion failures
		}
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Password changed successfully", map[string]any{
		"method": "ChangePassword",
		"userID": req.UserID,
	}, "SERVICE", nil)

	return &authUserAdminService.ChangePasswordResponse{
		Message: "Your password has been updated successfully.",
	}, nil
}

// UpdateProfile updates user profile
func (s *AuthUserAdminService) UpdateProfile(ctx context.Context, req *authUserAdminService.UpdateProfileRequest) (*authUserAdminService.UpdateProfileResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting UpdateProfile", map[string]any{
		"method":    "UpdateProfile",
		"userID":    req.UserID,
		"operation": "update_profile",
	}, "SERVICE", nil)

	currentUser, _, err := s.repo.GetUserByUserID(req.UserID)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "User not found", map[string]any{
			"method":    "UpdateProfile",
			"userID":    req.UserID,
			"errorType": customerrors.ERR_USER_NOT_FOUND,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "user not found", customerrors.ERR_USER_NOT_FOUND, err)
	}

	username := strings.ToLower(req.UserName)
	if len(username) < 3 {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Username too short", map[string]any{
			"method":    "UpdateProfile",
			"userID":    req.UserID,
			"errorType": customerrors.ERR_INVALID_USERNAME,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.InvalidArgument, "username too short", customerrors.ERR_INVALID_USERNAME, nil)
	}

	if username != strings.ToLower(currentUser.UserName) {
		available := s.repo.UserAvailable(username)
		if !available {
			s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Username taken", map[string]any{
				"method":    "UpdateProfile",
				"userID":    req.UserID,
				"username":  username,
				"errorType": customerrors.ERR_USERNAME_TAKEN,
			}, "SERVICE", nil)
			return nil, s.createGrpcError(codes.AlreadyExists, "username taken", customerrors.ERR_USERNAME_TAKEN, nil)
		}
	}

	req.UserName = username
	errorType, err := s.repo.UpdateProfile(req)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to update profile", map[string]any{
			"method":    "UpdateProfile",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.Internal, "update failed", errorType, err)
	}

	// Invalidate non-admin caches, including old username
	cacheKeys := []string{
		fmt.Sprintf("user_profile:id:%s", req.UserID),
		fmt.Sprintf("user_profile:username:%s", strings.ToLower(currentUser.UserName)),
		fmt.Sprintf("user_profile:username:%s", username),
		fmt.Sprintf("ban_status:%s", req.UserID),
		fmt.Sprintf("following:%s", req.UserID),
		fmt.Sprintf("followers:%s", req.UserID),
	}
	for _, key := range cacheKeys {
		if err := s.cache.Delete(key); err != nil {
			// Skip logging cache deletion failures
		}
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Profile updated successfully", map[string]any{
		"method":   "UpdateProfile",
		"userID":   req.UserID,
		"username": username,
	}, "SERVICE", nil)

	return &authUserAdminService.UpdateProfileResponse{
		UserProfile: &authUserAdminService.UserProfile{
			UserID:            req.UserID,
			FirstName:         req.FirstName,
			LastName:          req.LastName,
			PrimaryLanguageID: req.PrimaryLanguageID,
			Country:           strings.ToUpper(req.Country),
			UserName:          username,
			Bio:               req.Bio,
			Socials: &authUserAdminService.Socials{
				Github:   req.Socials.Github,
				Twitter:  req.Socials.Twitter,
				Linkedin: req.Socials.Linkedin,
			},
		},
		Message: "profile updated",
	}, nil
}

// UpdateProfileImage updates the user's profile image
func (s *AuthUserAdminService) UpdateProfileImage(ctx context.Context, req *authUserAdminService.UpdateProfileImageRequest) (*authUserAdminService.UpdateProfileImageResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting UpdateProfileImage", map[string]any{
		"method":    "UpdateProfileImage",
		"userID":    req.UserID,
		"operation": "update_profile_image",
	}, "SERVICE", nil)

	errorType, err := s.repo.UpdateProfileImage(req)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to update profile image", map[string]any{
			"method":    "UpdateProfileImage",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while updating your profile image", errorType, err)
	}

	// Invalidate non-admin caches
	cacheKeys := []string{
		fmt.Sprintf("user_profile:id:%s", req.UserID),
		fmt.Sprintf("ban_status:%s", req.UserID),
		fmt.Sprintf("following:%s", req.UserID),
		fmt.Sprintf("followers:%s", req.UserID),
	}
	for _, key := range cacheKeys {
		if err := s.cache.Delete(key); err != nil {
			// Skip logging cache deletion failures
		}
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Profile image updated successfully", map[string]any{
		"method": "UpdateProfileImage",
		"userID": req.UserID,
	}, "SERVICE", nil)

	return &authUserAdminService.UpdateProfileImageResponse{
		Message:   "Your profile image has been updated successfully.",
		AvatarURL: req.AvatarURL,
	}, nil
}

// GetUserProfile retrieves a user's profile by ID or Username
func (s *AuthUserAdminService) GetUserProfile(ctx context.Context, req *authUserAdminService.GetUserProfileRequest) (*authUserAdminService.GetUserProfileResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting GetUserProfile", map[string]any{
		"method":    "GetUserProfile",
		"userID":    req.UserID,
		"username":  req.UserName,
		"operation": "get_profile",
	}, "SERVICE", nil)

	var cacheKey string
	if req.UserID != "" {
		cacheKey = fmt.Sprintf("user_profile:id:%s", req.UserID)
	} else if req.UserName != nil && *req.UserName != "" {
		cacheKey = fmt.Sprintf("user_profile:username:%s", *req.UserName)
	} else {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Invalid userID or username", map[string]any{
			"method":    "GetUserProfile",
			"errorType": "INVALID_ARGUMENT",
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.InvalidArgument, "UserID or Username must be provided", "INVALID_ARGUMENT", nil)
	}

	cachedProfile, err := s.cache.Get(cacheKey)
	if err == nil && cachedProfile != "" {
		var profile authUserAdminService.GetUserProfileResponse
		if err := json.Unmarshal([]byte(cachedProfile), &profile); err == nil {
			s.logger.Log(zapcore.InfoLevel, req.TraceID, "Profile retrieved from cache", map[string]any{
				"method":   "GetUserProfile",
				"cacheKey": cacheKey,
			}, "SERVICE", nil)
			return &profile, nil
		}
	}

	var (
		resp      *authUserAdminService.GetUserProfileResponse
		errorType string
	)
	if req.UserID != "" {
		resp, errorType, err = s.repo.GetUserProfileByUserID(req.UserID)
	} else {
		resp, errorType, err = s.repo.GetUserProfileByUsername(*req.UserName)
	}
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to retrieve user profile", map[string]any{
			"method":    "GetUserProfile",
			"userID":    req.UserID,
			"username":  req.UserName,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "Failed to retrieve user profile", errorType, err)
	}

	profileBytes, _ := json.Marshal(resp)
	if err := s.cache.Set(cacheKey, profileBytes, 2*time.Minute); err != nil {
		// Skip logging cache set failure
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "User profile retrieved successfully", map[string]any{
		"method":   "GetUserProfile",
		"userID":   req.UserID,
		"username": req.UserName,
	}, "SERVICE", nil)

	return resp, nil
}

// CheckBanStatus checks if a user is banned
func (s *AuthUserAdminService) CheckBanStatus(ctx context.Context, req *authUserAdminService.CheckBanStatusRequest) (*authUserAdminService.CheckBanStatusResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting CheckBanStatus", map[string]any{
		"method":    "CheckBanStatus",
		"userID":    req.UserID,
		"operation": "check_ban",
	}, "SERVICE", nil)

	resp, errorType, err := s.repo.CheckBanStatus(req.UserID)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Error checking ban status", map[string]any{
			"method":    "CheckBanStatus",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while checking ban status", errorType, err)
	}
	if resp == nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "User not found", map[string]any{
			"method":    "CheckBanStatus",
			"userID":    req.UserID,
			"errorType": customerrors.ERR_BAN_STATUS_NOT_FOUND,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.NotFound, "The specified user could not be found", customerrors.ERR_BAN_STATUS_NOT_FOUND, nil)
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Ban status checked", map[string]any{
		"method":   "CheckBanStatus",
		"userID":   req.UserID,
		"isBanned": resp.IsBanned,
	}, "SERVICE", nil)

	return resp, nil
}

// FollowUser adds a follow relationship
func (s *AuthUserAdminService) FollowUser(ctx context.Context, req *authUserAdminService.FollowUserRequest) (*authUserAdminService.FollowUserResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting FollowUser", map[string]any{
		"method":     "FollowUser",
		"followerID": req.FollowerID,
		"followeeID": req.FolloweeID,
		"operation":  "follow_user",
	}, "SERVICE", nil)

	errorType, err := s.repo.FollowUser(req.FollowerID, req.FolloweeID)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to follow user", map[string]any{
			"method":     "FollowUser",
			"followerID": req.FollowerID,
			"followeeID": req.FolloweeID,
			"errorType":  errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while following the user", errorType, err)
	}

	// Invalidate non-admin follow-related caches
	cacheKeys := []string{
		fmt.Sprintf("following:%s", req.FollowerID),
		fmt.Sprintf("followers:%s", req.FolloweeID),
		fmt.Sprintf("follow_check:%s:%s", req.FollowerID, req.FolloweeID),
		fmt.Sprintf("follow_check:%s:%s", req.FolloweeID, req.FollowerID),
	}
	for _, key := range cacheKeys {
		if err := s.cache.Delete(key); err != nil {
			// Skip logging cache deletion failures
		}
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "User followed successfully", map[string]any{
		"method":     "FollowUser",
		"followerID": req.FollowerID,
		"followeeID": req.FolloweeID,
	}, "SERVICE", nil)

	return &authUserAdminService.FollowUserResponse{
		Message: "You are now following this user.",
	}, nil
}

// UnfollowUser removes a follow relationship
func (s *AuthUserAdminService) UnfollowUser(ctx context.Context, req *authUserAdminService.UnfollowUserRequest) (*authUserAdminService.UnfollowUserResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting UnfollowUser", map[string]any{
		"method":     "UnfollowUser",
		"followerID": req.FollowerID,
		"followeeID": req.FolloweeID,
		"operation":  "unfollow_user",
	}, "SERVICE", nil)

	errorType, err := s.repo.UnfollowUser(req.FollowerID, req.FolloweeID)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to unfollow user", map[string]any{
			"method":     "UnfollowUser",
			"followerID": req.FollowerID,
			"followeeID": req.FolloweeID,
			"errorType":  errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while unfollowing the user", errorType, err)
	}

	// Invalidate non-admin follow-related caches
	cacheKeys := []string{
		fmt.Sprintf("following:%s", req.FollowerID),
		fmt.Sprintf("followers:%s", req.FolloweeID),
		fmt.Sprintf("follow_check:%s:%s", req.FollowerID, req.FolloweeID),
		fmt.Sprintf("follow_check:%s:%s", req.FolloweeID, req.FollowerID),
	}
	for _, key := range cacheKeys {
		if err := s.cache.Delete(key); err != nil {
			// Skip logging cache deletion failures
		}
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "User unfollowed successfully", map[string]any{
		"method":     "UnfollowUser",
		"followerID": req.FollowerID,
		"followeeID": req.FolloweeID,
	}, "SERVICE", nil)

	return &authUserAdminService.UnfollowUserResponse{
		Message: "You have unfollowed this user.",
	}, nil
}

// GetFollowing retrieves users a given user is following
func (s *AuthUserAdminService) GetFollowing(ctx context.Context, req *authUserAdminService.GetFollowingRequest) (*authUserAdminService.GetFollowingResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting GetFollowing", map[string]any{
		"method":    "GetFollowing",
		"userID":    req.UserID,
		"operation": "get_following",
	}, "SERVICE", nil)

	cacheKey := fmt.Sprintf("following:%s", req.UserID)
	cachedFollowing, err := s.cache.Get(cacheKey)
	if err == nil && cachedFollowing != "" {
		var following authUserAdminService.GetFollowingResponse
		if err := json.Unmarshal([]byte(cachedFollowing), &following); err == nil {
			s.logger.Log(zapcore.InfoLevel, req.TraceID, "Following list retrieved from cache", map[string]any{
				"method":   "GetFollowing",
				"userID":   req.UserID,
				"cacheKey": cacheKey,
			}, "SERVICE", nil)
			return &following, nil
		}
	}

	profiles, errorType, err := s.repo.GetFollowing(req.UserID)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to retrieve following list", map[string]any{
			"method":    "GetFollowing",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while retrieving followed users", errorType, err)
	}

	resp := &authUserAdminService.GetFollowingResponse{
		Users: profiles,
	}
	followingBytes, _ := json.Marshal(resp)
	if err := s.cache.Set(cacheKey, followingBytes, 2*time.Minute); err != nil {
		// Skip logging cache set failure
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Following list retrieved successfully", map[string]any{
		"method": "GetFollowing",
		"userID": req.UserID,
	}, "SERVICE", nil)

	return resp, nil
}

// GetFollowers retrieves users following a given user
func (s *AuthUserAdminService) GetFollowers(ctx context.Context, req *authUserAdminService.GetFollowersRequest) (*authUserAdminService.GetFollowersResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting GetFollowers", map[string]any{
		"method":    "GetFollowers",
		"userID":    req.UserID,
		"operation": "get_followers",
	}, "SERVICE", nil)

	cacheKey := fmt.Sprintf("followers:%s", req.UserID)
	cachedFollowers, err := s.cache.Get(cacheKey)
	if err == nil && cachedFollowers != "" {
		var followers authUserAdminService.GetFollowersResponse
		if err := json.Unmarshal([]byte(cachedFollowers), &followers); err == nil {
			s.logger.Log(zapcore.InfoLevel, req.TraceID, "Followers list retrieved from cache", map[string]any{
				"method":   "GetFollowers",
				"userID":   req.UserID,
				"cacheKey": cacheKey,
			}, "SERVICE", nil)
			return &followers, nil
		}
	}

	profiles, errorType, err := s.repo.GetFollowers(req.UserID)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to retrieve followers list", map[string]any{
			"method":    "GetFollowers",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while retrieving followers", errorType, err)
	}

	resp := &authUserAdminService.GetFollowersResponse{
		Users: profiles,
	}
	followersBytes, _ := json.Marshal(resp)
	if err := s.cache.Set(cacheKey, followersBytes, 2*time.Minute); err != nil {
		// Skip logging cache set failure
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Followers list retrieved successfully", map[string]any{
		"method": "GetFollowers",
		"userID": req.UserID,
	}, "SERVICE", nil)

	return resp, nil
}

// GetFollowFollowingCheck checks if the owner user follows or is followed by the target user
func (s *AuthUserAdminService) GetFollowFollowingCheck(ctx context.Context, req *authUserAdminService.GetFollowFollowingCheckRequest) (*authUserAdminService.GetFollowFollowingCheckResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting GetFollowFollowingCheck", map[string]any{
		"method":       "GetFollowFollowingCheck",
		"ownerUserID":  req.OwnerUserID,
		"targetUserID": req.TargetUserID,
		"operation":    "check_follow",
	}, "SERVICE", nil)

	ownerUserID := req.OwnerUserID
	targetUserID := req.TargetUserID

	if ownerUserID == "" || targetUserID == "" {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Empty user IDs", map[string]any{
			"method":    "GetFollowFollowingCheck",
			"errorType": customerrors.ERR_PARAM_EMPTY,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.InvalidArgument, "Owner user ID and target user ID cannot be empty", customerrors.ERR_PARAM_EMPTY, nil)
	}

	if ownerUserID == targetUserID {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Self follow check", map[string]any{
			"method":    "GetFollowFollowingCheck",
			"errorType": customerrors.ERR_INVALID_REQUEST,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.InvalidArgument, "Cannot check follow status for self", customerrors.ERR_INVALID_REQUEST, nil)
	}

	isFollowing, isFollower, errorType, err := s.repo.CheckFollowRelationship(ownerUserID, targetUserID)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Error checking follow status", map[string]any{
			"method":       "GetFollowFollowingCheck",
			"ownerUserID":  ownerUserID,
			"targetUserID": targetUserID,
			"errorType":    errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while checking follow status", errorType, err)
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Follow status checked", map[string]any{
		"method":       "GetFollowFollowingCheck",
		"ownerUserID":  ownerUserID,
		"targetUserID": targetUserID,
		"isFollowing":  isFollowing,
		"isFollower":   isFollower,
	}, "SERVICE", nil)

	return &authUserAdminService.GetFollowFollowingCheckResponse{
		IsFollowing: isFollowing,
		IsFollower:  isFollower,
	}, nil
}

// CreateUserAdmin creates a new admin user
func (s *AuthUserAdminService) CreateUserAdmin(ctx context.Context, req *authUserAdminService.CreateUserAdminRequest) (*authUserAdminService.CreateUserAdminResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting CreateUserAdmin", map[string]any{
		"method":    "CreateUserAdmin",
		"email":     req.Email,
		"operation": "create_admin",
	}, "SERVICE", nil)

	if req.Password != req.ConfirmPassword {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Password mismatch", map[string]any{
			"method":    "CreateUserAdmin",
			"email":     req.Email,
			"errorType": customerrors.ERR_ADMIN_CREATE_PASSWORD_MISMATCH,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.InvalidArgument, "The passwords entered do not match", customerrors.ERR_ADMIN_CREATE_PASSWORD_MISMATCH, nil)
	}
	if !repository.IsValidEmail(req.Email) {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Invalid email", map[string]any{
			"method":    "CreateUserAdmin",
			"email":     req.Email,
			"errorType": customerrors.ERR_ADMIN_CREATE_INVALID_EMAIL,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.InvalidArgument, "Please provide a valid email address", customerrors.ERR_ADMIN_CREATE_INVALID_EMAIL, nil)
	}
	if !repository.IsValidPassword(req.Password) {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Invalid password format", map[string]any{
			"method":    "CreateUserAdmin",
			"email":     req.Email,
			"errorType": customerrors.ERR_ADMIN_CREATE_INVALID_PASSWORD,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.InvalidArgument, "Password must be at least 8 characters and include an uppercase letter and a number", customerrors.ERR_ADMIN_CREATE_INVALID_PASSWORD, nil)
	}

	userID, errorType, err := s.repo.CreateUserAdmin(req)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to create admin user", map[string]any{
			"method":    "CreateUserAdmin",
			"email":     req.Email,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while creating the admin account", errorType, err)
	}

	// Invalidate non-admin caches for new admin user
	cacheKeys := []string{
		fmt.Sprintf("user_profile:id:%s", userID),
		fmt.Sprintf("ban_status:%s", userID),
		fmt.Sprintf("following:%s", userID),
		fmt.Sprintf("followers:%s", userID),
	}
	for _, key := range cacheKeys {
		if err := s.cache.Delete(key); err != nil {
			// Skip logging cache deletion failures
		}
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Admin user created successfully", map[string]any{
		"method": "CreateUserAdmin",
		"userID": userID,
		"email":  req.Email,
	}, "SERVICE", nil)

	return &authUserAdminService.CreateUserAdminResponse{
		UserID:  userID,
		Message: "The admin account has been created successfully.",
	}, nil
}

// UpdateUserAdmin updates an admin user
func (s *AuthUserAdminService) UpdateUserAdmin(ctx context.Context, req *authUserAdminService.UpdateUserAdminRequest) (*authUserAdminService.UpdateUserAdminResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting UpdateUserAdmin", map[string]any{
		"method":    "UpdateUserAdmin",
		"userID":    req.UserID,
		"operation": "update_admin",
	}, "SERVICE", nil)

	isAdmin, errorType, err := s.repo.IsAdmin(req.UserID)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Error verifying admin status", map[string]any{
			"method":    "UpdateUserAdmin",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while verifying admin status", errorType, err)
	}
	if !isAdmin {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "No admin privileges", map[string]any{
			"method":    "UpdateUserAdmin",
			"userID":    req.UserID,
			"errorType": customerrors.ERR_ADMIN_UPDATE_NO_PRIVILEGES,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.PermissionDenied, "Administrative privileges are required to perform this action", customerrors.ERR_ADMIN_UPDATE_NO_PRIVILEGES, nil)
	}

	if req.Password != "" {
		if !repository.IsValidPassword(req.Password) {
			s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Invalid password format", map[string]any{
				"method":    "UpdateUserAdmin",
				"userID":    req.UserID,
				"errorType": customerrors.ERR_ADMIN_UPDATE_INVALID_PASSWORD,
			}, "SERVICE", nil)
			return nil, s.createGrpcError(codes.InvalidArgument, "Password must be at least 8 characters and include an uppercase letter and a number", customerrors.ERR_ADMIN_UPDATE_INVALID_PASSWORD, nil)
		}
	}

	errorType, err = s.repo.UpdateUserAdmin(req)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to update admin user", map[string]any{
			"method":    "UpdateUserAdmin",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while updating the admin account", errorType, err)
	}

	// Invalidate non-admin caches
	cacheKeys := []string{
		fmt.Sprintf("user_profile:id:%s", req.UserID),
		fmt.Sprintf("ban_status:%s", req.UserID),
		fmt.Sprintf("following:%s", req.UserID),
		fmt.Sprintf("followers:%s", req.UserID),
	}
	for _, key := range cacheKeys {
		if err := s.cache.Delete(key); err != nil {
			// Skip logging cache deletion failures
		}
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Admin user updated successfully", map[string]any{
		"method": "UpdateUserAdmin",
		"userID": req.UserID,
	}, "SERVICE", nil)

	return &authUserAdminService.UpdateUserAdminResponse{
		Message: "The admin account has been updated successfully.",
	}, nil
}

// BanUser sets a user as banned
func (s *AuthUserAdminService) BanUser(ctx context.Context, req *authUserAdminService.BanUserRequest) (*authUserAdminService.BanUserResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting BanUser", map[string]any{
		"method":    "BanUser",
		"userID":    req.UserID,
		"operation": "ban_user",
	}, "SERVICE", nil)

	errorType, err := s.repo.BanUser(req.UserID, req.BanReason, req.BanExpiry, req.BanType)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to ban user", map[string]any{
			"method":    "BanUser",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while banning the user", errorType, err)
	}

	// Invalidate non-admin caches
	cacheKeys := []string{
		fmt.Sprintf("user_profile:id:%s", req.UserID),
		fmt.Sprintf("ban_status:%s", req.UserID),
		fmt.Sprintf("following:%s", req.UserID),
		fmt.Sprintf("followers:%s", req.UserID),
	}
	for _, key := range cacheKeys {
		if err := s.cache.Delete(key); err != nil {
			// Skip logging cache deletion failures
		}
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "User banned successfully", map[string]any{
		"method":    "BanUser",
		"userID":    req.UserID,
		"banReason": req.BanReason,
	}, "SERVICE", nil)

	return &authUserAdminService.BanUserResponse{
		Message: "The user has been banned successfully.",
	}, nil
}

// UnbanUser removes a user's ban
func (s *AuthUserAdminService) UnbanUser(ctx context.Context, req *authUserAdminService.UnbanUserRequest) (*authUserAdminService.UnbanUserResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting UnbanUser", map[string]any{
		"method":    "UnbanUser",
		"userID":    req.UserID,
		"operation": "unban_user",
	}, "SERVICE", nil)

	errorType, err := s.repo.UnbanUser(req.UserID)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to unban user", map[string]any{
			"method":    "UnbanUser",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while unbanning the user", errorType, err)
	}

	// Invalidate non-admin caches
	cacheKeys := []string{
		fmt.Sprintf("user_profile:id:%s", req.UserID),
		fmt.Sprintf("ban_status:%s", req.UserID),
		fmt.Sprintf("following:%s", req.UserID),
		fmt.Sprintf("followers:%s", req.UserID),
	}
	for _, key := range cacheKeys {
		if err := s.cache.Delete(key); err != nil {
			// Skip logging cache deletion failures
		}
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "User unbanned successfully", map[string]any{
		"method": "UnbanUser",
		"userID": req.UserID,
	}, "SERVICE", nil)

	return &authUserAdminService.UnbanUserResponse{
		Message: "The user has been unbanned successfully.",
	}, nil
}

// VerifyAdminUser verifies a user (admin action)
func (s *AuthUserAdminService) VerifyAdminUser(ctx context.Context, req *authUserAdminService.VerifyAdminUserRequest) (*authUserAdminService.VerifyAdminUserResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting VerifyAdminUser", map[string]any{
		"method":    "VerifyAdminUser",
		"userID":    req.UserID,
		"operation": "verify_admin_user",
	}, "SERVICE", nil)

	errorType, err := s.repo.VerifyAdminUser(req.UserID)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to verify user", map[string]any{
			"method":    "VerifyAdminUser",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while verifying the user", errorType, err)
	}

	// Invalidate non-admin caches
	cacheKeys := []string{
		fmt.Sprintf("user_profile:id:%s", req.UserID),
		fmt.Sprintf("ban_status:%s", req.UserID),
		fmt.Sprintf("following:%s", req.UserID),
		fmt.Sprintf("followers:%s", req.UserID),
	}
	for _, key := range cacheKeys {
		if err := s.cache.Delete(key); err != nil {
			// Skip logging cache deletion failures
		}
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "User verified successfully by admin", map[string]any{
		"method": "VerifyAdminUser",
		"userID": req.UserID,
	}, "SERVICE", nil)

	return &authUserAdminService.VerifyAdminUserResponse{
		Message: "The user has been verified successfully.",
	}, nil
}

// UnverifyUser un-verifies a user (admin action)
func (s *AuthUserAdminService) UnverifyUser(ctx context.Context, req *authUserAdminService.UnverifyUserAdminRequest) (*authUserAdminService.UnverifyUserAdminResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting UnverifyUser", map[string]any{
		"method":    "UnverifyUser",
		"userID":    req.UserID,
		"operation": "unverify_user",
	}, "SERVICE", nil)

	errorType, err := s.repo.UnverifyUser(req.UserID)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to unverify user", map[string]any{
			"method":    "UnverifyUser",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while unverifying the user", errorType, err)
	}

	// Invalidate non-admin caches
	cacheKeys := []string{
		fmt.Sprintf("user_profile:id:%s", req.UserID),
		fmt.Sprintf("ban_status:%s", req.UserID),
		fmt.Sprintf("following:%s", req.UserID),
		fmt.Sprintf("followers:%s", req.UserID),
	}
	for _, key := range cacheKeys {
		if err := s.cache.Delete(key); err != nil {
			// Skip logging cache deletion failures
		}
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "User unverified successfully", map[string]any{
		"method": "UnverifyUser",
		"userID": req.UserID,
	}, "SERVICE", nil)

	return &authUserAdminService.UnverifyUserAdminResponse{
		Message: "The user’s verification has been removed successfully.",
	}, nil
}

// SoftDeleteUserAdmin soft deletes a user
func (s *AuthUserAdminService) SoftDeleteUserAdmin(ctx context.Context, req *authUserAdminService.SoftDeleteUserAdminRequest) (*authUserAdminService.SoftDeleteUserAdminResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting SoftDeleteUserAdmin", map[string]any{
		"method":    "SoftDeleteUserAdmin",
		"userID":    req.UserID,
		"operation": "soft_delete_user",
	}, "SERVICE", nil)

	isAdmin, errorType, err := s.repo.IsAdmin(req.UserID)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Error verifying admin status", map[string]any{
			"method":    "SoftDeleteUserAdmin",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while verifying admin status", errorType, err)
	}
	if !isAdmin {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "No admin privileges", map[string]any{
			"method":    "SoftDeleteUserAdmin",
			"userID":    req.UserID,
			"errorType": customerrors.ERR_ADMIN_DELETE_NO_PRIVILEGES,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.PermissionDenied, "Administrative privileges are required to delete a user", customerrors.ERR_ADMIN_DELETE_NO_PRIVILEGES, nil)
	}

	errorType, err = s.repo.SoftDeleteUserAdmin(req.UserID)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to soft delete user", map[string]any{
			"method":    "SoftDeleteUserAdmin",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while deleting the user", errorType, err)
	}

	// Invalidate non-admin caches
	cacheKeys := []string{
		fmt.Sprintf("user_profile:id:%s", req.UserID),
		fmt.Sprintf("ban_status:%s", req.UserID),
		fmt.Sprintf("following:%s", req.UserID),
		fmt.Sprintf("followers:%s", req.UserID),
	}
	for _, key := range cacheKeys {
		if err := s.cache.Delete(key); err != nil {
			// Skip logging cache deletion failures
		}
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "User soft deleted successfully", map[string]any{
		"method": "SoftDeleteUserAdmin",
		"userID": req.UserID,
	}, "SERVICE", nil)

	return &authUserAdminService.SoftDeleteUserAdminResponse{
		Message: "The user has been soft-deleted successfully.",
	}, nil
}

// GetAllUsers retrieves a paginated list of users
func (s *AuthUserAdminService) GetAllUsers(ctx context.Context, req *authUserAdminService.GetAllUsersRequest) (*authUserAdminService.GetAllUsersResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting GetAllUsers", map[string]any{
		"method":    "GetAllUsers",
		"operation": "get_all_users",
	}, "SERVICE", nil)

	profiles, totalCount, errorType, nextPageToken, prevPageToken, err := s.repo.GetAllUsers(req)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to retrieve user list", map[string]any{
			"method":    "GetAllUsers",
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while retrieving users", errorType, err)
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "User list retrieved successfully", map[string]any{
		"method":     "GetAllUsers",
		"totalCount": totalCount,
	}, "SERVICE", nil)

	return &authUserAdminService.GetAllUsersResponse{
		Users:         profiles,
		TotalCount:    totalCount,
		PrevPageToken: prevPageToken,
		NextPageToken: nextPageToken,
		Message:       "User list retrieved successfully.",
	}, nil
}

// BanHistory retrieves ban history for a user
func (s *AuthUserAdminService) BanHistory(ctx context.Context, req *authUserAdminService.BanHistoryRequest) (*authUserAdminService.BanHistoryResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting BanHistory", map[string]any{
		"method":    "BanHistory",
		"userID":    req.UserID,
		"operation": "get_ban_history",
	}, "SERVICE", nil)

	history, errorType, err := s.repo.GetBanHistory(req.UserID)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to retrieve ban history", map[string]any{
			"method":    "BanHistory",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while retrieving ban history", errorType, err)
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Ban history retrieved successfully", map[string]any{
		"method": "BanHistory",
		"userID": req.UserID,
	}, "SERVICE", nil)

	return &authUserAdminService.BanHistoryResponse{
		Bans:    history,
		Message: "Ban history retrieved successfully.",
	}, nil
}

// SearchUsers searches for users with pagination
func (s *AuthUserAdminService) SearchUsers(ctx context.Context, req *authUserAdminService.SearchUsersRequest) (*authUserAdminService.SearchUsersResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting SearchUsers", map[string]any{
		"method":    "SearchUsers",
		"query":     req.Query,
		"operation": "search_users",
	}, "SERVICE", nil)

	cacheKey := fmt.Sprintf("search_users:%s:%s:%d", req.Query, req.PageToken, req.Limit)
	cachedUsers, err := s.cache.Get(cacheKey)
	if err == nil && cachedUsers != "" {
		var usersResp authUserAdminService.SearchUsersResponse
		if err := json.Unmarshal([]byte(cachedUsers), &usersResp); err == nil {
			s.logger.Log(zapcore.InfoLevel, req.TraceID, "Users retrieved from cache", map[string]any{
				"method":   "SearchUsers",
				"query":    req.Query,
				"cacheKey": cacheKey,
			}, "SERVICE", nil)
			return &usersResp, nil
		}
	}

	users, nextPageToken, errorType, err := s.repo.SearchUsers(req.Query, req.PageToken, req.Limit)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to search users", map[string]any{
			"method":    "SearchUsers",
			"query":     req.Query,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while searching for users", errorType, err)
	}

	resp := &authUserAdminService.SearchUsersResponse{
		Users:         users,
		NextPageToken: nextPageToken,
		Message:       "User search completed successfully.",
	}

	usersBytes, _ := json.Marshal(resp)
	if err := s.cache.Set(cacheKey, usersBytes, 2*time.Minute); err != nil {
		// Skip logging cache set failure
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "User search completed successfully", map[string]any{
		"method": "SearchUsers",
		"query":  req.Query,
	}, "SERVICE", nil)

	return resp, nil
}

// SetUpTwoFactorAuth enables 2FA for a user
func (s *AuthUserAdminService) SetUpTwoFactorAuth(ctx context.Context, req *authUserAdminService.SetUpTwoFactorAuthRequest) (*authUserAdminService.SetUpTwoFactorAuthResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting SetUpTwoFactorAuth", map[string]any{
		"method":    "SetUpTwoFactorAuth",
		"userID":    req.UserID,
		"operation": "setup_2fa",
	}, "SERVICE", nil)

	qrCodeImage, otpSecret, errorType, err := s.repo.SetUpTwoFactorAuth(req.UserID)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to set up 2FA", map[string]any{
			"method":    "SetUpTwoFactorAuth",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while setting up two factor authentication", errorType, err)
	}

	// Invalidate non-admin caches
	cacheKeys := []string{
		fmt.Sprintf("user_profile:id:%s", req.UserID),
		fmt.Sprintf("ban_status:%s", req.UserID),
		fmt.Sprintf("following:%s", req.UserID),
		fmt.Sprintf("followers:%s", req.UserID),
	}
	for _, key := range cacheKeys {
		if err := s.cache.Delete(key); err != nil {
			// Skip logging cache deletion failures
		}
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "2FA set up successfully", map[string]any{
		"method": "SetUpTwoFactorAuth",
		"userID": req.UserID,
	}, "SERVICE", nil)

	return &authUserAdminService.SetUpTwoFactorAuthResponse{
		Message: "Two factor authentication setup successfully",
		Image:   qrCodeImage,
		Secret:  otpSecret,
	}, nil
}

// VerifyTwoFactorAuth verifies 2FA setup
func (s *AuthUserAdminService) VerifyTwoFactorAuth(ctx context.Context, req *authUserAdminService.VerifyTwoFactorAuthRequest) (*authUserAdminService.VerifyTwoFactorAuthResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting VerifyTwoFactorAuth", map[string]any{
		"method":    "VerifyTwoFactorAuth",
		"userID":    req.UserID,
		"operation": "verify_2fa",
	}, "SERVICE", nil)

	done, errorType, err := s.repo.VerifyTwoFactorAuth(req.UserID, req.TwoFactorCode)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Error verifying 2FA", map[string]any{
			"method":    "VerifyTwoFactorAuth",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while verifying two factor authentication", errorType, err)
	}
	if !done {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Invalid 2FA code", map[string]any{
			"method":    "VerifyTwoFactorAuth",
			"userID":    req.UserID,
			"errorType": customerrors.ERR_2FA_VERIFY_INVALID,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.InvalidArgument, "Invalid two factor authentication code", customerrors.ERR_2FA_VERIFY_INVALID, nil)
	}

	// Invalidate non-admin caches
	cacheKeys := []string{
		fmt.Sprintf("user_profile:id:%s", req.UserID),
		fmt.Sprintf("ban_status:%s", req.UserID),
		fmt.Sprintf("following:%s", req.UserID),
		fmt.Sprintf("followers:%s", req.UserID),
	}
	for _, key := range cacheKeys {
		if err := s.cache.Delete(key); err != nil {
			// Skip logging cache deletion failures
		}
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "2FA verified successfully", map[string]any{
		"method": "VerifyTwoFactorAuth",
		"userID": req.UserID,
	}, "SERVICE", nil)

	return &authUserAdminService.VerifyTwoFactorAuthResponse{
		Message:  "Two factor authentication verified successfully",
		Verified: true,
	}, nil
}

// DisableTwoFactorAuth disables 2FA for a user
func (s *AuthUserAdminService) DisableTwoFactorAuth(ctx context.Context, req *authUserAdminService.DisableTwoFactorAuthRequest) (*authUserAdminService.DisableTwoFactorAuthResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting DisableTwoFactorAuth", map[string]any{
		"method":    "DisableTwoFactorAuth",
		"userID":    req.UserID,
		"operation": "disable_2fa",
	}, "SERVICE", nil)

	valid, errorType, err := s.repo.CheckUserPassword(req.UserID, req.Password)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Error checking user credentials", map[string]any{
			"method":    "DisableTwoFactorAuth",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while checking user credentials", errorType, err)
	}
	if !valid {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Incorrect password", map[string]any{
			"method":    "DisableTwoFactorAuth",
			"userID":    req.UserID,
			"errorType": customerrors.ERR_2FA_DISABLE_CRED_WRONG,
		}, "SERVICE", nil)
		return nil, s.createGrpcError(codes.PermissionDenied, "The provided password is incorrect", customerrors.ERR_2FA_DISABLE_CRED_WRONG, nil)
	}

	errorType, err = s.repo.DisableTwoFactorAuth(req.UserID)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Failed to disable 2FA", map[string]any{
			"method":    "DisableTwoFactorAuth",
			"userID":    req.UserID,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while disabling two factor authentication", errorType, err)
	}

	// Invalidate non-admin caches
	cacheKeys := []string{
		fmt.Sprintf("user_profile:id:%s", req.UserID),
		fmt.Sprintf("ban_status:%s", req.UserID),
		fmt.Sprintf("following:%s", req.UserID),
		fmt.Sprintf("followers:%s", req.UserID),
	}
	for _, key := range cacheKeys {
		if err := s.cache.Delete(key); err != nil {
			// Skip logging cache deletion failures
		}
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "2FA disabled successfully", map[string]any{
		"method": "DisableTwoFactorAuth",
		"userID": req.UserID,
	}, "SERVICE", nil)

	return &authUserAdminService.DisableTwoFactorAuthResponse{
		Message: "Two factor authentication has been disabled successfully",
	}, nil
}

// GetTwoFactorAuthStatus retrieves the 2FA status for a user
func (s *AuthUserAdminService) GetTwoFactorAuthStatus(ctx context.Context, req *authUserAdminService.GetTwoFactorAuthStatusRequest) (*authUserAdminService.GetTwoFactorAuthStatusResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting GetTwoFactorAuthStatus", map[string]any{
		"method":    "GetTwoFactorAuthStatus",
		"email":     req.Email,
		"operation": "get_2fa_status",
	}, "SERVICE", nil)

	isEnabled, errorType, err := s.repo.GetTwoFactorAuthStatus(req.Email)
	if err != nil {
		s.logger.Log(zapcore.ErrorLevel, req.TraceID, "Error retrieving 2FA status", map[string]any{
			"method":    "GetTwoFactorAuthStatus",
			"email":     req.Email,
			"errorType": errorType,
		}, "SERVICE", err)
		return nil, s.createGrpcError(codes.NotFound, "An error occurred while retrieving two factor authentication status", errorType, err)
	}

	s.logger.Log(zapcore.InfoLevel, req.TraceID, "2FA status retrieved", map[string]any{
		"method":    "GetTwoFactorAuthStatus",
		"email":     req.Email,
		"isEnabled": isEnabled,
	}, "SERVICE", nil)

	return &authUserAdminService.GetTwoFactorAuthStatusResponse{
		IsEnabled: isEnabled,
	}, nil
}

// UsernameAvailable checks if a username is available
func (s *AuthUserAdminService) UsernameAvailable(ctx context.Context, req *authUserAdminService.UsernameAvailableRequest) (*authUserAdminService.UsernameAvailableResponse, error) {
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Starting UsernameAvailable", map[string]any{
		"method":    "UsernameAvailable",
		"username":  req.Username,
		"operation": "check_username",
	}, "SERVICE", nil)

	if len(req.Username) < 3 {
		s.logger.Log(zapcore.InfoLevel, req.TraceID, "Username too short", map[string]any{
			"method":   "UsernameAvailable",
			"username": req.Username,
		}, "SERVICE", nil)
		return &authUserAdminService.UsernameAvailableResponse{
			Status: false,
		}, nil
	}

	status := s.repo.UserAvailable(req.Username)
	s.logger.Log(zapcore.InfoLevel, req.TraceID, "Username availability checked", map[string]any{
		"method":   "UsernameAvailable",
		"username": req.Username,
		"status":   status,
	}, "SERVICE", nil)

	return &authUserAdminService.UsernameAvailableResponse{
		Status: status,
	}, nil
}
