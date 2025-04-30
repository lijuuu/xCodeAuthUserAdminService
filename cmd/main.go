package main

import (
	"net"

	"xcode/cache"
	"xcode/configs"
	"xcode/db"
	zap_betterstack "xcode/logger"
	"xcode/repository"
	"xcode/service"

	authUserAdminProto "github.com/lijuuu/GlobalProtoXcode/AuthUserAdminService"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
)

//TODO - all snake cases to pascal. only use snake in database.

func main() {
	// Load configuration
	config := configs.LoadConfig()

	// Initialize Zap logger based on environment
	var logger *zap.Logger
	var err error
	if config.Environment == "development" {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		panic("Failed to initialize Zap logger: " + err.Error())
	}
	defer logger.Sync()

	// Initialize BetterStackLogStreamer
	logStreamer := zap_betterstack.NewBetterStackLogStreamer(
		config.BetterStackSourceToken,
		config.Environment,
		config.BetterStackUploadURL,
		logger,
	)

	// Initialize PostgreSQL connection
	dbConn, err := db.InitDB(config.PostgresDSN)
	if err != nil {
		logStreamer.Log(zapcore.ErrorLevel, "GENESISTRACEID", "Failed to connect to PostgreSQL", map[string]any{
			"error": err.Error(),
		}, "DB INIT", nil)
		// logger.Fatal("Failed to connect to PostgreSQL", zap.Error(err))
	}
	defer db.Close(dbConn)

	// Initialize Redis cache
	redisCache := cache.NewRedisCache(config.RedisURL, "", 0)

	// Initialize repository and service
	userRepo := repository.NewUserRepository(dbConn, &config, logStreamer)
	authUserAdminService := service.NewAuthUserAdminService(userRepo, *redisCache, &config, config.JWTSecretKey,logStreamer)

	// Start gRPC server
	lis, err := net.Listen("tcp", ":"+config.UserGRPCPort)
	if err != nil {
		logStreamer.Log(zapcore.ErrorLevel, "GENESISTRACEID", "Failed to listen on port", map[string]any{
			"port":  config.UserGRPCPort,
			"error": err.Error(),
		}, "GRPC INIT", nil)
		// logger.Fatal("Failed to listen on port", zap.Error(err))
	}

	grpcServer := grpc.NewServer()
	authUserAdminProto.RegisterAuthUserAdminServiceServer(grpcServer, authUserAdminService)

	// Log server startup
	logStreamer.Log(zapcore.InfoLevel, "GENESISTRACEID", "AuthUserAdminService gRPC server running", map[string]any{
		"port": config.UserGRPCPort,
	}, "SERVICE INIT", nil)

	// Start gRPC server
	if err := grpcServer.Serve(lis); err != nil {
		logStreamer.Log(zapcore.ErrorLevel, "GENESISTRACEID", "Failed to serve gRPC server", map[string]any{
			"error": err.Error(),
		}, "GRPC SERVE", nil)
		// logger.Fatal("Failed to serve gRPC server", zap.Error(err))
	}
}