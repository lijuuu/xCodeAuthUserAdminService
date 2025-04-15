package main

import (
	"log"
	"net"

	"xcode/cache"
	"xcode/configs"
	"xcode/db"
	"xcode/repository"
	"xcode/service"

	authUserAdminProto "github.com/lijuuu/GlobalProtoXcode/AuthUserAdminService"
	"google.golang.org/grpc"
)

func main() {
	// Load configuration
	config := configs.LoadConfig()

	// Initialize PostgreSQL connection
	dbConn, err := db.InitDB(config.PostgresDSN)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	defer db.Close(dbConn)

	redisCache := cache.NewRedisCache(config.RedisURL, "", 0)

	// Initialize repository and service
	userRepo := repository.NewUserRepository(dbConn, &config)
	authUserAdminService := service.NewAuthUserAdminService(userRepo, *redisCache, &config, config.JWTSecretKey)

	// Start gRPC server
	lis, err := net.Listen("tcp", ":"+config.UserGRPCPort)
	if err != nil {
		log.Fatalf("Failed to listen on port %s: %v", config.UserGRPCPort, err)
	}

	grpcServer := grpc.NewServer()
	authUserAdminProto.RegisterAuthUserAdminServiceServer(grpcServer, authUserAdminService)

	log.Printf("AuthUserAdminService gRPC server running on port %s", config.UserGRPCPort)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve gRPC server: %v", err)
	}
}
