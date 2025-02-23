#!/bin/bash

# Define the base directory as the current working directory
BASE_DIR="$(pwd)"

# Define the directory structure
DIRS=(
    "$BASE_DIR/cmd"
    "$BASE_DIR/configs"
    "$BASE_DIR/db"
    "$BASE_DIR/repository"
    "$BASE_DIR/service"
    "$BASE_DIR/proto"
    "$BASE_DIR/model"
    "$BASE_DIR/utils"
)

# Create directories
for dir in "${DIRS[@]}"; do
    mkdir -p "$dir"
    chmod 755 "$dir"
    echo "Created directory: $dir with permissions 755"
done

# Create files with placeholders
FILES=(
    "$BASE_DIR/cmd/main.go"
    "$BASE_DIR/configs/config.go"
    "$BASE_DIR/db/db.go"
    "$BASE_DIR/repository/user_repository.go"
    "$BASE_DIR/service/user_service.go"
    "$BASE_DIR/proto/user.proto"
    "$BASE_DIR/model/user.go"
    "$BASE_DIR/model/socials.go"
    "$BASE_DIR/utils/jwt.go"
    "$BASE_DIR/go.mod"
    "$BASE_DIR/go.sum"
    "$BASE_DIR/README.md"
)

# Populate each file with a basic structure
for file in "${FILES[@]}"; do
    touch "$file"
    chmod 644 "$file"
    echo "// $file" > "$file"
    echo "Created file: $file with permissions 644"
done

# Initialize go module
cd "$BASE_DIR" || exit

go mod init github.com/yourusername/UserService

echo "Go module initialized."

echo "UserService project structure created successfully!"