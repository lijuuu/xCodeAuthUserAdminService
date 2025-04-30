package cache

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
)

// rediscache manages redis cache operations
type RedisCache struct {
	client *redis.Client
	existingCache map[string]struct{}
}

// newrediscache initializes a new redis cache client
func NewRedisCache(addr, password string, db int) *RedisCache {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})
	return &RedisCache{client: client,existingCache: make(map[string]struct{})}
}

// set stores a value in redis with expiration
func (r *RedisCache) Set(key string, value interface{}, expiration time.Duration) error {

	//store on the redis struct
	r.existingCache[key] = struct{}{}

	log.Printf("cache: setting key '%s' with expiration %v", key, expiration)
	err := r.client.Set(context.Background(), key, value, expiration).Err()
	if err != nil {
		log.Printf("cache error: failed to set key '%s': %v", key, err)
		return fmt.Errorf("failed to set key %s in cache: %v", key, err)
	}
	log.Printf("cache: successfully set key '%s'", key)
	return nil
}

// get retrieves a string value from redis
func (r *RedisCache) Get(key string) (string, error) {
	log.Printf("cache: attempting to get key '%s'", key)
	val, err := r.client.Get(context.Background(), key).Result()
	if err == redis.Nil {
		log.Printf("cache miss: key '%s' not found", key)
		return "", nil
	}
	if err != nil {
		log.Printf("cache error: failed to get key '%s': %v", key, err)
		return "", fmt.Errorf("failed to get key %s from cache: %v", key, err)
	}
	log.Printf("cache hit: successfully retrieved key '%s'", key)
	return val, nil
}

// delete removes a key from redis
func (r *RedisCache) Delete(key string) error {
	log.Printf("cache: attempting to delete key '%s'", key)
	err := r.client.Del(context.Background(), key).Err()
	if err != nil {
		log.Printf("cache error: failed to delete key '%s': %v", key, err)
		return fmt.Errorf("failed to delete key %s from cache: %v", key, err)
	}
	log.Printf("cache: successfully deleted key '%s'", key)
	return nil
}

// exists checks if a key exists in redis
func (r *RedisCache) Exists(key string) (bool, error) {
	log.Printf("cache: checking existence of key '%s'", key)
	result, err := r.client.Exists(context.Background(), key).Result()
	if err != nil {
		log.Printf("cache error: failed to check existence of key '%s': %v", key, err)
		return false, fmt.Errorf("failed to check existence of key %s in cache: %v", key, err)
	}
	exists := result > 0
	log.Printf("cache: key '%s' exists: %v", key, exists)
	return exists, nil
}
