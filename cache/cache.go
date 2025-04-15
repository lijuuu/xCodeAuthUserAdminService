package cache

import "time"

//cache is an abstraction layer for cache operations.
type Cache interface {
    Set(key string, value interface{}, expiration time.Duration) error
    Get(key string) (interface{}, error)
    Delete(key string) error
    Exists(key string) (bool, error)
}
