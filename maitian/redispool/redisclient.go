package redispool

import (
	"github.com/go-redis/redis"
	"github.com/minio/minio/internal/crypto"
	"github.com/minio/minio/maitian/config"
)

var RedisClient *redis.Client

func GetRedisOption() *redis.Options {
	return &redis.Options{
		Addr:     config.GetString("redis.redis_addr"),
		Password: crypto.DecryptLocalPassword(config.GetString("redis.password")),
		DB:       config.GetInt("redis.db_number"),
		PoolSize: config.GetInt("redis.pool_size"),
	}
}

func InitRedisClient(redisOpt *redis.Options) {
	RedisClient = redis.NewClient(redisOpt)
}

func GetRedisClient() *redis.Client {
	return RedisClient
}
