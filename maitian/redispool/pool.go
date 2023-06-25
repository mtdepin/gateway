package redispool

import (
	"github.com/gomodule/redigo/redis"
)

const (
	RedisPoolHost     = "redispool.host"
	RedisPoolPort     = "redispool.port"
	RedisPoolPassword = "redispool.password"
)

var (
	RedisConn redis.Conn
	RedisPool redis.Pool
)

// 启动redis 服务

func GetRedisConnect() redis.Conn {
	if RedisConn != nil && RedisConn.Err() != nil {
		RedisConn = RedisPool.Get()
	}
	return RedisConn
}
