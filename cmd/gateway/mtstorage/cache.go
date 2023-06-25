package mtstorage

import (
	"encoding/json"
	"github.com/minio/minio/maitian/redispool"
	"time"
)

type Cache interface {
	Get() (interface{}, error)

	Put(interface{}) error

	Delete(interface{})
}

func SetMultiPart(mp MultiPart) error {
	//RedisConn := redispool.RedisPool.Get()
	//_, err := RedisConn.Do("SET", mp.UploadID, mp)
	//return err
	jsonBytes, _ := json.Marshal(mp)
	sc := redispool.GetRedisClient().Set(mp.UploadID, jsonBytes, 24*time.Hour)
	return sc.Err()
}

func GetMultiPart(uploadId string, mp *MultiPart) error {
	sc := redispool.GetRedisClient().Get(uploadId)
	jsonBytes, _ := sc.Bytes()
	return json.Unmarshal(jsonBytes, mp)

}
