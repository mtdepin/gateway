package mtstorage

import (
	"context"
	"encoding/json"
	"fmt"
	minio "github.com/minio/minio/cmd"
	"github.com/minio/minio/internal/logger"
	"net/http"
)

func (m *mtStorageObject) PutBucketLogging(ctx context.Context, bucket string, ret minio.BucketLoggingRet) error {

	nsUrl := fmt.Sprintf("%s/logging", m.address)
	param := map[string]string{
		"bucket": bucket,
		"prefix": ret.Enabled.TargetPrefix,
		"target": ret.Enabled.TargetBucket,
	}

	rs, err := doRequest(ctx, http.MethodPut, nsUrl, param, nil)
	if err != nil {
		logger.Error("response: %s", rs)
		return err
	}

	return nil
}

func (m *mtStorageObject) DeleteBucketLogging(ctx context.Context, bucket string) error {

	nsUrl := fmt.Sprintf("%s/logging", m.address)

	param := map[string]string{
		"bucket": bucket,
	}

	rs, err := doRequest(ctx, http.MethodDelete, nsUrl, param, nil)
	if err != nil {
		logger.Error("response: %s", rs)
		return err
	}
	return nil
}

func (m *mtStorageObject) GetBucketLogging(ctx context.Context, bucket string) (minio.BucketLoggingRet, error) {

	nsUrl := fmt.Sprintf("%s/logging", m.address)

	param := map[string]string{
		"bucket": bucket,
	}

	retData, err := doRequest(ctx, http.MethodGet, nsUrl, param, nil)
	if err != nil {
		logger.Error("response: %s", retData)
		return minio.BucketLoggingRet{}, err
	}
	if string(retData) == "" {
		return minio.BucketLoggingRet{}, minio.BucketLoggingNotFound{Bucket: bucket}
	}
	retM := make(map[string]interface{})
	err = json.Unmarshal(retData, &retM)
	if err != nil {
		return minio.BucketLoggingRet{}, err
	}
	return minio.BucketLoggingRet{
		Enabled: &minio.BucketLoggingEnabled{
			TargetPrefix: retM["prefix"].(string),
			TargetBucket: retM["target"].(string),
		},
	}, nil
}
