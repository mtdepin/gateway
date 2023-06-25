package mtstorage

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	minio "github.com/minio/minio/cmd"
	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/logger"
	"net/http"
)

func (m *mtStorageObject) PutBucketLifeCycle(ctx context.Context, bucket string, sys *lifecycle.Lifecycle) error {

	nsUrl := fmt.Sprintf("%s/lifecycle", m.address)
	configData, err := xml.Marshal(sys)
	if err != nil {
		return err
	}

	param := map[string]string{
		"bucket": bucket,
	}

	rs, err := doRequest(ctx, http.MethodPut, nsUrl, param, bytes.NewReader(configData))
	if err != nil {
		logger.Error("response: %s", rs)
		return err
	}
	return nil
}

func (m *mtStorageObject) GetBucketLifeCycle(ctx context.Context, bucket string) (*lifecycle.Lifecycle, error) {

	nsUrl := fmt.Sprintf("%s/lifecycle", m.address)

	param := map[string]string{
		"bucket": bucket,
	}

	bs, err := doRequest(ctx, http.MethodGet, nsUrl, param, nil)
	if err != nil {
		logger.Error("response: %s", bs)
		return nil, err
	}

	if string(bs) == "" {
		return nil, minio.BucketLifecycleNotFound{Bucket: bucket}
	}

	return lifecycle.ParseLifecycleConfig(bytes.NewReader(bs))
}

func (m *mtStorageObject) DeleteBucketLifeCycle(ctx context.Context, bucket string) error {

	nsUrl := fmt.Sprintf("%s/lifecycle", m.address)

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
