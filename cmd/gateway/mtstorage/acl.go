package mtstorage

import (
	"context"
	"fmt"
	minio "github.com/minio/minio/cmd"
	"github.com/minio/minio/internal/logger"
	"go.opencensus.io/trace"
	"net/http"
	"strings"
)

func (m mtStorageObject) SetBucketACL(ctx context.Context, bucket string, s string) error {

	ctx, span := trace.StartSpan(ctx, "SetBucketACL")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	// /ns/v1/acl?bucket=xx&acl=xx [put]
	url := fmt.Sprintf("%s/acl", m.address)
	body := strings.NewReader(s)

	param := map[string]string{
		"bucket": bucket,
	}

	rs, err := doRequest(ctx, http.MethodPut, url, param, body)
	if err != nil {
		logger.Error("response: %s", rs)
		return err
	}
	return nil
}

func (m mtStorageObject) GetBucketACL(ctx context.Context, bucket string) (string, error) {

	ctx, span := trace.StartSpan(ctx, "GetBucketACL")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	// /ns/v1/acl?bucket=xx [get]
	url := fmt.Sprintf("%s/acl", m.address)

	param := map[string]string{
		"bucket": bucket,
	}

	body, err := doRequest(ctx, http.MethodGet, url, param, nil)
	if err != nil {
		logger.Error("response: %s", body)
		return "", err
	}

	return string(body), nil
}

func (m mtStorageObject) DeleteBucketACL(ctx context.Context, bucket string) error {

	ctx, span := trace.StartSpan(ctx, "DeleteBucketACL")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	// /ns/v1/acl?bucket=xx [delete]
	url := fmt.Sprintf("%s/acl", m.address)

	param := map[string]string{
		"bucket": bucket,
	}

	rs, err := doRequest(ctx, http.MethodDelete, url, param, nil)
	if err != nil {
		logger.Error("response: %s", rs)
		return err
	}
	return nil
}

// SetObjectACL object路径为绝对路径，对象名称前加“/”
// 如请求/bucket/object的acl时，
// 桶名称为bucket，对象名称为object，
// 传入参数为bucket和/object。
func (m mtStorageObject) SetObjectACL(ctx context.Context, bucket string, object string, acl string, opts minio.ObjectOptions) error {

	ctx, span := trace.StartSpan(ctx, "SetObjectACL")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	// /ns/v1/object/acl?bucket=xx&object=xx [put]
	url := fmt.Sprintf("%s/object/acl", m.address)
	body := strings.NewReader(acl)

	param := map[string]string{
		"bucket":    bucket,
		"object":    "/" + object,
		"versionId": opts.VersionID,
	}

	rs, err := doRequest(ctx, http.MethodPut, url, param, body)
	if err != nil {
		logger.Error("response: %s", rs)
		return err
	}
	return nil
}

// GetObjectACL object路径为绝对路径，对象名称前加“/”
// 如请求/bucket/object的acl时，
// 桶名称为bucket，对象名称为object，
// 传入参数为bucket和/object。
func (m mtStorageObject) GetObjectACL(ctx context.Context, bucket string, object string, opts minio.ObjectOptions) (string, error) {

	ctx, span := trace.StartSpan(ctx, "GetObjectACL")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	// /ns/v1/object/acl?bucket=xx&object=xx  [get]
	url := fmt.Sprintf("%s/object/acl", m.address)

	param := map[string]string{
		"bucket":    bucket,
		"object":    "/" + object,
		"versionId": opts.VersionID,
	}

	body, err := doRequest(ctx, http.MethodGet, url, param, nil)
	if err != nil {
		//logger.Errorf("response: %s", body)
		return "", err
	}

	return string(body), nil
}

// DeleteObjectACL object路径为绝对路径，对象名称前加“/”
// 如请求/bucket/object的acl时，
// 桶名称为bucket，对象名称为object，
// 传入参数为bucket和/object。
func (m mtStorageObject) DeleteObjectACL(ctx context.Context, bucket string, object string, opts minio.ObjectOptions) error {

	ctx, span := trace.StartSpan(ctx, "DeleteObjectACL")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	// /ns/v1/object/acl?bucket=xx&object=xx  [delete]
	url := fmt.Sprintf("%s/object/acl", m.address)

	param := map[string]string{
		"bucket":    bucket,
		"object":    "/" + object,
		"versionId": opts.VersionID,
	}

	rs, err := doRequest(ctx, http.MethodDelete, url, param, nil)
	if err != nil {
		logger.Error("response: %s", rs)
		return err
	}
	return nil
}
