package mtstorage

import (
	"context"
	"encoding/base64"
	"fmt"
	minio "github.com/minio/minio/cmd"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/pkg/bucket/policy"
	"go.opencensus.io/trace"
	"net/http"
	"strings"
)

func (m *mtStorageObject) SetBucketPolicy(ctx context.Context, bucket string, policy *policy.Policy) error {

	ctx, span := trace.StartSpan(ctx, "SetBucketPolicy")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	// /ns/v1/policy?bucket=xx [put]
	url := fmt.Sprintf("%s/policy", m.address)
	// json marshal policy
	policyBuf, err := policy.MarshalJSON()
	if err != nil {
		return err
	}
	// base64 encode
	policyStr := base64.StdEncoding.EncodeToString(policyBuf)

	param := map[string]string{
		"bucket": bucket,
	}

	body := strings.NewReader(policyStr)
	rs, err := doRequest(ctx, http.MethodPut, url, param, body)
	if err != nil {
		logger.Error("response: %s", rs)
		return err
	}

	return nil
}

func (m *mtStorageObject) GetBucketPolicy(ctx context.Context, bucket string) (*policy.Policy, error) {

	ctx, span := trace.StartSpan(ctx, "GetBucketPolicy")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	// /ns/v1/policy?bucket=xx [get]
	url := fmt.Sprintf("%s/policy", m.address)

	//body, _ := ioutil.ReadAll(resp.Body)
	//defer resp.Body.Close()

	param := map[string]string{
		"bucket": bucket,
	}

	body, err := doRequest(ctx, http.MethodGet, url, param, nil)
	if err != nil {
		if _, ok := err.(minio.NotFound); ok {
			return nil, minio.BucketPolicyNotFound{Bucket: bucket}
		}
		logger.Error("response: %s", body)
		return nil, err
	}

	var policy policy.Policy
	if len(body) != 0 {
		// base64 decode
		policyBuf, err := base64.StdEncoding.DecodeString(string(body))
		if err != nil {
			return nil, err
		}
		// json unmarshal
		err = (&policy).UnmarshalJSON(policyBuf)
		if err != nil {
			return nil, err
		}
	}

	return &policy, nil
}

func (m *mtStorageObject) DeleteBucketPolicy(ctx context.Context, bucket string) error {

	ctx, span := trace.StartSpan(ctx, "DeleteBucketPolicy")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	// /ns/v1/policy?bucket=xx [delete]
	url := fmt.Sprintf("%s/policy", m.address)

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
