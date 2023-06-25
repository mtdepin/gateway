package mtstorage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	minio "github.com/minio/minio/cmd"
	"github.com/minio/minio/internal/logger"
	"go.opencensus.io/trace"
)

func (m *mtStorageObject) GetDagTree(ctx context.Context, bucket, object, cid string, opts minio.ObjectOptions) ([]byte, error) {

	ctx, span := trace.StartSpan(ctx, "GetDagTree")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()
	var err error
	if cid == "" {
		cid, err = m.GetObjectCid(ctx, bucket, object, opts)
		if err != nil {
			logger.Error("errMessage: %s", err.Error())
			return nil, err
		}
	}
	addressNode := m.getRandomChunkerNode(ctx, bucket)
	// /cs/v1/getObjectDagTree [get]
	url := fmt.Sprintf("http://%s/cs/v1/getObjectDagTree", addressNode)

	args := map[string]string{
		"bucket": bucket,
		"cid":    cid,
	}
	if cid == "" {
		ciderr := errors.New("cid 不能为空")
		logger.Error("errMessage: %s", ciderr.Error())
		return nil, ciderr
	}
	rs, err := doRequest(ctx, http.MethodGet, strings.TrimSpace(url), args, nil)
	if err != nil {
		fmt.Println("dag error:", err.Error())
		logger.Error("errMessage: %s", rs)
		return nil, err
	}
	return rs, nil
}

// 获取object的cid

func (m *mtStorageObject) GetObjectCid(ctx context.Context, bucket string, object string, opts minio.ObjectOptions) (string, error) {

	ctx, span := trace.StartSpan(ctx, "GetObjectCid")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	// /ns/v1/object/cid?bucket=xx&object=xx  [get]
	url := fmt.Sprintf("%s/object/cid", m.address)
	param := map[string]string{
		"bucket":    bucket,
		"object":    "/" + object,
		"versionId": opts.VersionID,
	}
	body, err := doRequest(ctx, http.MethodGet, url, param, nil)
	if err != nil {
		logger.Error("response: %s", body)
		return "", err
	}
	res := make(map[string]string)
	if err := json.Unmarshal(body, &res); err != nil {
		return "", err
	}
	return res["cid"], nil
}
