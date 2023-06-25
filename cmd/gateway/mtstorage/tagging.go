package mtstorage

import (
	"context"
	"fmt"
	"github.com/minio/minio-go/v7/pkg/tags"
	minio "github.com/minio/minio/cmd"
	"github.com/minio/minio/internal/logger"
	"go.opencensus.io/trace"
	"net/http"
	"strings"
)

// bucketTagging operations
func (m *mtStorageObject) PutBucketTags(ctx context.Context, bucket string, tagStr string, opts minio.ObjectOptions) (minio.BucketInfo, error) {

	ctx, span := trace.StartSpan(ctx, "PutBucketTags")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	newTags, err := tags.Parse(tagStr, false)
	if err != nil {
		return minio.BucketInfo{}, err
	}

	tagStr = newTags.TagSet.String()
	reqUrl := fmt.Sprintf("%s/tag", m.address)
	param := map[string]string{
		"bucket": bucket,
	}

	tagStr = newTags.TagSet.String()
	body := strings.NewReader(tagStr)
	_, err = doRequest(ctx, http.MethodPut, reqUrl, param, body)
	if err != nil {
		return minio.BucketInfo{}, err
	}

	bucketInfo, err := m.GetBucketInfo(ctx, bucket)
	if err != nil {
		return minio.BucketInfo{}, err
	}

	return bucketInfo, nil
}

func (m *mtStorageObject) GetBucketTags(ctx context.Context, bucket string, opts minio.ObjectOptions) (*tags.Tags, error) {

	ctx, span := trace.StartSpan(ctx, "GetBucketTags")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	reqUrl := fmt.Sprintf("%s/tag", m.address)
	param := map[string]string{
		"bucket": bucket,
	}
	resp, err := doRequest(ctx, http.MethodGet, reqUrl, param, nil)
	if err != nil {
		return nil, err
	}

	objTags, err := tags.Parse(string(resp), false)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	return objTags, nil
}

func (m *mtStorageObject) DeleteBucketTags(ctx context.Context, bucket string, opts minio.ObjectOptions) (minio.BucketInfo, error) {

	ctx, span := trace.StartSpan(ctx, "DeleteBucketTags")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	reqUrl := fmt.Sprintf("%s/tag", m.address)
	param := map[string]string{
		"bucket": bucket,
	}
	_, err := doRequest(ctx, http.MethodDelete, reqUrl, param, nil)
	if err != nil {
		return minio.BucketInfo{}, err
	}

	return minio.BucketInfo{}, nil
}

//PutObjectTags put object tags
func (m *mtStorageObject) PutObjectTags(ctx context.Context, bucket, object string, tagStr string, opts minio.ObjectOptions) (minio.ObjectInfo, error) {

	ctx, span := trace.StartSpan(ctx, "PutObjectTags")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	newTags, err := tags.Parse(tagStr, true)
	if err != nil {
		return minio.ObjectInfo{}, err
	}

	if !strings.HasPrefix(object, "/") {
		object = fmt.Sprintf("/%s", object)
	}

	tagStr = newTags.TagSet.String()
	reqUrl := fmt.Sprintf("%s/object/tag", m.address)
	param := map[string]string{
		"bucket":    bucket,
		"object":    object,
		"versionId": opts.VersionID,
	}

	tagStr = newTags.TagSet.String()
	body := strings.NewReader(tagStr)
	resp, err := doRequest(ctx, http.MethodPut, reqUrl, param, body)
	if err != nil {
		return minio.ObjectInfo{}, err
	}

	if resp == nil {

	}

	objInfo, err := m.GetObjectInfo(ctx, bucket, object, opts)
	if err != nil {
		return minio.ObjectInfo{}, minio.ErrorRespToObjectError(err, bucket, object)
	}

	return objInfo, nil
	//return minio.ObjectInfo{}, nil
}

//GetObjectTags get object tags
func (m *mtStorageObject) GetObjectTags(ctx context.Context, bucket string, object string, opts minio.ObjectOptions) (*tags.Tags, error) {

	ctx, span := trace.StartSpan(ctx, "GetObjectTags")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()
	if !strings.HasPrefix(object, "/") {
		object = fmt.Sprintf("/%s", object)
	}

	reqUrl := fmt.Sprintf("%s/object/tag", m.address)
	param := map[string]string{
		"bucket":    bucket,
		"object":    object,
		"versionId": opts.VersionID,
	}
	resp, err := doRequest(ctx, http.MethodGet, reqUrl, param, nil)
	if err != nil {
		return nil, err
	}

	objTags, err := tags.Parse(string(resp), true)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	return objTags, nil
}

//DeleteObjectTags delete object tags
func (m *mtStorageObject) DeleteObjectTags(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (minio.ObjectInfo, error) {

	ctx, span := trace.StartSpan(ctx, "DeleteObjectTags")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	if !strings.HasPrefix(object, "/") {
		object = fmt.Sprintf("/%s", object)
	}

	reqUrl := fmt.Sprintf("%s/object/tag", m.address)
	param := map[string]string{
		"bucket":    bucket,
		"object":    object,
		"versionId": opts.VersionID,
	}
	_, err := doRequest(ctx, http.MethodDelete, reqUrl, param, nil)
	if err != nil {
		return minio.ObjectInfo{}, err
	}

	return minio.ObjectInfo{
		VersionID: opts.VersionID,
	}, nil
}
