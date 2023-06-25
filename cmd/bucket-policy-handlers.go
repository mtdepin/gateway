package cmd

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/dustin/go-humanize"
	"github.com/gorilla/mux"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/pkg/bucket/policy"
)

const (
	// As per AWS S3 specification, 20KiB policy JSON data is allowed.
	maxBucketPolicySize = 20 * humanize.KiByte

	// Policy configuration file.
	bucketPolicyConfig = "policy.json"
)

// PutBucketPolicyHandler - This HTTP handler stores given bucket policy configuration as per
// https://docs.aws.amazon.com/AmazonS3/latest/dev/access-policy-language-overview.html
// 桶策略中不能设置Action字段为"s3:*"，"s3:*"只能在IAM策略中设置,
// 桶策略Action字段必须为minio/pkg/bucket/policy/action.go中supportedActions集合中的字段
func (api objectAPIHandlers) PutBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "PutBucketPolicy")

	defer logger.AuditLog(ctx, w, r)

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	// 若PutBucketPolicy请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.PutBucketPolicyAction, bucket, ""); s3Error != ErrNone {
		//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		//	return
		//}
		if checkoutTenantId(ctx, objAPI, bucket, nil) != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	// Check if bucket exists.
	if _, err := objAPI.GetBucketInfo(ctx, bucket); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Error out if Content-Length is missing.
	// PutBucketPolicy always needs Content-Length.
	if r.ContentLength <= 0 {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL)
		return
	}

	// Error out if Content-Length is beyond allowed size.
	if r.ContentLength > maxBucketPolicySize {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrPolicyTooLarge), r.URL)
		return
	}

	bucketPolicy, err := policy.ParseConfig(io.LimitReader(r.Body, r.ContentLength), bucket)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Version in policy must not be empty
	if bucketPolicy.Version == "" {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMalformedPolicy), r.URL)
		return
	}

	//configData, err := json.Marshal(bucketPolicy)
	//if err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}
	//
	//if err = globalBucketMetadataSys.Update(bucket, bucketPolicyConfig, configData); err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}

	// set bucket policy
	if err = objAPI.SetBucketPolicy(ctx, bucket, bucketPolicy); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	}

	// Success.
	writeSuccessNoContent(w)
}

// DeleteBucketPolicyHandler - This HTTP handler removes bucket policy configuration.
func (api objectAPIHandlers) DeleteBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "DeleteBucketPolicy")

	defer logger.AuditLog(ctx, w, r)

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	// 若DeleteBucketPolicy请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.DeleteBucketPolicyAction, bucket, ""); s3Error != ErrNone {
		//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		//	return
		//}
		if checkoutTenantId(ctx, objAPI, bucket, nil) != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	// Check if bucket exists.
	if _, err := objAPI.GetBucketInfo(ctx, bucket); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	//if err := globalBucketMetadataSys.Update(bucket, bucketPolicyConfig, nil); err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}

	// delete bucket policy
	if err := objAPI.DeleteBucketPolicy(ctx, bucket); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	}

	// Success.
	writeSuccessNoContent(w)
}

// GetBucketPolicyHandler - This HTTP handler returns bucket policy configuration.
func (api objectAPIHandlers) GetBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetBucketPolicy")

	defer logger.AuditLog(ctx, w, r)

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	// 若GetBucketPolicy请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.GetBucketPolicyAction, bucket, ""); s3Error != ErrNone {
		//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		//	return
		//}
		if checkoutTenantId(ctx, objAPI, bucket, nil) != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	// Check if bucket exists.
	if _, err := objAPI.GetBucketInfo(ctx, bucket); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	//// Read bucket access policy.
	//config, err := globalPolicySys.Get(bucket)
	//if err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}
	//
	//configData, err := json.Marshal(config)
	//if err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}

	// get bucket policy
	bucketPolicy, err := objAPI.GetBucketPolicy(ctx, bucket)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	}
	configData, err := json.Marshal(bucketPolicy)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Write to client.
	writeSuccessResponseJSON(w, configData)
}
