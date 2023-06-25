package cmd

import (
	"encoding/xml"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/logger"
)

const (
	// Lifecycle configuration file.
	bucketLifecycleConfig = "lifecycle.xml"
)

// PutBucketLifecycleHandler - This HTTP handler stores given bucket lifecycle configuration as per
// https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lifecycle-mgmt.html
func (api objectAPIHandlers) PutBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "PutBucketLifecycle")

	defer logger.AuditLog(ctx, w, r)

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	// PutBucketLifecycle always needs a Content-Md5
	//if _, ok := r.Header[xhttp.ContentMD5]; !ok {
	//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentMD5), r.URL)
	//	return
	//}

	// 若PutBucketLifecycle请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.PutBucketLifecycleAction, bucket, ""); s3Error != ErrNone {
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

	bucketLifecycle, err := lifecycle.ParseLifecycleConfig(io.LimitReader(r.Body, r.ContentLength))
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Validate the received bucket policy document
	if err = bucketLifecycle.Validate(); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	if err = objAPI.PutBucketLifeCycle(ctx, bucket, bucketLifecycle); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	/*
		// Validate the transition storage ARNs
		if err = validateTransitionTier(bucketLifecycle); err != nil {
			writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
			return
		}
		configData, err := xml.Marshal(bucketLifecycle)
		if err != nil {
			writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
			return
		}

		if err = globalBucketMetadataSys.Update(bucket, objAPI.GetNameServerAddress(ctx), bucketLifecycleConfig, configData); err != nil {
			writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
			return
		}
	*/

	// Success.
	writeSuccessResponseHeadersOnly(w)
}

// GetBucketLifecycleHandler - This HTTP handler returns bucket policy configuration.
func (api objectAPIHandlers) GetBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetBucketLifecycle")

	defer logger.AuditLog(ctx, w, r)

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	// 若GetBucketLifecycle请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.GetBucketLifecycleAction, bucket, ""); s3Error != ErrNone {
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
	config, err := objAPI.GetBucketLifeCycle(ctx, bucket)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	/*
		config, err := globalBucketMetadataSys.GetLifecycleConfig(bucket)
		if err != nil {
			writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
			return
		}
	*/

	configData, err := xml.Marshal(config)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Write lifecycle configuration to client.
	writeSuccessResponseXML(w, configData)
}

// DeleteBucketLifecycleHandler - This HTTP handler removes bucket lifecycle configuration.
func (api objectAPIHandlers) DeleteBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "DeleteBucketLifecycle")

	defer logger.AuditLog(ctx, w, r)

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	// 若DeleteBucketLifecycle请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.PutBucketLifecycleAction, bucket, ""); s3Error != ErrNone {
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
	if err := objAPI.DeleteBucketLifeCycle(ctx, bucket); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	/*
		if err := globalBucketMetadataSys.Update(bucket, objAPI.GetNameServerAddress(ctx), bucketLifecycleConfig, nil); err != nil {
			writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
			return
		}
	*/

	// Success.
	writeSuccessNoContent(w)
}
