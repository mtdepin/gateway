package cmd

import (
	"encoding/xml"
	"io"
	"net/http"

	"github.com/dustin/go-humanize"
	"github.com/gorilla/mux"
	"github.com/minio/minio/internal/bucket/versioning"
	"github.com/minio/minio/internal/logger"
)

const (
	bucketVersioningConfig = "versioning.xml"

	// Maximum size of bucket versioning configuration payload sent to the PutBucketVersioningHandler.
	maxBucketVersioningConfigSize = 1 * humanize.MiByte
)

// PutBucketVersioningHandler - PUT Bucket Versioning.
// ----------
func (api objectAPIHandlers) PutBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "PutBucketVersioning")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// 若PutBucketVersioning请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.PutBucketVersioningAction, bucket, ""); s3Error != ErrNone {
		//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		//	return
		//}
		if checkoutTenantId(ctx, objectAPI, bucket, nil) != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	v, err := versioning.ParseConfig(io.LimitReader(r.Body, maxBucketVersioningConfigSize))
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	configData, err := xml.Marshal(v)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	err = objectAPI.PutBucketVersioning(GlobalContext, bucket, configData)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	writeSuccessResponseHeadersOnly(w)
}

// GetBucketVersioningHandler - GET Bucket Versioning.
// ----------
func (api objectAPIHandlers) GetBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetBucketVersioning")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// 若GetBucketVersioning请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.GetBucketVersioningAction, bucket, ""); s3Error != ErrNone {
		//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		//	return
		//}
		if checkoutTenantId(ctx, objectAPI, bucket, nil) != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	// Check if bucket exists.
	if _, err := objectAPI.GetBucketInfo(ctx, bucket); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	config, err := globalBucketVersioningSys.Get(bucket)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	configData, err := xml.Marshal(config)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Write bucket versioning configuration to client
	writeSuccessResponseXML(w, configData)

}
