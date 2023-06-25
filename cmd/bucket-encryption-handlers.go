package cmd

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/minio/minio/internal/logger"
)

// PutBucketEncryptionHandler - Stores given bucket encryption configuration
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketEncryption.html
func (api objectAPIHandlers) PutBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "PutBucketEncryption")

	defer logger.AuditLog(ctx, w, r)

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	if !objAPI.IsEncryptionSupported() {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL)
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	// 若PutBucketEncryption请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.PutBucketEncryptionAction, bucket, ""); s3Error != ErrNone {
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

	// Parse bucket encryption xml
	encConfig, err := validateBucketSSEConfig(io.LimitReader(r.Body, maxBucketSSEConfigSize))
	if err != nil {
		apiErr := APIError{
			Code:           "MalformedXML",
			Description:    fmt.Sprintf("%s (%s)", errorCodes[ErrMalformedXML].Description, err),
			HTTPStatusCode: errorCodes[ErrMalformedXML].HTTPStatusCode,
		}
		writeErrorResponse(ctx, w, apiErr, r.URL)
		return
	}

	// Return error if KMS is not initialized
	//if GlobalKMS == nil {
	//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrKMSNotConfigured), r.URL)
	//	return
	//}
	//
	//configData, err := xml.Marshal(encConfig)
	//if err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}

	// Store the bucket encryption configuration in the object layer
	//if err = globalBucketMetadataSys.Update(bucket, "", bucketSSEConfig, configData); err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}
	// 目前只支持一种
	if len(encConfig.Rules) >= 2 {
		writeErrorResponse(ctx, w, toAPIError(ctx, errors.New("只能设置一种加密规则")), r.URL)
		return
	}
	if len(encConfig.Rules) == 0 {
		writeErrorResponse(ctx, w, toAPIError(ctx, errors.New("请设置加密")), r.URL)
		return
	}
	err = objAPI.PutBucketEncryption(ctx, bucket, *encConfig)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	writeSuccessResponseHeadersOnly(w)
}

// GetBucketEncryptionHandler - Returns bucket policy configuration
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketEncryption.html
func (api objectAPIHandlers) GetBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetBucketEncryption")

	defer logger.AuditLog(ctx, w, r)

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	// 若GetBucketEncryption请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.GetBucketEncryptionAction, bucket, ""); s3Error != ErrNone {
		//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		//	return
		//}
		if checkoutTenantId(ctx, objAPI, bucket, nil) != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	// Check if bucket exists
	var err error
	if _, err = objAPI.GetBucketInfo(ctx, bucket); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	config, err := objAPI.GetBucketEncryption(ctx, bucket)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	configData, err := xml.Marshal(config)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Write bucket encryption configuration to client
	writeSuccessResponseXML(w, configData)
}

// DeleteBucketEncryptionHandler - Removes bucket encryption configuration
func (api objectAPIHandlers) DeleteBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "DeleteBucketEncryption")

	defer logger.AuditLog(ctx, w, r)

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	// 若DeleteBucketEncryption请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.PutBucketEncryptionAction, bucket, ""); s3Error != ErrNone {
		//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		//	return
		//}
		if checkoutTenantId(ctx, objAPI, bucket, nil) != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	// Check if bucket exists
	var err error
	if _, err = objAPI.GetBucketInfo(ctx, bucket); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	//// Delete bucket encryption config from object layer
	//if err = globalBucketMetadataSys.Update(bucket, "", bucketSSEConfig, nil); err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}
	err = objAPI.DeleteBucketEncryption(ctx, bucket)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	writeSuccessNoContent(w)
}
