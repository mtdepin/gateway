package cmd

import (
	"fmt"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/minio/minio/internal/logger"
)

func (api objectAPIHandlers) DeleteBucketLoggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "DeleteBucketLogging")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	//if s3Error := checkRequestAuthType(ctx, r, policy.GetBucketPolicyAction, bucket, ""); s3Error != ErrNone {
	//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
	//	return
	//}
	if checkoutTenantId(ctx, objAPI, bucket, nil) != nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	}
	// Validate if bucket exists, before proceeding further...
	_, err := objAPI.GetBucketInfo(ctx, bucket)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	if err = objAPI.DeleteBucketLogging(ctx, bucket); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	writeSuccessResponseHeadersOnly(w)
}

func (api objectAPIHandlers) PutBucketLoggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "PutBucketLogging")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	//if s3Error := checkRequestAuthType(ctx, r, policy.GetBucketPolicyAction, bucket, ""); s3Error != ErrNone {
	//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
	//	return
	//}
	if checkoutTenantId(ctx, objAPI, bucket, nil) != nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	}
	// Validate if bucket exists, before proceeding further...
	_, err := objAPI.GetBucketInfo(ctx, bucket)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	ret, err := ParseBucketLoggingXML(io.LimitReader(r.Body, r.ContentLength))
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	if err = objAPI.PutBucketLogging(ctx, bucket, *ret); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	writeSuccessResponseHeadersOnly(w)
}

// GetBucketLoggingHandler - GET bucket logging
func (api objectAPIHandlers) GetBucketLoggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetBucketLogging")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// Allow getBucketCors if policy action is set, since this is a dummy call
	// we are simply re-purposing the bucketPolicyAction.
	//if s3Error := checkRequestAuthType(ctx, r, policy.GetBucketPolicyAction, bucket, ""); s3Error != ErrNone {
	//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
	//	return
	//}
	if checkoutTenantId(ctx, objAPI, bucket, nil) != nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	}

	// Validate if bucket exists, before proceeding further...
	_, err := objAPI.GetBucketInfo(ctx, bucket)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	ret, err := objAPI.GetBucketLogging(ctx, bucket)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	var loggingConfig string
	if ret.Enabled == nil {
		loggingConfig = `<?xml version="1.0" encoding="UTF-8"?><BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></BucketLoggingStatus>`
		writeSuccessResponseXML(w, []byte(loggingConfig))
		return
	}
	loggingConfig = fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LoggingEnabled><TargetBucket>%s</TargetBucket><TargetPrefix>%s</TargetPrefix></LoggingEnabled></BucketLoggingStatus>`, ret.Enabled.TargetBucket, ret.Enabled.TargetPrefix)
	//const loggingDefaultConfig = `<?xml version="1.0" encoding="UTF-8"?><BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><!--<LoggingEnabled><TargetBucket>myLogsBucket</TargetBucket><TargetPrefix>add/this/prefix/to/my/log/files/access_log-</TargetPrefix></LoggingEnabled>--></BucketLoggingStatus>`
	writeSuccessResponseXML(w, []byte(loggingConfig))
}
