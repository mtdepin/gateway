package cmd

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/minio/minio/internal/logger"
)

// Data types used for returning dummy tagging XML.
// These variables shouldn't be used elsewhere.
// They are only defined to be used in this file alone.

// GetBucketWebsite  - GET bucket website, a dummy api
func (api objectAPIHandlers) GetBucketWebsiteHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetBucketWebsite")

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

	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNoSuchWebsiteConfiguration), r.URL)
}

// GetBucketAccelerate  - GET bucket accelerate, a dummy api
func (api objectAPIHandlers) GetBucketAccelerateHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetBucketAccelerate")

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

	const accelerateDefaultConfig = `<?xml version="1.0" encoding="UTF-8"?><AccelerateConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>`
	writeSuccessResponseXML(w, []byte(accelerateDefaultConfig))
}

// GetBucketRequestPaymentHandler - GET bucket requestPayment, a dummy api
func (api objectAPIHandlers) GetBucketRequestPaymentHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetBucketRequestPayment")

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

	const requestPaymentDefaultConfig = `<?xml version="1.0" encoding="UTF-8"?><RequestPaymentConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Payer>BucketOwner</Payer></RequestPaymentConfiguration>`

	writeSuccessResponseXML(w, []byte(requestPaymentDefaultConfig))
}

// DeleteBucketWebsiteHandler - DELETE bucket website, a dummy api
func (api objectAPIHandlers) DeleteBucketWebsiteHandler(w http.ResponseWriter, r *http.Request) {
	writeSuccessResponseHeadersOnly(w)
	w.(http.Flusher).Flush()
}

// GetBucketCorsHandler - GET bucket cors, a dummy api
func (api objectAPIHandlers) GetBucketCorsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetBucketCors")

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

	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNoSuchCORSConfiguration), r.URL)
}
