package cmd

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/minio/minio/internal/logger"
)

const (
	bucketConfigPrefix       = "buckets"
	bucketNotificationConfig = "notification.xml"
)

// GetBucketNotificationHandler - This HTTP handler returns event notification configuration
// as per http://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html.
// It returns empty configuration if its not set.
func (api objectAPIHandlers) GetBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetBucketNotification")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucketName := vars["bucket"]

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	if !objAPI.IsNotificationSupported() {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL)
		return
	}

	// 若GetBucketNotification请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.GetBucketNotificationAction, bucketName, ""); s3Error != ErrNone {
		//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		//	return
		//}
		if checkoutTenantId(ctx, objAPI, bucketName, nil) != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	_, err := objAPI.GetBucketInfo(ctx, bucketName)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	//config, err := globalBucketMetadataSys.GetNotificationConfig(bucketName)
	//if err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}
	//config.SetRegion(globalServerRegion)
	//
	//configData, err := xml.Marshal(config)
	//if err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}
	//
	//writeSuccessResponseXML(w, configData)
}

// PutBucketNotificationHandler - This HTTP handler stores given notification configuration as per
// http://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html.
func (api objectAPIHandlers) PutBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "PutBucketNotification")

	defer logger.AuditLog(ctx, w, r)

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	if !objectAPI.IsNotificationSupported() {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL)
		return
	}

	vars := mux.Vars(r)
	bucketName := vars["bucket"]

	// 若PutBucketNotification请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.PutBucketNotificationAction, bucketName, ""); s3Error != ErrNone {
		//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		//	return
		//}
		if checkoutTenantId(ctx, objectAPI, bucketName, nil) != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	_, err := objectAPI.GetBucketInfo(ctx, bucketName)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// PutBucketNotification always needs a Content-Length.
	if r.ContentLength <= 0 {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL)
		return
	}

	//config, err := event.ParseConfig(io.LimitReader(r.Body, r.ContentLength), globalServerRegion, globalNotificationSys.targetList)
	//if err != nil {
	//	apiErr := errorCodes.ToAPIErr(ErrMalformedXML)
	//	if event.IsEventError(err) {
	//		apiErr = toAPIError(ctx, err)
	//	}
	//	writeErrorResponse(ctx, w, apiErr, r.URL)
	//	return
	//}
	//
	//configData, err := xml.Marshal(config)
	//if err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}
	//
	//if err = globalBucketMetadataSys.Update(bucketName, "", bucketNotificationConfig, configData); err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}
	//
	//rulesMap := config.ToRulesMap()
	//globalNotificationSys.AddRulesMap(bucketName, rulesMap)

	writeSuccessResponseHeadersOnly(w)
}
