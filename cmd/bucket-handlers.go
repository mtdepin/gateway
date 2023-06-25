package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/minio/minio-go/v7/pkg/tags"

	"github.com/gorilla/mux"
	"github.com/minio/minio/internal/config/storageclass"
	"github.com/minio/minio/internal/crypto"
	"github.com/minio/minio/internal/hash"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/pkg/bucket/policy"
	iampolicy "github.com/minio/pkg/iam/policy"
)

// GetBucketLocationHandler - GET Bucket location.
// -------------------------
// This operation returns bucket location.
func (api objectAPIHandlers) GetBucketLocationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetBucketLocation")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// 若GetBucketLocation请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	// Anonymous users, should be rejected.
	ai := globalIAMSys.GetAuthInfo(ctx)
	if ai == nil || ai.TenantId == 0 || ai.AuthType == authTypeAnonymous || ai.AuthType == authTypeUnknown {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		// todo 多租户的时候需要修改iam判断
		//if s3Error := checkRequestAuthType(ctx, r, policy.GetBucketLocationAction, bucket, ""); s3Error != ErrNone {
		//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		//	return
		//}
		if checkoutTenantId(ctx, objectAPI, bucket, nil) != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	getBucketInfo := objectAPI.GetBucketInfo

	bucketInfo, err := getBucketInfo(ctx, bucket)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Generate response.
	encodedSuccessResponse := encodeResponse(LocationResponse{})
	// Get current region.
	//region := globalServerRegion
	region := bucketInfo.Location
	if region != globalMinioDefaultRegion {
		encodedSuccessResponse = encodeResponse(LocationResponse{
			Location: region,
		})
	}

	// Write success response.
	writeSuccessResponseXML(w, encodedSuccessResponse)
}

// ListMultipartUploadsHandler - GET Bucket (List Multipart uploads)
// -------------------------
// This operation lists in-progress multipart uploads. An in-progress
// multipart upload is a multipart upload that has been initiated,
// using the Initiate Multipart Upload request, but has not yet been
// completed or aborted. This operation returns at most 1,000 multipart
// uploads in the response.
//
func (api objectAPIHandlers) ListMultipartUploadsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "ListMultipartUploads")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// 若ListBucketMultipartUploads请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.ListBucketMultipartUploadsAction, bucket, ""); s3Error != ErrNone {
		//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		//	return
		//}
		if checkoutTenantId(ctx, objectAPI, bucket, nil) != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	prefix, keyMarker, uploadIDMarker, delimiter, maxUploads, encodingType, errCode := getBucketMultipartResources(r.URL.Query())
	if errCode != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(errCode), r.URL)
		return
	}

	if maxUploads < 0 {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidMaxUploads), r.URL)
		return
	}

	if keyMarker != "" {
		// Marker not common with prefix is not implemented.
		if !HasPrefix(keyMarker, prefix) {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL)
			return
		}
	}

	listMultipartsInfo, err := objectAPI.ListMultipartUploads(ctx, bucket, prefix, keyMarker, uploadIDMarker, delimiter, maxUploads)
	if err != nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErrWithErr(ErrInternalError, err), r.URL)
		return
	}
	// generate response
	response := generateListMultipartUploadsResponse(bucket, listMultipartsInfo, encodingType)
	encodedSuccessResponse := encodeResponse(response)

	// write success response.
	writeSuccessResponseXML(w, encodedSuccessResponse)
}

// ListBucketsHandler - GET Service.
// -----------
// This implementation of the GET operation returns a list of all buckets
// owned by the authenticated sender of the request.
func (api objectAPIHandlers) ListBucketsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "ListBuckets")

	defer logger.AuditLog(ctx, w, r)

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// Anonymous users, should be rejected.
	ai := globalIAMSys.GetAuthInfo(ctx)
	if ai == nil || ai.TenantId == 0 || ai.AuthType == authTypeAnonymous || ai.AuthType == authTypeUnknown {
		logger.Error("Tenant info not found")
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	}

	listBuckets := objectAPI.ListBuckets
	s3Error := checkRequestAuthType(ctx, r, policy.ListAllMyBucketsAction, "", "")
	if s3Error != ErrNone && s3Error != ErrAccessDenied {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}

	// If etcd, dns federation configured list buckets from etcd.
	var bucketsInfo []BucketInfo

	// Invoke the list buckets.
	var err error
	bucketsInfo, err = listBuckets(ctx)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	//禁止匿名访问
	if false || s3Error == ErrAccessDenied {
		// Set prefix value for "s3:prefix" policy conditionals.
		r.Header.Set("prefix", "")

		// Set delimiter value for "s3:delimiter" policy conditionals.
		r.Header.Set("delimiter", SlashSeparator)

		// err will be nil here as we already called this function
		// earlier in this request.
		n := 0
		// Use the following trick to filter in place
		// https://github.com/golang/go/wiki/SliceTricks#filter-in-place
		for _, bucketInfo := range bucketsInfo {
			_, _, _, allow, _ := globalIAMSys.IsAllowed_2(r, iampolicy.Args{
				Action:     iampolicy.ListBucketAction,
				BucketName: bucketInfo.Name,
			})
			if allow {
				bucketsInfo[n] = bucketInfo
				n++
			}
		}
		bucketsInfo = bucketsInfo[:n]
		// No buckets can be filtered return access denied error.
		if len(bucketsInfo) == 0 {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
			return
		}
	}

	// Generate response.
	response := generateListBucketsResponse(bucketsInfo)
	encodedSuccessResponse := encodeResponse(response)

	// Write response.
	writeSuccessResponseXML(w, encodedSuccessResponse)
}

// DeleteMultipleObjectsHandler - deletes multiple objects.
func (api objectAPIHandlers) DeleteMultipleObjectsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "DeleteMultipleObjects")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// DeleteMultipleObjects需要先获取桶信息，暂时不允许匿名访问
	// 若DeleteMultipleObjects请求为匿名访问，拒绝访问
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		if checkoutTenantId(ctx, objectAPI, bucket, nil) != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	// Content-Md5 is requied should be set
	// http://docs.aws.amazon.com/AmazonS3/latest/API/multiobjectdeleteapi.html
	if _, ok := r.Header[xhttp.ContentMD5]; !ok {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentMD5), r.URL)
		return
	}

	// Content-Length is required and should be non-zero
	// http://docs.aws.amazon.com/AmazonS3/latest/API/multiobjectdeleteapi.html
	if r.ContentLength <= 0 {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL)
		return
	}

	// The max. XML contains 100000 object names (each at most 1024 bytes long) + XML overhead
	const maxBodySize = 2 * 100000 * 1024

	// Unmarshal list of keys to be deleted.
	deleteObjects := &DeleteObjectsRequest{}
	if err := xmlDecoder(r.Body, deleteObjects, maxBodySize); err != nil {
		logger.LogIf(ctx, err, logger.Application)
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Convert object name delete objects if it has `/` in the beginning.
	for i := range deleteObjects.Objects {
		deleteObjects.Objects[i].ObjectName = trimLeadingSlash(deleteObjects.Objects[i].ObjectName)
	}

	// Call checkRequestAuthType to populate ReqInfo.AccessKey before GetBucketInfo()
	// Ignore errors here to preserve the S3 error behavior of GetBucketInfo()
	checkRequestAuthType(ctx, r, policy.DeleteObjectAction, bucket, "")

	// Before proceeding validate if bucket exists.
	//bucketInfo, err := objectAPI.GetBucketInfo(ctx, bucket)
	bucketInfo, err := objectAPI.GetBucketInfoDetail(ctx, bucket)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	deleteObjectsFn := objectAPI.DeleteObjects
	//if api.CacheAPI() != nil {
	//	deleteObjectsFn = api.CacheAPI().DeleteObjects
	//}

	// Return Malformed XML as S3 spec if the list of objects is empty
	if len(deleteObjects.Objects) == 0 {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMalformedXML), r.URL)
		return
	}

	var objectsToDelete = map[ObjectToDelete]int{}
	getObjectInfoFn := objectAPI.GetObjectInfo
	//if api.CacheAPI() != nil {
	//	getObjectInfoFn = api.CacheAPI().GetObjectInfo
	//}
	var (
		goi  ObjectInfo
		gerr error
	)
	dErrs := make([]DeleteError, len(deleteObjects.Objects))
	objectMap := make(map[string]ObjectInfo)
	//oss := make([]*objSweeper, len(deleteObjects.Objects))
	for index, object := range deleteObjects.Objects {
		if apiErrCode := checkRequestAuthType(ctx, r, policy.DeleteObjectAction, bucket, object.ObjectName); apiErrCode != ErrNone {
			if apiErrCode == ErrSignatureDoesNotMatch || apiErrCode == ErrInvalidAccessKeyID {
				writeErrorResponse(ctx, w, errorCodes.ToAPIErr(apiErrCode), r.URL)
				return
			}
			apiErr := errorCodes.ToAPIErr(apiErrCode)
			dErrs[index] = DeleteError{
				Code:      apiErr.Code,
				Message:   apiErr.Description,
				Key:       object.ObjectName,
				VersionID: object.VersionID,
			}
			continue
		}
		if object.VersionID != "" && object.VersionID != nullVersionID {
			if _, err := uuid.Parse(object.VersionID); err != nil {
				logger.LogIf(ctx, fmt.Errorf("invalid version-id specified %w", err))
				apiErr := errorCodes.ToAPIErr(ErrNoSuchVersion)
				dErrs[index] = DeleteError{
					Code:      apiErr.Code,
					Message:   apiErr.Description,
					Key:       object.ObjectName,
					VersionID: object.VersionID,
				}
				continue
			}
		}

		//oss[index] = newObjSweeper(bucket, object.ObjectName).WithVersion(multiDelete(object))
		// Mutations of objects on versioning suspended buckets
		// affect its null version. Through opts below we select
		// the null version's remote object to delete if
		// transitioned.
		//opts := oss[index].GetOpts()
		opts, _ := delOpts(ctx, r, bucket, object.ObjectName)
		//opts := ObjectOptions{
		//	VersionID:        object.VersionID,
		//}
		//if opts.VersionID == "" {
		//	opts.VersionID = nullVersionID
		//}
		goi, gerr = getObjectInfoFn(ctx, bucket, object.ObjectName, opts)
		if gerr == nil {
			//oss[index].SetTransitionState(goi)
			objectMap[object.ObjectName] = goi
		}

		// Avoid duplicate objects, we use map to filter them out.
		if _, ok := objectsToDelete[object]; !ok {
			objectsToDelete[object] = index
		}
	}

	toNames := func(input map[ObjectToDelete]int) (output []ObjectToDelete) {
		output = make([]ObjectToDelete, len(input))
		idx := 0
		for obj := range input {
			output[idx] = obj
			idx++
		}
		return
	}

	deleteList := toNames(objectsToDelete)
	dObjects, errs := deleteObjectsFn(ctx, bucket, deleteList, ObjectOptions{
		Versioned:        globalBucketVersioningSys.Enabled(bucket),
		VersionSuspended: globalBucketVersioningSys.Suspended(bucket),
	})
	deletedObjects := make([]DeletedObject, len(deleteObjects.Objects))
	for i := range errs {
		// DeleteMarkerVersionID is not used specifically to avoid
		// lookup errors, since DeleteMarkerVersionID is only
		// created during DeleteMarker creation when client didn't
		// specify a versionID.
		objToDel := ObjectToDelete{
			ObjectName:                    dObjects[i].ObjectName,
			VersionID:                     dObjects[i].VersionID,
			DeleteMarkerReplicationStatus: dObjects[i].DeleteMarkerReplicationStatus,
		}
		dindex := objectsToDelete[objToDel]
		if errs[i] == nil {
			deletedObjects[dindex] = dObjects[i]
			continue
		}
		apiErr := toAPIError(ctx, errs[i])
		dErrs[dindex] = DeleteError{
			Code:      apiErr.Code,
			Message:   apiErr.Description,
			Key:       deleteList[i].ObjectName,
			VersionID: deleteList[i].VersionID,
		}
	}

	var deleteErrors []DeleteError
	for _, dErr := range dErrs {
		if dErr.Code != "" {
			deleteErrors = append(deleteErrors, dErr)
		}
	}

	// Generate response
	response := generateMultiDeleteResponse(deleteObjects.Quiet, deletedObjects, deleteErrors)
	encodedSuccessResponse := encodeResponse(response)

	// Write success response.
	writeSuccessResponseXML(w, encodedSuccessResponse)
	for _, dobj := range deletedObjects {
		if obj, ok := objectMap[dobj.ObjectName]; ok {
			//send to charge
			obj.Size = dobj.Size
			SendToCharge(ctx, CHARGE_DELETE, bucketInfo, obj)
		}
	}
}

// PutBucketHandler - PUT Bucket
// ----------
// This implementation of the PUT operation creates a new bucket for authenticated request
func (api objectAPIHandlers) PutBucketHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "PutBucket")

	defer logger.AuditLog(ctx, w, r)

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	ai := globalIAMSys.GetAuthInfo(ctx)
	if ai == nil || ai.TenantId == 0 || ai.AuthType == authTypeAnonymous || ai.AuthType == authTypeUnknown {
		logger.Error("Tenant info not found")
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	}

	// 验证IAM策略，checkRequestAuthType内部已验证
	if s3Error := checkRequestAuthType(ctx, r, policy.CreateBucketAction, bucket, ""); s3Error != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}

	//check user quota
	bucketList, err := objectAPI.ListBuckets(ctx)
	if err != nil {
		logger.Error(err)
		writeErrorResponse(ctx, w, errorCodes.ToAPIErrWithErr(ErrInternalError, err), r.URL)
		return
	}

	//todo : check quota
	//tenantInfo := globalIAMSys.GetTenantInfo(r, ai)
	//userQuota := uq.(int)
	if len(bucketList) >= 100 {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAdminBucketQuotaExceeded), r.URL)
		return
	}

	// Parse incoming location constraint and storageclass.
	location, sc, s3Error := parsePutBucketConfig(r)
	if s3Error != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}

	// Validate if location sent by the client is valid, reject
	// requests which do not follow valid region requirements.
	//todo check valid location
	if !isValidLocation(location) {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidRegion), r.URL)
		return
	}

	// storageclass .
	if sc != "" && !storageclass.IsValid(sc) {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidStorageClass), r.URL)
		return
	} else if sc == "" {
		sc = storageclass.STANDARD
	}

	opts := BucketOptions{
		Location:     location,
		StorageClass: sc,
		Acl:          r.Header.Get(xhttp.AmzACL),
	}

	// Proceed to creating a bucket.
	err = objectAPI.MakeBucketWithLocation(ctx, bucket, opts)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Make sure to add Location information here only for bucket
	if cp := pathClean(r.URL.Path); cp != "" {
		w.Header().Set(xhttp.Location, cp) // Clean any trailing slashes.
	}

	writeSuccessResponseHeadersOnly(w)
}

// PostPolicyBucketHandler - POST policy
// ----------
// This implementation of the POST operation handles object creation with a specified
// signature policy in multipart/form-data
func (api objectAPIHandlers) PostPolicyBucketHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "PostPolicyBucket")

	defer logger.AuditLog(ctx, w, r)

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	if crypto.S3KMS.IsRequested(r.Header) { // SSE-KMS is not supported
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL)
		return
	}

	if _, ok := crypto.IsRequested(r.Header); !objectAPI.IsEncryptionSupported() && ok {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL)
		return
	}
	bucket := mux.Vars(r)["bucket"]
	// 若ListBucketMultipartUploads请求为匿名访问，拒绝访问
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		if checkoutTenantId(ctx, objectAPI, bucket, nil) != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	// Require Content-Length to be set in the request
	size := r.ContentLength
	if size < 0 {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL)
		return
	}

	resource, err := getResource(r.URL.Path, r.Host, globalDomainNames)
	if err != nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidRequest), r.URL)
		return
	}

	// Make sure that the URL does not contain object name.
	if bucket != path.Clean(resource[1:]) {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMethodNotAllowed), r.URL)
		return
	}

	// Here the parameter is the size of the form data that should
	// be loaded in memory, the remaining being put in temporary files.
	reader, err := r.MultipartReader()
	if err != nil {
		logger.LogIf(ctx, err)
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMalformedPOSTRequest), r.URL)
		return
	}

	// Read multipart data and save in memory and in the disk if needed
	form, err := reader.ReadForm(maxFormMemory)
	if err != nil {
		logger.LogIf(ctx, err, logger.Application)
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMalformedPOSTRequest), r.URL)
		return
	}

	// Remove all tmp files created during multipart upload
	defer form.RemoveAll()

	// Extract all form fields
	fileBody, fileName, fileSize, formValues, err := extractPostPolicyFormValues(ctx, form)
	if err != nil {
		logger.LogIf(ctx, err, logger.Application)
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMalformedPOSTRequest), r.URL)
		return
	}

	// Check if file is provided, error out otherwise.
	if fileBody == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrPOSTFileRequired), r.URL)
		return
	}

	// Close multipart file
	defer fileBody.Close()

	formValues.Set("Bucket", bucket)
	if fileName != "" && strings.Contains(formValues.Get("Key"), "${filename}") {
		// S3 feature to replace ${filename} found in Key form field
		// by the filename attribute passed in multipart
		formValues.Set("Key", strings.Replace(formValues.Get("Key"), "${filename}", fileName, -1))
	}
	object := trimLeadingSlash(formValues.Get("Key"))

	successRedirect := formValues.Get("success_action_redirect")
	successStatus := formValues.Get("success_action_status")
	var redirectURL *url.URL
	if successRedirect != "" {
		redirectURL, err = url.Parse(successRedirect)
		if err != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMalformedPOSTRequest), r.URL)
			return
		}
	}

	_, _, _, isallow, _ := globalIAMSys.IsAllowed_2(r, iampolicy.Args{
		Action:     iampolicy.PutObjectAction,
		BucketName: bucket,
		ObjectName: object,
	})

	if !isallow {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	}

	//if !globalIAMSys.IsAllowed(iampolicy.Args{
	//	AccountName:     cred.AccessKey,
	//	Action:          iampolicy.PutObjectAction,
	//	ConditionValues: getConditionValues(r, "", cred.AccessKey, claims),
	//	BucketName:      bucket,
	//	ObjectName:      object,
	//	IsOwner:         owner,
	//	Claims:          claims,
	//}) {
	//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
	//	return
	//}

	policyBytes, err := base64.StdEncoding.DecodeString(formValues.Get("Policy"))
	if err != nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMalformedPOSTRequest), r.URL)
		return
	}

	// Handle policy if it is set.
	if len(policyBytes) > 0 {
		postPolicyForm, err := parsePostPolicyForm(bytes.NewReader(policyBytes))
		if err != nil {
			errAPI := errorCodes.ToAPIErr(ErrPostPolicyConditionInvalidFormat)
			errAPI.Description = fmt.Sprintf("%s '(%s)'", errAPI.Description, err)
			writeErrorResponse(ctx, w, errAPI, r.URL)
			return
		}

		// Make sure formValues adhere to policy restrictions.
		if err = checkPostPolicy(formValues, postPolicyForm); err != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErrWithErr(ErrAccessDenied, err), r.URL)
			return
		}

		// Ensure that the object size is within expected range, also the file size
		// should not exceed the maximum single Put size (5 GiB)
		lengthRange := postPolicyForm.Conditions.ContentLengthRange
		if lengthRange.Valid {
			if fileSize < lengthRange.Min {
				writeErrorResponse(ctx, w, toAPIError(ctx, errDataTooSmall), r.URL)
				return
			}

			if fileSize > lengthRange.Max || isMaxObjectSize(fileSize) {
				writeErrorResponse(ctx, w, toAPIError(ctx, errDataTooLarge), r.URL)
				return
			}
		}
	}

	// Extract metadata to be saved from received Form.
	metadata := make(map[string]string)
	err = extractMetadataFromMime(ctx, textproto.MIMEHeader(formValues), metadata)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	hashReader, err := hash.NewReader(fileBody, fileSize, "", "", fileSize)
	if err != nil {
		logger.LogIf(ctx, err)
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	rawReader := hashReader
	pReader := NewPutObjReader(rawReader)
	var objectEncryptionKey crypto.ObjectKey

	// get gateway encryption options
	var opts ObjectOptions
	opts, err = putOpts(ctx, r, bucket, object, metadata)
	if err != nil {
		writeErrorResponseHeadersOnly(w, toAPIError(ctx, err))
		return
	}
	if objectAPI.IsEncryptionSupported() {
		if _, ok := crypto.IsRequested(formValues); ok && !HasSuffix(object, SlashSeparator) { // handle SSE requests
			if crypto.SSECopy.IsRequested(r.Header) {
				writeErrorResponse(ctx, w, toAPIError(ctx, errInvalidEncryptionParameters), r.URL)
				return
			}
			var (
				reader io.Reader
				keyID  string
				key    []byte
				kmsCtx kms.Context
			)
			kind, _ := crypto.IsRequested(formValues)
			switch kind {
			case crypto.SSEC:
				key, err = ParseSSECustomerHeader(formValues)
				if err != nil {
					writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
					return
				}
			case crypto.S3KMS:
				keyID, kmsCtx, err = crypto.S3KMS.ParseHTTP(formValues)
				if err != nil {
					writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
					return
				}
			}
			reader, objectEncryptionKey, err = newEncryptReader(hashReader, kind, keyID, key, bucket, object, metadata, kmsCtx)
			if err != nil {
				writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
				return
			}
			info := ObjectInfo{Size: fileSize}
			// do not try to verify encrypted content
			hashReader, err = hash.NewReader(reader, info.EncryptedSize(), "", "", fileSize)
			if err != nil {
				writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
				return
			}
			pReader, err = pReader.WithEncryption(hashReader, &objectEncryptionKey)
			if err != nil {
				writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
				return
			}
		}
	}
	if opts.UserDefined[xhttp.AmzStorageClass] == "" {
		info, _ := objectAPI.GetBucketInfo(ctx, bucket)
		opts.UserDefined[xhttp.AmzStorageClass] = info.StorageClass
	}
	objInfo, err := objectAPI.PutObject(ctx, bucket, object, pReader, opts)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// We must not use the http.Header().Set method here because some (broken)
	// clients expect the ETag header key to be literally "ETag" - not "Etag" (case-sensitive).
	// Therefore, we have to set the ETag directly as map entry.
	w.Header()[xhttp.ETag] = []string{`"` + objInfo.ETag + `"`}

	// Set the relevant version ID as part of the response header.
	if objInfo.VersionID != "" {
		w.Header()[xhttp.AmzVersionID] = []string{objInfo.VersionID}
	}

	w.Header().Set(xhttp.Location, getObjectLocation(r, globalDomainNames, bucket, object))

	if successRedirect != "" {
		// Replace raw query params..
		redirectURL.RawQuery = getRedirectPostRawQuery(objInfo)
		writeRedirectSeeOther(w, redirectURL.String())
		return
	}

	// Decide what http response to send depending on success_action_status parameter
	switch successStatus {
	case "201":
		resp := encodeResponse(PostResponse{
			Bucket:   objInfo.Bucket,
			Key:      objInfo.Name,
			ETag:     `"` + objInfo.ETag + `"`,
			Location: w.Header().Get(xhttp.Location),
		})
		writeResponse(w, http.StatusCreated, resp, mimeXML)
	case "200":
		writeSuccessResponseHeadersOnly(w)
	default:
		writeSuccessNoContent(w)
	}
}

// GetBucketPolicyStatusHandler -  Retrieves the policy status
// for an MinIO bucket, indicating whether the bucket is public.
func (api objectAPIHandlers) GetBucketPolicyStatusHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetBucketPolicyStatus")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(ErrServerNotInitialized))
		return
	}

	// 若GetBucketPolicyStatus请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.GetBucketPolicyStatusAction, bucket, ""); s3Error != ErrNone {
		//	writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(s3Error))
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

	// 目前桶相关操作暂时不允许匿名访问
	var readable, writable bool
	//
	// Check if anonymous (non-owner) has access to list objects.
	//readable := globalPolicySys.IsAllowed(policy.Args{
	//	Action:          policy.ListBucketAction,
	//	BucketName:      bucket,
	//	ConditionValues: getConditionValues(r, "", "", nil),
	//	IsOwner:         false,
	//})
	//
	//// Check if anonymous (non-owner) has access to upload objects.
	//writable := globalPolicySys.IsAllowed(policy.Args{
	//	Action:          policy.PutObjectAction,
	//	BucketName:      bucket,
	//	ConditionValues: getConditionValues(r, "", "", nil),
	//	IsOwner:         false,
	//})

	encodedSuccessResponse := encodeResponse(PolicyStatus{
		IsPublic: func() string {
			// Silly to have special 'boolean' values yes
			// but complying with silly implementation
			// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicyStatus.html
			if readable && writable {
				return "TRUE"
			}
			return "FALSE"
		}(),
	})

	writeSuccessResponseXML(w, encodedSuccessResponse)
}

// HeadBucketHandler - HEAD Bucket
// ----------
// This operation is useful to determine if a bucket exists.
// The operation returns a 200 OK if the bucket exists and you
// have permission to access it. Otherwise, the operation might
// return responses such as 404 Not Found and 403 Forbidden.
func (api objectAPIHandlers) HeadBucketHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "HeadBucket")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(ErrServerNotInitialized))
		return
	}

	// 若HeadBucket请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.ListBucketAction, bucket, ""); s3Error != ErrNone {
		//	writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(s3Error))
		//	return
		//}
		err := checkoutTenantId(ctx, objectAPI, bucket, nil)
		if err != nil && strings.Contains(err.Error(), "桶不属于该账号的租户") {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	getBucketInfo := objectAPI.GetBucketInfo

	if _, err := getBucketInfo(ctx, bucket); err != nil {
		writeErrorResponseHeadersOnly(w, toAPIError(ctx, err))
		return
	}

	writeSuccessResponseHeadersOnly(w)
}

// GetBucketInfoDetailHandler - GET Bucket Info Detail
// ----------
// This operation will return bucket infomation as detailed as possible.
// The operation returns a 200 OK if the bucket exists and you
// have permission to access it. Otherwise, the operation might
// return responses such as 404 Not Found and 403 Forbidden.
func (api objectAPIHandlers) GetBucketInfoDetailHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetBucketInfoDetail")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(ErrServerNotInitialized))
		return
	}

	// 若GetBucketInfoDetail请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.ListBucketAction, bucket, ""); s3Error != ErrNone {
		//	writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(s3Error))
		//	return
		//}
	}

	getBucketInfoDetail := objectAPI.GetBucketInfoDetail

	bucketinfodetail, err := getBucketInfoDetail(ctx, bucket)
	if err != nil {
		writeErrorResponseHeadersOnly(w, toAPIError(ctx, err))
		return
	}
	if checkoutTenantId(ctx, objectAPI, bucket, &bucketinfodetail) != nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	}
	configData, err := xml.Marshal(bucketinfodetail)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	writeSuccessResponseXML(w, configData)
}

// DeleteBucketHandler - Delete bucket
func (api objectAPIHandlers) DeleteBucketHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "DeleteBucket")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// 若DeleteBucket请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		// Verify if the caller has sufficient permissions.
		//if s3Error := checkRequestAuthType(ctx, r, policy.DeleteBucketAction, bucket, ""); s3Error != ErrNone {
		//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		//	return
		//}
		if checkoutTenantId(ctx, objectAPI, bucket, nil) != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	forceDelete := false
	if value := r.Header.Get(xhttp.MinIOForceDelete); value != "" {
		var err error
		forceDelete, err = strconv.ParseBool(value)
		if err != nil {
			apiErr := errorCodes.ToAPIErr(ErrInvalidRequest)
			apiErr.Description = err.Error()
			writeErrorResponse(ctx, w, apiErr, r.URL)
			return
		}

		// if force delete header is set, we need to evaluate the policy anyways
		// regardless of it being true or not.
		if s3Error := checkRequestAuthType(ctx, r, policy.ForceDeleteBucketAction, bucket, ""); s3Error != ErrNone {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
			return
		}

	}

	deleteBucket := objectAPI.DeleteBucket

	// Attempt to delete bucket.
	if err := deleteBucket(ctx, bucket, forceDelete); err != nil {
		apiErr := toAPIError(ctx, err)
		if _, ok := err.(BucketNotEmpty); ok {
			if globalBucketVersioningSys.Enabled(bucket) || globalBucketVersioningSys.Suspended(bucket) {
				apiErr.Description = "The bucket you tried to delete is not empty. You must delete all versions in the bucket."
			}
		}
		writeErrorResponse(ctx, w, apiErr, r.URL)
		return
	}

	//globalNotificationSys.DeleteBucketMetadata(ctx, bucket)

	// Write success response.
	writeSuccessNoContent(w)
}

// GetBucketObjectLockConfigHandler - GET Bucket object lock configuration.
// ----------
// Gets the Object Lock configuration for a bucket. The rule specified in
// the Object Lock configuration will be applied by default to every new
// object placed in the specified bucket.
func (api objectAPIHandlers) GetBucketObjectLockConfigHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetBucketObjectLockConfig")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// 若GetBucketObjectLockConfig请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		// check if user has permissions to perform this operation
		//if s3Error := checkRequestAuthType(ctx, r, policy.GetBucketObjectLockConfigurationAction, bucket, ""); s3Error != ErrNone {
		//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		//	return
		//}
		if checkoutTenantId(ctx, objectAPI, bucket, nil) != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	//config, err := globalBucketMetadataSys.GetObjectLockConfig(bucket)
	//if err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}
	//
	//configData, err := xml.Marshal(config)
	//if err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}
	//
	//// Write success response.
	//writeSuccessResponseXML(w, configData)
}

// PutBucketTaggingHandler - PUT Bucket tagging.
// ----------
func (api objectAPIHandlers) PutBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "PutBucketTagging")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// 若PutBucketTagging请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.PutBucketTaggingAction, bucket, ""); s3Error != ErrNone {
		//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		//	return
		//}
		if checkoutTenantId(ctx, objectAPI, bucket, nil) != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	tags, err := tags.ParseBucketXML(io.LimitReader(r.Body, r.ContentLength))
	if err != nil {
		apiErr := errorCodes.ToAPIErr(ErrMalformedXML)
		apiErr.Description = err.Error()
		writeErrorResponse(ctx, w, apiErr, r.URL)
		return
	}

	opts, err := getOpts(ctx, r, bucket, "")
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	_, err = objectAPI.GetBucketInfo(ctx, bucket)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	tagsStr := tags.String()

	_, err = objectAPI.PutBucketTags(ctx, bucket, tagsStr, opts)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Write success response.
	writeSuccessResponseHeadersOnly(w)
}

// GetBucketTaggingHandler - GET Bucket tagging.
// ----------
func (api objectAPIHandlers) GetBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetBucketTagging")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	if !objectAPI.IsTaggingSupported() {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL)
		return
	}

	// 若GetBucketTagging请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		// check if user has permissions to perform this operation
		//if s3Error := checkRequestAuthType(ctx, r, policy.GetBucketTaggingAction, bucket, ""); s3Error != ErrNone {
		//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		//	return
		//}
		if checkoutTenantId(ctx, objectAPI, bucket, nil) != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	opts, err := getOpts(ctx, r, bucket, "")
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Get object tags
	tags, err := objectAPI.GetBucketTags(ctx, bucket, opts)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	configData, err := xml.Marshal(tags)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Write success response.
	writeSuccessResponseXML(w, configData)
}

// DeleteBucketTaggingHandler - DELETE Bucket tagging.
// ----------
func (api objectAPIHandlers) DeleteBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "DeleteBucketTagging")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// 若DeleteBucketTagging请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.PutBucketTaggingAction, bucket, ""); s3Error != ErrNone {
		//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		//	return
		//}
		if checkoutTenantId(ctx, objectAPI, bucket, nil) != nil {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
			return
		}
	}

	opts, err := getOpts(ctx, r, bucket, "")
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	//oi, err := objectAPI.GetObjectInfo(ctx, bucket, opts)
	//if err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}

	_, err = objectAPI.DeleteBucketTags(ctx, bucket, opts)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Write success response.
	writeSuccessResponseHeadersOnly(w)
}

// GetBucketReplicationConfigHandler - GET Bucket replication configuration.
// ----------
// Gets the replication configuration for a bucket.
func (api objectAPIHandlers) GetBucketReplicationConfigHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetBucketReplicationConfig")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// 若GetBucketReplicationConfig请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		// check if user has permissions to perform this operation
		//if s3Error := checkRequestAuthType(ctx, r, policy.GetReplicationConfigurationAction, bucket, ""); s3Error != ErrNone {
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

	//config, err := globalBucketMetadataSys.GetReplicationConfig(ctx, bucket)
	//if err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}
	config := struct{}{}
	configData, err := xml.Marshal(config)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Write success response.
	writeSuccessResponseXML(w, configData)
}

// DeleteBucketReplicationConfigHandler - DELETE Bucket replication config.
// ----------
func (api objectAPIHandlers) DeleteBucketReplicationConfigHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "DeleteBucketReplicationConfig")
	defer logger.AuditLog(ctx, w, r)
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// 若DeleteBucketReplicationConfig请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.PutReplicationConfigurationAction, bucket, ""); s3Error != ErrNone {
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
	//if err := globalBucketMetadataSys.Update(bucket, "", bucketReplicationConfig, nil); err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}

	// Write success response.
	writeSuccessResponseHeadersOnly(w)
}

// GetBucketReplicationMetricsHandler - GET Bucket replication metrics.
// ----------
// Gets the replication metrics for a bucket.
func (api objectAPIHandlers) GetBucketReplicationMetricsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetBucketReplicationMetrics")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// 若GetBucketReplicationMetrics请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		// check if user has permissions to perform this operation
		//if s3Error := checkRequestAuthType(ctx, r, policy.GetReplicationConfigurationAction, bucket, ""); s3Error != ErrNone {
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

	w.(http.Flusher).Flush()
}

// ResetBucketReplicationStateHandler - starts a replication reset for all objects in a bucket which
// qualify for replication and re-sync the object(s) to target, provided ExistingObjectReplication is
// enabled for the qualifying rule. This API is a MinIO only extension provided for situations where
// remote target is entirely lost,and previously replicated objects need to be re-synced.
func (api objectAPIHandlers) ResetBucketReplicationStateHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "ResetBucketReplicationState")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	//durationStr := r.URL.Query().Get("older-than")
	//var (
	//	days time.Duration
	//	err  error
	//)
	//if durationStr != "" {
	//	days, err = time.ParseDuration(durationStr)
	//	if err != nil {
	//		writeErrorResponse(ctx, w, toAPIError(ctx, InvalidArgument{
	//			Bucket: bucket,
	//			Err:    fmt.Errorf("invalid query parameter older-than %s for %s : %w", durationStr, bucket, err),
	//		}), r.URL)
	//	}
	//}

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// 若ResetBucketReplicationState请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
	if getRequestAuthType(r) == authTypeAnonymous {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	} else {
		//if s3Error := checkRequestAuthType(ctx, r, policy.ResetBucketReplicationStateAction, bucket, ""); s3Error != ErrNone {
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

	//config, err := globalBucketMetadataSys.GetReplicationConfig(ctx, bucket)
	//if err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}
	//if !config.HasActiveRules("", true) {
	//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrReplicationNoMatchingRuleError), r.URL)
	//	return
	//}
	//target := globalBucketTargetSys.GetRemoteBucketTargetByArn(ctx, bucket, config.RoleArn)
	//target.ResetBeforeDate = UTCNow().AddDate(0, 0, -1*int(days/24))
	//target.ResetID = mustGetUUID()
	//if err = globalBucketTargetSys.SetTarget(ctx, bucket, &target, true); err != nil {
	//	switch err.(type) {
	//	case BucketRemoteConnectionErr:
	//		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErrWithErr(ErrReplicationRemoteConnectionError, err), r.URL)
	//	default:
	//		writeErrorResponseJSON(ctx, w, toAPIError(ctx, err), r.URL)
	//	}
	//	return
	//}
	//targets, err := globalBucketTargetSys.ListBucketTargets(ctx, bucket)
	//if err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}
	//tgtBytes, err := json.Marshal(&targets)
	//if err != nil {
	//	writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErrWithErr(ErrAdminConfigBadJSON, err), r.URL)
	//	return
	//}
	//if err = globalBucketMetadataSys.Update(bucket, "", bucketTargetsFile, tgtBytes); err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}
	//data, err := json.Marshal(target.ResetID)
	//if err != nil {
	//	writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
	//	return
	//}
	data := []byte("")
	// Write success response.
	writeSuccessResponseJSON(w, data)
}
