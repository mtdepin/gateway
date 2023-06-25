package cmd

import (
	"encoding/xml"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/pkg/bucket/policy"
)

const (
	// PublicReadWrite 公开读写，适用于桶ACL和对象ACL
	PublicReadWrite = "public-read-write"
	// PublicRead 公开读，适用于桶ACL和对象ACL
	PublicRead = "public-read"
	// Private 私有，适用于桶ACL和对象ACL
	Private = "private"
	// Default 默认，适用于对象ACL
	Default = "default"
)

// Data types used for returning dummy access control
// policy XML, these variables shouldn't be used elsewhere
// they are only defined to be used in this file alone.
type grantee struct {
	XMLNS       string `xml:"xmlns:xsi,attr"`
	XMLXSI      string `xml:"xsi:type,attr"`
	Type        string `xml:"Type"`
	ID          string `xml:"ID,omitempty"`
	DisplayName string `xml:"DisplayName,omitempty"`
	URI         string `xml:"URI,omitempty"`
}

type grant struct {
	// todo，暂注释掉
	Grantee    grantee `xml:"Grantee"`
	Permission string  `xml:"Permission"`
	//Permission string `xml:"Grant"`
}

type accessControlPolicy struct {
	XMLName           xml.Name `xml:"AccessControlPolicy"`
	Owner             Owner    `xml:"Owner"`
	AccessControlList struct {
		// todo，暂注释掉
		Grants []grant `xml:"Grant"`
		//Grant string `xml:"Grant"`
	} `xml:"AccessControlList"`
}

func checkPermissionType(s string) bool {
	switch s {
	case PublicRead:
		return true
	case PublicReadWrite:
		return true
	case Private:
		return true
	case Default, "":
		return true
	}
	return false
}

// 上传对象时设置object ACL，目前只支持private | public-read | public-read-write | default
// 如果传其他的，默认default
func checkPutObjectACL(acl string) string {
	switch acl {
	case PublicRead:
		return acl
	case PublicReadWrite:
		return acl
	case Private:
		return acl
	default:
		return Default
	}
}

// bucket ACL: 包括public-read-write（公开读写）、public-read（公开读）和private（私有），
// 支持创建（PUT）、更新（PUT）、查询（GET）、删除(DELETE)。
// private（私有）:只有该Bucket的Owner或者授权对象可以对存放在其中的Object进行读、写、删除操作；其他人在未经授权的情况下无法访问该Bucket内的 Object。
// public-read（公开读）:	只有该Bucket的Owner或者授权对象可以对存放在其中的Object进行写、删除操作；任何人（包括匿名访问）可以对Object进行读操作。
// public-read-write（公开读写）:任何人（包括匿名访问）都可以对该Bucket中的Object进行读、写、删除操作。

// PutBucketACLHandler - PUT Bucket ACL
// -----------------
// This operation uses the ACL subresource
// to set ACL for a bucket, this is a dummy call
// only responds success if the ACL is private.
func (api objectAPIHandlers) PutBucketACLHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "PutBucketACL")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	//acl := vars["acl"]
	//if acl == "" {
	//	acl = Default
	//}

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// Allow putBucketACL if policy action is set, since this is a dummy call
	// we are simply re-purposing the bucketPolicyAction.
	// 暂时使用PutBucketPolicy替代PutBucketACL
	// TODO：
	// 支持PutBucketACL， 需要在策略支持的action中增加PutBucketACL，
	// 可参考https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazons3.html。

	// 若PutBucketACL请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
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

	// Before proceeding validate if bucket exists.
	_, err := objAPI.GetBucketInfo(ctx, bucket)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	aclHeader := r.Header.Get(xhttp.AmzACL)
	if aclHeader == "" {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidRequestParameter), r.URL)
		return
	}
	if !checkPermissionType(aclHeader) {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidRequestParameter), r.URL)
		return
	}

	// 设置bucket acl
	if err = objAPI.SetBucketACL(ctx, bucket, aclHeader); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	writeSuccessResponseHeadersOnly(w)
}

// GetBucketACLHandler - GET Bucket ACL
// -----------------
// This operation uses the ACL
// subresource to return the ACL of a specified bucket.
func (api objectAPIHandlers) GetBucketACLHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetBucketACL")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// Allow getBucketACL if policy action is set, since this is a dummy call
	// we are simply re-purposing the bucketPolicyAction.
	// 暂时使用GetBucketPolicy替代GetBucketACL
	// TODO：
	// 支持GetBucketACL， 需要在策略支持的action中增加GetBucketACL，
	// 可参考https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazons3.html。
	// 若GetBucketACL请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
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

	// Before proceeding validate if bucket exists.
	_, err := objAPI.GetBucketInfo(ctx, bucket)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// 查询bucket acl
	acl, err := objAPI.GetBucketACL(ctx, bucket)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	// 校验桶ACL类型，公共读(PublicRead)，公共读写(PublicReadWrite)，私有(Private)
	if acl == "" {
		acl = "private"
	}
	if !checkPermissionType(acl) {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInternalError), r.URL)
		return
	}

	bucketACL := &accessControlPolicy{}
	bucketACL.AccessControlList.Grants = append(bucketACL.AccessControlList.Grants, grant{
		Grantee: grantee{
			XMLNS: "http://www.w3.org/2001/XMLSchema-instance",
		},
		Permission: acl,
	})

	writeSuccessResponseXML(w, encodeResponse(bucketACL))

	//writeSuccessResponseXML()
	//w.Write([]byte("<?xml version=\"1.0\" encoding=\"utf-8\"?>"))
	//encoder := xml.NewEncoder(w)
	//encoder.Indent("", "\t")
	//if err = encoder.Encode(bucketACL); err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}
	//
	//w.(http.Flusher).Flush()
}

// DeleteBucketACLHandler - Delete Bucket ACL
// -----------------
// This operation uses the ACL subresource
// to set ACL for a bucket, this is a dummy call
// only responds success if the ACL is private.
func (api objectAPIHandlers) DeleteBucketACLHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "DeleteBucketACL")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// Allow putBucketACL if policy action is set, since this is a dummy call
	// we are simply re-purposing the bucketPolicyAction.
	//if s3Error := checkRequestAuthType(ctx, r, policy.PutBucketPolicyAction, bucket, ""); s3Error != ErrNone {
	//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
	//	return
	//}

	// 这里对源代码进行修改，使用DeleteBucketPolicy替代DeleteBucketACL
	// TODO：
	// 支持DeleteBucketACL， 需要在策略支持的action中增加DeleteBucketACL，
	// 可参考https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazons3.html。
	// 若DeleteBucketACL请求为匿名访问，拒绝访问；否则，判断IAM和桶策略
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

	// Before proceeding validate if bucket exists.
	_, err := objAPI.GetBucketInfo(ctx, bucket)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// 删除bucket acl
	if err = objAPI.DeleteBucketACL(ctx, bucket); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	writeSuccessResponseHeadersOnly(w)

	//aclHeader := r.Header.Get(xhttp.AmzACL)
	//if aclHeader == "" {
	//	acl := &accessControlPolicy{}
	//	if err = xmlDecoder(r.Body, acl, r.ContentLength); err != nil {
	//		if err == io.EOF {
	//			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingSecurityHeader),
	//				r.URL)
	//			return
	//		}
	//		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//		return
	//	}
	//
	//	if len(acl.AccessControlList.Grants) == 0 {
	//		writeErrorResponse(ctx, w, toAPIError(ctx, NotImplemented{}), r.URL)
	//		return
	//	}
	//
	//	if acl.AccessControlList.Grants[0].Permission != "FULL_CONTROL" {
	//		writeErrorResponse(ctx, w, toAPIError(ctx, NotImplemented{}), r.URL)
	//		return
	//	}
	//}
	//
	//if aclHeader != "" && aclHeader != "private" {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, NotImplemented{}), r.URL)
	//	return
	//}
	//
	//w.(http.Flusher).Flush()
}

// object ACL：包括private（私有）、public-read（公开读）、public-read-write（公开读写）、default（默认），
// 支持创建（PUT）、更新（PUT）、查询（GET）、删除(DELETE)。
// private（私有）:该ACL表明某个Object是私有资源，即只有该Object的Owner拥有该Object的读写权限，其他的用户没有权限操作该Object。
// public-read（公开读）:	该ACL表明某个Object是公共读资源，即非Object Owner只有该Object的读权限，而Object Owner拥有该Object的读写权限。
// public-read-write（公开读写）:该ACL表明某个Object是公共读写资源，即所有用户拥有对该Object的读写权限。
// default（默认）:该ACL表明某个Object是遵循Bucket读写权限的资源，即Bucket是什么权限，Object就是什么权限。

// PutObjectACLHandler - PUT Object ACL
// -----------------
// This operation uses the ACL subresource
// to set ACL for a bucket, this is a dummy call
// only responds success if the ACL is private.
func (api objectAPIHandlers) PutObjectACLHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "PutObjectACL")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)

	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// Allow putObjectACL if policy action is set, since this is a dummy call
	// we are simply re-purposing the bucketPolicyAction.
	//if s3Error := checkRequestAuthType(ctx, r, policy.PutBucketPolicyAction, bucket, ""); s3Error != ErrNone {
	//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
	//	return
	//}

	// 这里对源代码进行修改，使用PutObject替代PutObjectACL
	// TODO：
	// 支持PutObjectACL， 需要在策略支持的action中增加PutObjectACL，
	// 可参考https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazons3.html。
	//if s3Error := checkRequestAuthType(ctx, r, policy.PutObjectAction, bucket, ""); s3Error != ErrNone {
	//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
	//	return
	//}
	if checkoutTenantId(ctx, objAPI, bucket, nil) != nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	}

	// Before proceeding validate if object exists.
	_, err = objAPI.GetObjectInfo(ctx, bucket, object, ObjectOptions{})
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	aclHeader := r.Header.Get(xhttp.AmzACL)
	if aclHeader == "" {
		acl := &accessControlPolicy{}
		if err = xmlDecoder(r.Body, acl, r.ContentLength); err != nil {
			if err == io.EOF {
				writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingSecurityHeader),
					r.URL)
				return
			}
			writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
			return
		}

		if len(acl.AccessControlList.Grants) == 0 {
			writeErrorResponse(ctx, w, toAPIError(ctx, NotImplemented{}), r.URL)
			return
		}

		if acl.AccessControlList.Grants[0].Permission == "" {
			acl.AccessControlList.Grants[0].Permission = Default
		}

		//if acl.AccessControlList.Grants[0].Permission != "FULL_CONTROL" {
		//if !checkPermissionType(acl.AccessControlList.Grants[0].Permission) {
		//	writeErrorResponse(ctx, w, toAPIError(ctx, NotImplemented{}), r.URL)
		//	return
		//}
		aclHeader = acl.AccessControlList.Grants[0].Permission
	}

	// 校验对象ACL类型，公共读(PublicRead)，公共读写(PublicReadWrite)，私有(Private)，默认(Default)
	if !checkPermissionType(aclHeader) {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidRequestParameter), r.URL)
		return
	}

	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// 设置object acl
	if err = objAPI.SetObjectACL(ctx, bucket, object, aclHeader, opts); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	writeSuccessResponseHeadersOnly(w)

	//w.(http.Flusher).Flush()
}

// GetObjectACLHandler - GET Object ACL
// -----------------
// This operation uses the ACL
// subresource to return the ACL of a specified object.
func (api objectAPIHandlers) GetObjectACLHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetObjectACL")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	object = slashSeparator + object

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// Allow getObjectACL if policy action is set, since this is a dummy call
	// we are simply re-purposing the bucketPolicyAction.
	//if s3Error := checkRequestAuthType(ctx, r, policy.GetBucketPolicyAction, bucket, ""); s3Error != ErrNone {
	//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
	//	return
	//}

	// 这里对源代码进行修改，使用GetObject替代GetObjectACL
	// TODO：
	// 支持GetObjectACL， 需要在策略支持的action中增加GetObjectACL，
	// 可参考https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazons3.html。
	//if s3Error := checkRequestAuthType(ctx, r, policy.GetObjectAction, bucket, ""); s3Error != ErrNone {
	//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
	//	return
	//}
	if checkoutTenantId(ctx, objAPI, bucket, nil) != nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrAccessDenied), r.URL)
		return
	}

	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Before proceeding validate if object exists.
	_, err = objAPI.GetObjectInfo(ctx, bucket, object, opts)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// 查询对象acl
	aclstr, err := objAPI.GetObjectACL(ctx, bucket, object, opts)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	//writeSuccessResponseJSON(w, []byte(acl))
	acl := &accessControlPolicy{}
	//acl.AccessControlList.Grant = aclstr
	acl.AccessControlList.Grants = append(acl.AccessControlList.Grants, grant{
		Grantee: grantee{
			XMLNS: "http://www.w3.org/2001/XMLSchema-instance",
		},
		Permission: aclstr,
	})
	//acl.AccessControlList.Grants = append(acl.AccessControlList.Grants, grant{
	//	Grantee: grantee{
	//		XMLNS:  "http://www.w3.org/2001/XMLSchema-instance",
	//		XMLXSI: "CanonicalUser",
	//		Type:   "CanonicalUser",
	//	},
	//	Permission: "FULL_CONTROL",
	//})

	writeSuccessResponseXML(w, encodeResponse(acl))

	//if err := xml.NewEncoder(w).Encode(acl); err != nil {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//	return
	//}
	//
	//w.(http.Flusher).Flush()
}

// DeleteObjectACLHandler - Delete Object ACL
// -----------------
// This operation uses the ACL subresource
// to set ACL for a bucket, this is a dummy call
// only responds success if the ACL is private.
func (api objectAPIHandlers) DeleteObjectACLHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "DeleteObjectACL")

	defer logger.AuditLog(ctx, w, r)

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	// Allow putObjectACL if policy action is set, since this is a dummy call
	// we are simply re-purposing the bucketPolicyAction.
	//if s3Error := checkRequestAuthType(ctx, r, policy.PutBucketPolicyAction, bucket, ""); s3Error != ErrNone {
	//	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
	//	return
	//}

	// 这里对源代码进行修改，使用DeleteObject替代DeleteObjectACL
	// TODO：
	// 支持DeleteObjectACL， 需要在策略支持的action中增加DeleteObjectACL，
	// 可参考https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazons3.html。
	if s3Error := checkRequestAuthType(ctx, r, policy.DeleteObjectAction, bucket, ""); s3Error != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}

	// Before proceeding validate if object exists.
	_, err = objAPI.GetObjectInfo(ctx, bucket, object, ObjectOptions{})
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// 删除object acl
	if err = objAPI.DeleteObjectACL(ctx, bucket, object, opts); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	writeSuccessResponseHeadersOnly(w)

	//aclHeader := r.Header.Get(xhttp.AmzACL)
	//if aclHeader == "" {
	//	acl := &accessControlPolicy{}
	//	if err = xmlDecoder(r.Body, acl, r.ContentLength); err != nil {
	//		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
	//		return
	//	}
	//
	//	if len(acl.AccessControlList.Grants) == 0 {
	//		writeErrorResponse(ctx, w, toAPIError(ctx, NotImplemented{}), r.URL)
	//		return
	//	}
	//
	//	if acl.AccessControlList.Grants[0].Permission != "FULL_CONTROL" {
	//		writeErrorResponse(ctx, w, toAPIError(ctx, NotImplemented{}), r.URL)
	//		return
	//	}
	//}
	//
	//if aclHeader != "" && aclHeader != "private" {
	//	writeErrorResponse(ctx, w, toAPIError(ctx, NotImplemented{}), r.URL)
	//	return
	//}
	//
	//w.(http.Flusher).Flush()
}
