package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/minio/minio/internal/auth"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/pkg/bucket/policy"
	iampolicy "github.com/minio/pkg/iam/policy"
)

// Verify if request has JWT.
func isRequestJWT(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get(xhttp.Authorization), jwtAlgorithm)
}

// Verify if request has AWS Signature Version '4'.
func isRequestSignatureV4(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get(xhttp.Authorization), signV4Algorithm)
}

// Verify if request has AWS Signature Version '2'.
func isRequestSignatureV2(r *http.Request) bool {
	return (!strings.HasPrefix(r.Header.Get(xhttp.Authorization), signV4Algorithm) &&
		strings.HasPrefix(r.Header.Get(xhttp.Authorization), signV2Algorithm))
}

// Verify if request has AWS PreSign Version '4'.
func isRequestPresignedSignatureV4(r *http.Request) bool {
	_, ok := r.URL.Query()[xhttp.AmzCredential]
	return ok
}

// Verify request has AWS PreSign Version '2'.
func isRequestPresignedSignatureV2(r *http.Request) bool {
	_, ok := r.URL.Query()[xhttp.AmzAccessKeyID]
	return ok
}

// Verify if request has AWS Post policy Signature Version '4'.
func isRequestPostPolicySignatureV4(r *http.Request) bool {
	return strings.Contains(r.Header.Get(xhttp.ContentType), "multipart/form-data") &&
		r.Method == http.MethodPost
}

// Verify if the request has AWS Streaming Signature Version '4'. This is only valid for 'PUT' operation.
func isRequestSignStreamingV4(r *http.Request) bool {
	return r.Header.Get(xhttp.AmzContentSha256) == streamingContentSHA256 &&
		r.Method == http.MethodPut
}

// Authorization type.
type authType int

// List of all supported auth types.
const (
	authTypeUnknown authType = iota
	authTypeAnonymous
	authTypePresigned
	authTypePresignedV2
	authTypePostPolicy
	authTypeStreamingSigned
	authTypeSigned
	authTypeSignedV2
	authTypeJWT
	authTypeSTS
)

// Get request authentication type.
func getRequestAuthType(r *http.Request) authType {
	if isRequestSignatureV2(r) {
		return authTypeSignedV2
	} else if isRequestPresignedSignatureV2(r) {
		return authTypePresignedV2
	} else if isRequestSignStreamingV4(r) {
		return authTypeStreamingSigned
	} else if isRequestSignatureV4(r) {
		return authTypeSigned
	} else if isRequestPresignedSignatureV4(r) {
		return authTypePresigned
	} else if isRequestJWT(r) {
		return authTypeJWT
	} else if isRequestPostPolicySignatureV4(r) {
		return authTypePostPolicy
	} else if _, ok := r.URL.Query()[xhttp.Action]; ok {
		return authTypeSTS
	} else if _, ok := r.Header[xhttp.Authorization]; !ok {
		return authTypeAnonymous
	}
	return authTypeUnknown
}

// checkAdminRequestAuth checks for authentication and authorization for the incoming
// request. It only accepts V2 and V4 requests. Presigned, JWT and anonymous requests
// are automatically rejected.
func checkAdminRequestAuth(ctx context.Context, r *http.Request, action iampolicy.AdminAction, region string) (auth.Credentials, APIErrorCode) {
	//cred, claims, owner, s3Err := validateAdminSignature(ctx, r, region)
	//if s3Err != ErrNone {
	//	return cred, s3Err
	//}

	cred, _, _, isallowed, _ := globalIAMSys.IsAllowed_2(r, iampolicy.Args{
		Action: iampolicy.Action(action),
	})
	if isallowed {
		// Request is allowed return the appropriate access key.
		return cred, ErrNone
	}

	return cred, ErrAccessDenied
}

//ParseSignatureFromReq parse signature from request, only valid for post request
func ParseSignatureFromReq(r *http.Request) error {
	if r.Method != http.MethodPost {
		return nil
	}
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "boundary=") {
		ss := strings.Split(ct, "boundary=")
		if len(ss) < 2 {
			return errors.New("boundary not correct")
		}
		m := make(map[string]string, 10) // 记录参数key-value
		mr := multipart.NewReader(r.Body, ss[1])
		var file *multipart.Part
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			key := p.FormName()

			if key == "file" || p.FileName() != "" {
				contentType := p.Header.Get("Content-Type")
				r.Header.Set("Content-Type", contentType)
				file = p
				break
			}
			slurp, _ := io.ReadAll(p)
			m[key] = string(slurp)
		}
		v4ResignQueryParams := []string{xhttp.AmzAlgorithm, xhttp.AmzCredential, xhttp.AmzSignature, xhttp.AmzDate, xhttp.AmzSignedHeaders, xhttp.AmzExpires}
		q := r.URL.Query()
		for _, v4ResignQueryParam := range v4ResignQueryParams {
			value := m[v4ResignQueryParam]
			q.Set(v4ResignQueryParam, value)
		}
		if _, ok := m["key"]; ok {
			q.Set("key", m["key"])
		}
		r.URL.RawQuery = q.Encode()
		if v, ok := m["acl"]; ok {
			r.Header.Set(xhttp.AmzACL, v)
		}
		r.Body = file
	}

	return nil
}

// Check request auth type verifies the incoming http request
// - validates the request signature
// - validates the policy action if anonymous tests bucket policies if any,
//   for authenticated requests validates IAM policies.
// returns APIErrorCode if any to be replied to the client.
func checkRequestAuthType(ctx context.Context, r *http.Request, action policy.Action, bucketName, objectName string) (s3Err APIErrorCode) {
	s3Err = checkRequestAuthTypeCredential(ctx, r, action, bucketName, objectName)
	return s3Err
}

func checkRequestAuthTypeCredential(ctx context.Context, r *http.Request, action policy.Action, bucketName, objectName string) (s3Err APIErrorCode) {
	// LocationConstraint is valid only for CreateBucketAction.
	var locationConstraint string
	if action == policy.CreateBucketAction {
		// To extract region from XML in request body, get copy of request body.
		payload, err := ioutil.ReadAll(io.LimitReader(r.Body, maxLocationConstraintSize))
		if err != nil {
			logger.LogIf(ctx, err, logger.Application)
			return ErrMalformedXML
		}

		// Populate payload to extract location constraint.
		r.Body = ioutil.NopCloser(bytes.NewReader(payload))

		var s3Error APIErrorCode
		locationConstraint, s3Error = parseLocationConstraint(r)
		if s3Error != ErrNone {
			return s3Error
		}

		// Populate payload again to handle it in HTTP handler.
		r.Body = ioutil.NopCloser(bytes.NewReader(payload))
	}

	// 验证桶策略和IAM策略
	var iamPolicy, bucketPolicy bool
	// 验证桶策略
	if bucketName != "" {
		if action != policy.ListAllMyBucketsAction && action != policy.CreateBucketAction {
			//check bucket policy
			// 判断桶策略
			bucketPolicy = true
			if locationConstraint == "" {

			}
			//// 判断证书类型，并返回对应的用户名
			//// 桶策略判断中，需传入reg类型的用户名
			//var accountName string
			//if ok, name, err := globalIAMSys.IsTempUser(cred.AccessKey); ok {
			//	if err != nil {
			//		return cred, owner, ErrInternalError
			//	}
			//	// sts证书，返回parentuser
			//	accountName = name
			//} else if ok, name, err = globalIAMSys.IsServiceAccount(cred.AccessKey); ok {
			//	if err != nil {
			//		return cred, owner, ErrInternalError
			//	}
			//	// svc证书，返回parentuser
			//	accountName = name
			//} else {
			//	// reg证书或租户，返回accesskey
			//	accountName = cred.AccessKey
			//}
			//
			//bucketPolicy = globalPolicySys.IsAllowed(policy.Args{
			//	AccountName:     accountName,
			//	Action:          action,
			//	BucketName:      bucketName,
			//	ConditionValues: getConditionValues(r, locationConstraint, "", nil),
			//	IsOwner:         false,
			//	ObjectName:      objectName,
			//})
		}
	}

	if action == policy.ListBucketVersionsAction {
		// In AWS S3 s3:ListBucket permission is same as s3:ListBucketVersions permission
		// verify as a fallback.

		// 判断桶策略
		bucketPolicy = true
		// 判断证书类型，并返回对应的用户名
		// 桶策略判断中，需传入reg类型的用户名
		//var accountName string
		//if ok, name, err := globalIAMSys.IsTempUser(cred.AccessKey); ok {
		//	if err != nil {
		//		return cred, owner, ErrInternalError
		//	}
		//	// sts证书，返回parentuser
		//	accountName = name
		//} else if ok, name, err = globalIAMSys.IsServiceAccount(cred.AccessKey); ok {
		//	if err != nil {
		//		return cred, owner, ErrInternalError
		//	}
		//	// svc证书，返回parentuser
		//	accountName = name
		//} else {
		//	// reg证书或租户，返回accesskey
		//	accountName = cred.AccessKey
		//}
		//
		//bucketPolicy = globalPolicySys.IsAllowed(policy.Args{
		//	AccountName:     accountName,
		//	Action:          policy.ListBucketAction,
		//	BucketName:      bucketName,
		//	ConditionValues: getConditionValues(r, locationConstraint, "", nil),
		//	IsOwner:         false,
		//	ObjectName:      objectName,
		//})
	}

	// 验证IAM策略
	if action == policy.ListBucketVersionsAction {
		// In AWS S3 s3:ListBucket permission is same as s3:ListBucketVersions permission
		// verify as a fallback.
		action = iampolicy.ListBucketAction
	}

	_, _, _, iamPolicy, s3Err = globalIAMSys.IsAllowed_2(r, iampolicy.Args{
		Action:     iampolicy.Action(action),
		BucketName: bucketName,
	})

	// 若IAM和桶策略任一验证通过，则允许访问
	if iamPolicy || bucketPolicy {
		return ErrNone
	}

	return ErrAccessDenied
}

// 匿名请求认证：
// 若请求为Put/Get/Delete Object，验证ACL
// - 若对象ACL验证通过，则允许访问；否则，拒绝访问
// - 若对象ACL为默认，则继承桶ACL，进行验证
// - 若没有桶ACL，则拒绝访问
func checkRequestAuthTypeAnonymous(r *http.Request, action policy.Action, bucketACL, objectACL string) (s3Err APIErrorCode) {
	if getRequestAuthType(r) != authTypeAnonymous {
		return ErrAuthorizationHeaderMalformed
	}

	// 验证ACL
	if objectACL == Default || objectACL == "" {
		if bucketACL != "" {
			objectACL = bucketACL
		} else {
			return ErrAccessDenied
		}
	}

	// 支持匿名公开读的action集合
	var rdActionSet = map[policy.Action]struct{}{
		policy.GetObjectAction:                      {},
		policy.GetObjectRetentionAction:             {},
		policy.GetObjectLegalHoldAction:             {},
		policy.GetObjectTaggingAction:               {},
		policy.GetObjectVersionAction:               {},
		policy.GetObjectVersionTaggingAction:        {},
		policy.GetObjectVersionForReplicationAction: {},
	}
	// 支持匿名公开读写的action集合
	var rwActionSet = map[policy.Action]struct{}{
		policy.AbortMultipartUploadAction:           {},
		policy.DeleteObjectAction:                   {},
		policy.GetObjectAction:                      {},
		policy.ListMultipartUploadPartsAction:       {},
		policy.PutObjectAction:                      {},
		policy.BypassGovernanceRetentionAction:      {},
		policy.PutObjectRetentionAction:             {},
		policy.GetObjectRetentionAction:             {},
		policy.PutObjectLegalHoldAction:             {},
		policy.GetObjectLegalHoldAction:             {},
		policy.GetObjectTaggingAction:               {},
		policy.PutObjectTaggingAction:               {},
		policy.DeleteObjectTaggingAction:            {},
		policy.GetObjectVersionAction:               {},
		policy.GetObjectVersionTaggingAction:        {},
		policy.DeleteObjectVersionAction:            {},
		policy.DeleteObjectVersionTaggingAction:     {},
		policy.PutObjectVersionTaggingAction:        {},
		policy.ReplicateObjectAction:                {},
		policy.ReplicateDeleteAction:                {},
		policy.ReplicateTagsAction:                  {},
		policy.GetObjectVersionForReplicationAction: {},
		policy.RestoreObjectAction:                  {},
		policy.ResetBucketReplicationStateAction:    {},
	}

	switch objectACL {
	case PublicRead:
		if _, ok := rdActionSet[action]; ok {
			return ErrNone
		}
	case PublicReadWrite:
		if _, ok := rwActionSet[action]; ok {
			return ErrNone
		}
	}

	return ErrAccessDenied
}

// List of all support S3 auth types.
var supportedS3AuthTypes = map[authType]struct{}{
	authTypeAnonymous:       {},
	authTypePresigned:       {},
	authTypePresignedV2:     {},
	authTypeSigned:          {},
	authTypeSignedV2:        {},
	authTypePostPolicy:      {},
	authTypeStreamingSigned: {},
}

// Validate if the authType is valid and supported.
func isSupportedS3AuthType(aType authType) bool {
	_, ok := supportedS3AuthTypes[aType]
	return ok
}

// setAuthHandler to validate authorization header for the incoming request.
func setAuthHandler(h http.Handler) http.Handler {
	// handler for validating incoming authorization headers.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aType := getRequestAuthType(r)
		if isSupportedS3AuthType(aType) {
			// Let top level caller validate for anonymous and known signed requests.
			//add by lyc begin
			ctx := context.WithValue(r.Context(), Ctx_Host, r.Host)
			r = r.WithContext(ctx)
			authInfo := globalIAMSys.mustGetAuthInfoFromToken(r)
			if authInfo != nil {
				if aType != authTypeAnonymous && !authInfo.CompareSignature {
					logger.Debug(r.URL, ErrSignatureDoesNotMatch)
					writeErrorResponse(r.Context(), w, errorCodes.ToAPIErr(ErrSignatureDoesNotMatch), r.URL)
					atomic.AddUint64(&globalHTTPStats.rejectedRequestsAuth, 1)
					return
				}
				ctx = context.WithValue(r.Context(), Ctx_Auth, authInfo)
				r = r.WithContext(ctx)
			}
			//add by lyc end
			h.ServeHTTP(w, r)
			return
		} else if aType == authTypeJWT {
			// Validate Authorization header if its valid for JWT request.
			if _, _, authErr := webRequestAuthenticate(r); authErr != nil {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(authErr.Error()))
				return
			}
			h.ServeHTTP(w, r)
			return
		} else if aType == authTypeSTS {
			h.ServeHTTP(w, r)
			return
		}
		writeErrorResponse(r.Context(), w, errorCodes.ToAPIErr(ErrSignatureVersionNotSupported), r.URL)
		atomic.AddUint64(&globalHTTPStats.rejectedRequestsAuth, 1)
	})
}

// isPutActionAllowed - check if PUT operation is allowed on the resource, this
// call verifies bucket policies and IAM policies, supports multi user
// checks etc.
// 原有验证逻辑：
// 1.解析请求头部，若为身份认证，则验证签名；
// 2.若为匿名访问，则验证桶策略，验证通过，则允许访问，否则，拒绝访问；
// 3.验证IAM策略，验证通过，允许访问，否则，拒绝访问。
//
// 修改后逻辑（只支持身份认证，对象匿名请求需调用checkRequestAuthTypeAnonymous进行验证）：
// 1.解析请求头部，若为身份认证，则验证签名；
// 2.验证桶策略和IAM策略，若任一策略验证通过，则允许访问。
func isPutActionAllowed(ctx context.Context, atype authType, bucketName, objectName string, r *http.Request, action iampolicy.Action) (s3Err APIErrorCode) {
	//cred, _, _, _ := validateAdminSignature(ctx, r, "")
	// 验证IAM策略
	cred, _, _, iamPolicy, _ := globalIAMSys.IsAllowed_2(r, iampolicy.Args{
		Action:     action,
		BucketName: bucketName,
		ObjectName: objectName,
	})

	if cred.AccessKey != "" {
		logger.GetReqInfo(ctx).AccessKey = cred.AccessKey
	}

	// Do not check for PutObjectRetentionAction permission,
	// if mode and retain until date are not set.
	// Can happen when bucket has default lock config set
	if action == iampolicy.PutObjectRetentionAction &&
		r.Header.Get(xhttp.AmzObjectLockMode) == "" &&
		r.Header.Get(xhttp.AmzObjectLockRetainUntilDate) == "" {
		return ErrNone
	}

	//todo
	// 判断证书类型，并返回对应的用户名
	// 桶策略判断中，需传入reg类型的用户名
	bucketPolicy := true
	//var accountName string
	//if ok, name, err := globalIAMSys.IsTempUser(cred.AccessKey); ok {
	//	if err != nil {
	//		return ErrInternalError
	//	}
	//	// sts证书，返回parentuser
	//	accountName = name
	//} else if ok, name, err = globalIAMSys.IsServiceAccount(cred.AccessKey); ok {
	//	if err != nil {
	//		return ErrInternalError
	//	}
	//	// svc证书，返回parentuser
	//	accountName = name
	//} else {
	//	// reg证书或租户，返回accesskey
	//	accountName = cred.AccessKey
	//}
	//// 验证IAM策略和桶策略
	//var iamPolicy, bucketPolicy bool
	//// 验证桶策略
	bucketPolicy = true
	//bucketPolicy = globalPolicySys.IsAllowed(policy.Args{
	//	//AccountName:     accountName,
	//	AccountName:     cred.AccessKey,
	//	Groups:          cred.Groups,
	//	Action:          policy.Action(action),
	//	BucketName:      bucketName,
	//	ConditionValues: getConditionValues(r, "", "", nil),
	//	IsOwner:         false,
	//	ObjectName:      objectName,
	//})

	//// 验证IAM策略
	//cred, _, _, iamPolicy, _ := globalIAMSys.IsAllowed_2(r, iampolicy.Args{
	//	Action:     action,
	//	BucketName: bucketName,
	//	ObjectName: objectName,
	//})

	if iamPolicy || bucketPolicy {
		return ErrNone
	}

	return ErrAccessDenied
}
