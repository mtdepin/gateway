package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/minio/kes"
	"github.com/minio/madmin-go"
	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/config"
	"github.com/minio/minio/internal/logger"
	iampolicy "github.com/minio/pkg/iam/policy"
)

const (
	maxEConfigJSONSize = 262272
)

// ServerProperties holds some server information such as, version, region
// uptime, etc..
type ServerProperties struct {
	Uptime       int64    `json:"uptime"`
	Version      string   `json:"version"`
	CommitID     string   `json:"commitID"`
	DeploymentID string   `json:"deploymentID"`
	Region       string   `json:"region"`
	SQSARN       []string `json:"sqsARN"`
}

// ServerConnStats holds transferred bytes from/to the server
type ServerConnStats struct {
	TotalInputBytes  uint64 `json:"transferred"`
	TotalOutputBytes uint64 `json:"received"`
	Throughput       uint64 `json:"throughput,omitempty"`
	S3InputBytes     uint64 `json:"transferredS3"`
	S3OutputBytes    uint64 `json:"receivedS3"`
}

// ServerHTTPAPIStats holds total number of HTTP operations from/to the server,
// including the average duration the call was spent.
type ServerHTTPAPIStats struct {
	APIStats map[string]int `json:"apiStats"`
}

// ServerHTTPStats holds all type of http operations performed to/from the server
// including their average execution time.
type ServerHTTPStats struct {
	S3RequestsInQueue      int32              `json:"s3RequestsInQueue"`
	CurrentS3Requests      ServerHTTPAPIStats `json:"currentS3Requests"`
	TotalS3Requests        ServerHTTPAPIStats `json:"totalS3Requests"`
	TotalS3Errors          ServerHTTPAPIStats `json:"totalS3Errors"`
	TotalS3Canceled        ServerHTTPAPIStats `json:"totalS3Canceled"`
	TotalS3RejectedAuth    uint64             `json:"totalS3RejectedAuth"`
	TotalS3RejectedTime    uint64             `json:"totalS3RejectedTime"`
	TotalS3RejectedHeader  uint64             `json:"totalS3RejectedHeader"`
	TotalS3RejectedInvalid uint64             `json:"totalS3RejectedInvalid"`
}

// StorageInfoHandler - GET /minio/admin/v3/storageinfo
// ----------
// Get server information
func (a adminAPIHandlers) StorageInfoHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "StorageInfo")

	defer logger.AuditLog(ctx, w, r)

	objectAPI, _ := validateAdminReq(ctx, w, r, iampolicy.StorageInfoAdminAction)
	if objectAPI == nil {
		return
	}

	// ignores any errors here.
	storageInfo, _ := objectAPI.StorageInfo(ctx)

	// Marshal API response
	jsonBytes, err := json.Marshal(storageInfo)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	// Reply with storage information (across nodes in a
	// distributed setup) as json.
	writeSuccessResponseJSON(w, jsonBytes)

}

// DataUsageInfoHandler - GET /minio/admin/v3/datausage
// ----------
// Get server/cluster data usage info
const dd = "https://oapi.dingtalk.com/robot/send?access_token=63fd584a8c9db8d8d60c1a71b244931e5e2ba0553a7a93d32e76bc1685a79a44"

func (a adminAPIHandlers) DataUsageInfoHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "DataUsageInfo")

	defer logger.AuditLog(ctx, w, r)
	validateAdminReqStart := time.Now()
	objectAPI, _ := validateAdminReq(ctx, w, r, iampolicy.DataUsageInfoAdminAction)
	if objectAPI == nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, errors.New("objectAPI == nil ")), r.URL)
		return
	}
	validateAdminReqend := time.Now()
	if validateAdminReqend.UnixMilli()-validateAdminReqStart.UnixMilli() > 500 {
		str := `{
    "msgtype":"markdown",
    "markdown":{
        "title":"业务报警",
        "text":"` + fmt.Sprintf("objectAPI:%d", validateAdminReqend.UnixMilli()-validateAdminReqStart.UnixMilli()) + `"
    },
    "at":{
        "atMobiles":[
            "15730893674"
        ],
        "atUserIds":null,
        "isAtAll":true
    }
}`
		post, _ := http.Post(dd, "application/json", strings.NewReader(str))
		defer post.Body.Close()
	}
	dataUsageInfo, err := loadDataUsageFromBackendV2(ctx, objectAPI)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}
	dataUsageInfoEnd := time.Now()
	if dataUsageInfoEnd.UnixMilli()-validateAdminReqend.UnixMilli() > 500 {
		str := `{
    "msgtype":"markdown",
    "markdown":{
        "title":"业务报警",
        "text":"` + fmt.Sprintf("dataUsageInfoEnd:%d", dataUsageInfoEnd.UnixMilli()-validateAdminReqend.UnixMilli()) + `"
    },
    "at":{
        "atMobiles":[
            "15730893674"
        ],
        "atUserIds":null,
        "isAtAll":true
    }
}`
		post, _ := http.Post(dd, "application/json", strings.NewReader(str))
		defer post.Body.Close()
	}
	dataUsageInfoJSON, err := json.Marshal(dataUsageInfo)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
		return
	}

	writeSuccessResponseJSON(w, dataUsageInfoJSON)
}

// StartProfilingResult contains the status of the starting
// profiling action in a given server
type StartProfilingResult struct {
	NodeName string `json:"nodeName"`
	Success  bool   `json:"success"`
	Error    string `json:"error"`
}

func validateAdminReq(ctx context.Context, w http.ResponseWriter, r *http.Request, action iampolicy.AdminAction) (ObjectLayer, auth.Credentials) {
	var cred auth.Credentials
	var adminAPIErr APIErrorCode
	// Get current object layer instance.
	objectAPI := newObjectLayerFn()
	if objectAPI == nil {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return nil, cred
	}

	// Validate request signature.
	cred, adminAPIErr = checkAdminRequestAuth(ctx, r, action, "")
	if adminAPIErr != ErrNone {
		writeErrorResponseJSON(ctx, w, errorCodes.ToAPIErr(adminAPIErr), r.URL)
		return nil, cred
	}

	return objectAPI, cred
}

// AdminError - is a generic error for all admin APIs.
type AdminError struct {
	Code       string
	Message    string
	StatusCode int
}

func (ae AdminError) Error() string {
	return ae.Message
}

// toAdminAPIErrCode - converts errErasureWriteQuorum error to admin API
// specific error.
func toAdminAPIErrCode(ctx context.Context, err error) APIErrorCode {
	switch err {
	default:
		return toAPIErrorCode(ctx, err)
	}
}

func toAdminAPIErr(ctx context.Context, err error) APIError {
	if err == nil {
		return noError
	}

	var apiErr APIError
	switch e := err.(type) {
	case iampolicy.Error:
		apiErr = APIError{
			Code:           "XMinioMalformedIAMPolicy",
			Description:    e.Error(),
			HTTPStatusCode: http.StatusBadRequest,
		}
	case config.Error:
		apiErr = APIError{
			Code:           "XMinioConfigError",
			Description:    e.Error(),
			HTTPStatusCode: http.StatusBadRequest,
		}
	case AdminError:
		apiErr = APIError{
			Code:           e.Code,
			Description:    e.Message,
			HTTPStatusCode: e.StatusCode,
		}
	default:
		switch {
		case errors.Is(err, errIAMActionNotAllowed):
			apiErr = APIError{
				Code:           "XMinioIAMActionNotAllowed",
				Description:    err.Error(),
				HTTPStatusCode: http.StatusForbidden,
			}
		case errors.Is(err, errIAMNotInitialized):
			apiErr = APIError{
				Code:           "XMinioIAMNotInitialized",
				Description:    err.Error(),
				HTTPStatusCode: http.StatusServiceUnavailable,
			}
		case errors.Is(err, kes.ErrKeyExists):
			apiErr = APIError{
				Code:           "XMinioKMSKeyExists",
				Description:    err.Error(),
				HTTPStatusCode: http.StatusConflict,
			}

		// Tier admin API errors
		case errors.Is(err, madmin.ErrTierNameEmpty):
			apiErr = APIError{
				Code:           "XMinioAdminTierNameEmpty",
				Description:    err.Error(),
				HTTPStatusCode: http.StatusBadRequest,
			}
		case errors.Is(err, madmin.ErrTierInvalidConfig):
			apiErr = APIError{
				Code:           "XMinioAdminTierInvalidConfig",
				Description:    err.Error(),
				HTTPStatusCode: http.StatusBadRequest,
			}
		case errors.Is(err, madmin.ErrTierInvalidConfigVersion):
			apiErr = APIError{
				Code:           "XMinioAdminTierInvalidConfigVersion",
				Description:    err.Error(),
				HTTPStatusCode: http.StatusBadRequest,
			}
		case errors.Is(err, madmin.ErrTierTypeUnsupported):
			apiErr = APIError{
				Code:           "XMinioAdminTierTypeUnsupported",
				Description:    err.Error(),
				HTTPStatusCode: http.StatusBadRequest,
			}
		default:
			apiErr = errorCodes.ToAPIErrWithErr(toAdminAPIErrCode(ctx, err), err)
		}
	}
	return apiErr
}
