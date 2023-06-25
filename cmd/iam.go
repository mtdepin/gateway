package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/minio/maitian/tracing"
	"go.opencensus.io/trace"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/maitian/config"
	iampolicy "github.com/minio/pkg/iam/policy"
)

// UsersSysType - defines the type of users and groups system that is
// active on the server.
type UsersSysType string

// Types of users configured in the server.
const (
	// This mode uses the internal users system in MinIO.
	MinIOUsersSysType UsersSysType = "MinIOUsersSys"

	// This mode uses users and groups from a configured LDAP
	// server.
	LDAPUsersSysType UsersSysType = "LDAPUsersSys"
)

// 用户名、群组名格式
const (
	accesskeyFormat = "^[a-zA-Z0-9_.-]{3,64}$"
)

// UserIdentity represents a user's secret key and their status
type UserIdentity struct {
	Version     int              `json:"version"`
	Credentials auth.Credentials `json:"credentials"`
}

// GroupInfo contains info about a group
type GroupInfo struct {
	Version int      `json:"version"`
	Status  string   `json:"status"`
	Members []string `json:"members"`
}

// 用户名和群组名格式满足：
// 长度为3~64字符，包含英文字母、数字、.、_或-
func isNameValid(name string) bool {
	r := regexp.MustCompile(accesskeyFormat)
	return r.MatchString(name)
}

// IAMSys - config system.
type IAMSys struct {
	sync.Mutex

	//iam 服务地址
	url string

	usersSysType UsersSysType
}

// NewIAMSys - creates new config system object.
func NewIAMSys() *IAMSys {
	return &IAMSys{
		usersSysType: MinIOUsersSysType,
	}
}

func (sys *IAMSys) InitIam() {
	url := config.GetString("iam.url")
	if len(strings.TrimSpace(url)) == 0 {
		panic("iam config not found!")
	}
	globalIAMSys.url = url

}

// Initialized check if IAM is initialized
func (sys *IAMSys) Initialized() bool {
	if sys == nil {
		return false
	}
	sys.Lock()
	defer sys.Unlock()
	return true
}

// SetTempUser - set temporary user credentials, these credentials have an expiry.
func (sys *IAMSys) SetTempUser(accessKey string, cred auth.Credentials, policyName string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	return nil
}

// IsTempUser - returns if given key is a temporary user.
func (sys *IAMSys) IsTempUser(name string) (bool, string, error) {
	if !sys.Initialized() {
		return false, "", errServerNotInitialized
	}
	return false, "", nil
}

type AuthInfo struct {
	AuthType         authType
	Cred             *auth.Credentials
	Owner            bool
	Claims           map[string]interface{}
	TenantId         int
	ParentUserId     int
	CompareSignature bool
}

type AuthResult struct {
	Cred    auth.Credentials
	Owner   bool
	Allowed bool
	Claims  map[string]interface{}
}

type TenantInfo struct {
	ID        int       `json:"id" gorm:"primary_key"`
	Creator   string    `json:"creator" gorm:"type:varchar(64)"`
	Desc      string    `json:"desc"`
	Quota     int       `json:"quota"  gorm:"type:int(5)"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (sys *IAMSys) GetTenantInfo(r *http.Request, ai *AuthInfo) TenantInfo {
	return TenantInfo{}
}

func (sys *IAMSys) GetAuthInfo(ctx context.Context) *AuthInfo {
	c := ctx.Value(Ctx_Auth)
	if c != nil {
		switch c.(type) {
		case *AuthInfo:
			return c.(*AuthInfo)
		}
	}
	return nil
}

func (sys *IAMSys) GetAuthClaimsFromCtx(ctx context.Context) map[string]interface{} {
	ai := sys.GetAuthInfo(ctx)
	if ai != nil {
		return ai.Claims
	}
	return nil
}

// Fetch claims in the security token returned by the client, doesn't return
// errors - upon errors the returned claims map will be empty.
func (sys *IAMSys) mustGetAuthInfoFromToken(r *http.Request) *AuthInfo {
	logger.Debug("mustGetAuthInfoFromToken")
	url := fmt.Sprintf("%s/claim%s", globalIAMSys.url, r.RequestURI)

	//span
	_, span := trace.StartSpan(r.Context(), "mustGetAuthInfoFromToken")
	span.AddAttributes(trace.StringAttribute("url", url))
	span.AddAttributes(trace.StringAttribute("method", r.Method))
	defer span.End()

	req, err := http.NewRequest(r.Method, url, nil)
	if err != nil {
		logger.Error(err)
		return nil
	}
	tracing.SpanContextToRequest(span, req)

	//pre parse request
	err = ParseSignatureFromReq(r)
	if err != nil {
		logger.Error(err)
		return nil
	}

	req.URL.RawQuery = r.URL.RawQuery
	//req.Host = r.Host
	//req.URL.Host = ""
	for k, v := range r.Header {
		for _, vv := range v {
			req.Header.Add(k, vv)
		}
	}

	req.Header.Add("Origin_Content-Length", r.Header.Get("Content-Length"))
	//set origin host
	sys.setOriginHost(req, r)

	//set origin method
	sys.setOriginMethod(req)

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error(err)
		return nil
	}
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	if body == nil || len(body) == 0 {
		logger.Debug("iam api return no data")
		return nil
	}

	ar := &AuthInfo{}
	err = json.Unmarshal(body, ar)
	if err != nil {
		logger.Error(err)
		return nil
	}

	return ar
}

func (sys *IAMSys) setOriginMethod(req *http.Request) {
	if req.Method == http.MethodHead {
		req.Header.Add("Origin_Method", req.Method)
		req.Method = http.MethodGet
	}
}

func (sys *IAMSys) setOriginHost(req *http.Request, r *http.Request) {
	req.Header.Add("Origin_Host", r.Host)
}

// IsAllowed_2 - checks given policy args is allowed to continue the Rest API.
func (sys *IAMSys) IsAllowed_2(r *http.Request, args iampolicy.Args) (auth.Credentials, map[string]interface{}, bool, bool, APIErrorCode) {
	argsBytes, err := json.Marshal(args)
	if err != nil {
		fmt.Println(err)
		return auth.Credentials{}, nil, false, false, ErrAdminInvalidArgument
	}

	url := fmt.Sprintf("%s/auth%s", globalIAMSys.url, r.RequestURI)
	req, err := http.NewRequest(r.Method, url, bytes.NewReader(argsBytes))
	if err != nil {
		fmt.Println(err)
		return auth.Credentials{}, nil, false, false, ErrBadRequest
	}
	req.URL.RawQuery = r.URL.RawQuery
	req.Host = r.Host
	for k, v := range r.Header {
		for _, vv := range v {
			req.Header.Add(k, vv)
			req.Header.Add("Origin_Host", r.Host)
		}
	}

	if req.Method == http.MethodHead {
		req.Header.Add("Origin_Method", req.Method)
		req.Method = http.MethodGet
	}

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return auth.Credentials{}, nil, false, false, ErrBadRequest
	}
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	data := AuthResult{}

	_ = json.Unmarshal(body, &data)

	return data.Cred, data.Claims, data.Owner, data.Allowed, ErrNone
}
