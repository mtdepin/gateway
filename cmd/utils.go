package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"reflect"
	"strings"
	"sync"
	"time"

	humanize "github.com/dustin/go-humanize"
	"github.com/gorilla/mux"
	miniogopolicy "github.com/minio/minio-go/v7/pkg/policy"
	"github.com/minio/minio/internal/handlers"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/minio/internal/rest"
)

const (
	slashSeparator = "/"
)

// BucketAccessPolicy - Collection of canned bucket policy at a given prefix.
type BucketAccessPolicy struct {
	Bucket string                     `json:"bucket"`
	Prefix string                     `json:"prefix"`
	Policy miniogopolicy.BucketPolicy `json:"policy"`
}

// HealObjectFn closure function heals the object.
type HealObjectFn func(bucket, object, versionID string) error

// HealthOptions takes input options to return sepcific information
type HealthOptions struct {
	Maintenance bool
}

// HealthResult returns the current state of the system, also
// additionally with any specific heuristic information which
// was queried
type HealthResult struct {
	Healthy       bool
	HealingDrives int
	PoolID, SetID int
	WriteQuorum   int
}

// IsErrIgnored returns whether given error is ignored or not.
func IsErrIgnored(err error, ignoredErrs ...error) bool {
	return IsErr(err, ignoredErrs...)
}

// IsErr returns whether given error is exact error.
func IsErr(err error, errs ...error) bool {
	for _, exactErr := range errs {
		if errors.Is(err, exactErr) {
			return true
		}
	}
	return false
}

func request2BucketObjectName(r *http.Request) (bucketName, objectName string) {
	path, err := getResource(r.URL.Path, r.Host, globalDomainNames)
	if err != nil {
		logger.CriticalIf(GlobalContext, err)
	}

	return path2BucketObject(path)
}

// path2BucketObjectWithBasePath returns bucket and prefix, if any,
// of a 'path'. basePath is trimmed from the front of the 'path'.
func path2BucketObjectWithBasePath(basePath, path string) (bucket, prefix string) {
	path = strings.TrimPrefix(path, basePath)
	path = strings.TrimPrefix(path, SlashSeparator)
	m := strings.Index(path, SlashSeparator)
	if m < 0 {
		return path, ""
	}
	return path[:m], path[m+len(SlashSeparator):]
}

func path2BucketObject(s string) (bucket, prefix string) {
	return path2BucketObjectWithBasePath("", s)
}

func getReadQuorum(drive int) int {
	//return drive - getDefaultParityBlocks(drive)
	return drive
}

func getWriteQuorum(drive int) int {
	//parity := getDefaultParityBlocks(drive)
	parity := drive
	quorum := drive - parity
	if quorum == parity {
		quorum++
	}
	return quorum
}

// cloneMSS will clone a map[string]string.
// If input is nil an empty map is returned, not nil.
func cloneMSS(v map[string]string) map[string]string {
	r := make(map[string]string, len(v))
	for k, v := range v {
		r[k] = v
	}
	return r
}

// URI scheme constants.
const (
	httpScheme  = "http"
	httpsScheme = "https"
)

// nopCharsetConverter is a dummy charset convert which just copies input to output,
// it is used to ignore custom encoding charset in S3 XML body.
func nopCharsetConverter(label string, input io.Reader) (io.Reader, error) {
	return input, nil
}

// xmlDecoder provide decoded value in xml.
func xmlDecoder(body io.Reader, v interface{}, size int64) error {
	var lbody io.Reader
	if size > 0 {
		lbody = io.LimitReader(body, size)
	} else {
		lbody = body
	}
	d := xml.NewDecoder(lbody)
	// Ignore any encoding set in the XML body
	d.CharsetReader = nopCharsetConverter
	return d.Decode(v)
}

// hasContentMD5 returns true if Content-MD5 header is set.
func hasContentMD5(h http.Header) bool {
	_, ok := h[xhttp.ContentMD5]
	return ok
}

/// http://docs.aws.amazon.com/AmazonS3/latest/dev/UploadingObjects.html
const (
	// Maximum object size per PUT request is 5TB.
	// This is a divergence from S3 limit on purpose to support
	// use cases where users are going to upload large files
	// using 'curl' and presigned URL.
	globalMaxObjectSize = 5 * humanize.TiByte

	// Minimum Part size for multipart upload is 5MiB
	globalMinPartSize = 5 * humanize.MiByte

	// Maximum Part size for multipart upload is 5GiB
	globalMaxPartSize = 5 * humanize.GiByte

	globalMaxPostObjectSize = 5 * humanize.GiByte
	// Maximum Part ID for multipart upload is 10000
	// (Acceptable values range from 1 to 10000 inclusive)
	globalMaxPartID = 10000

	// Default values used while communicating for gateway communication
	defaultDialTimeout = 5 * time.Second
)

// 限制postObject方法上传的文件大小
func isMaxPostObjectSize(size int64) bool {
	return size > globalMaxPostObjectSize
}

// isMaxObjectSize - verify if max object size
func isMaxObjectSize(size int64) bool {
	return size > globalMaxObjectSize
}

// // Check if part size is more than maximum allowed size.
func isMaxAllowedPartSize(size int64) bool {
	return size > globalMaxPartSize
}

// Check if part size is more than or equal to minimum allowed size.
func isMinAllowedPartSize(size int64) bool {
	return size >= globalMinPartSize
}

// isMaxPartNumber - Check if part ID is greater than the maximum allowed ID.
func isMaxPartID(partID int) bool {
	return partID > globalMaxPartID
}

func contains(slice interface{}, elem interface{}) bool {
	v := reflect.ValueOf(slice)
	if v.Kind() == reflect.Slice {
		for i := 0; i < v.Len(); i++ {
			if v.Index(i).Interface() == elem {
				return true
			}
		}
	}
	return false
}

// minioProfiler - minio profiler interface.
type minioProfiler interface {
	// Return recorded profiles, each profile associated with a distinct generic name.
	Records() map[string][]byte
	// Stop the profiler
	Stop() ([]byte, error)
	// Return extension of profile
	Extension() string
}

// Global profiler to be used by service go-routine.
var globalProfiler map[string]minioProfiler
var globalProfilerMu sync.Mutex

// dump the request into a string in JSON format.
func dumpRequest(r *http.Request) string {
	header := r.Header.Clone()
	header.Set("Host", r.Host)
	// Replace all '%' to '%%' so that printer format parser
	// to ignore URL encoded values.
	rawURI := strings.Replace(r.RequestURI, "%", "%%", -1)
	req := struct {
		Method     string      `json:"method"`
		RequestURI string      `json:"reqURI"`
		Header     http.Header `json:"header"`
	}{r.Method, rawURI, header}

	var buffer bytes.Buffer
	enc := json.NewEncoder(&buffer)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&req); err != nil {
		// Upon error just return Go-syntax representation of the value
		return fmt.Sprintf("%#v", req)
	}

	// Formatted string.
	return strings.TrimSpace(buffer.String())
}

// isFile - returns whether given path is a file or not.
func isFile(path string) bool {
	if fi, err := os.Stat(path); err == nil {
		return fi.Mode().IsRegular()
	}

	return false
}

// UTCNow - returns current UTC time.
func UTCNow() time.Time {
	return time.Now().UTC()
}

// GenETag - generate UUID based ETag
func GenETag() string {
	return ToS3ETag(getMD5Hash([]byte(mustGetUUID())))
}

// ToS3ETag - return checksum to ETag
func ToS3ETag(etag string) string {
	etag = canonicalizeETag(etag)

	if !strings.HasSuffix(etag, "-1") {
		// Tools like s3cmd uses ETag as checksum of data to validate.
		// Append "-1" to indicate ETag is not a checksum.
		etag += "-1"
	}

	return etag
}

// pathClean is like path.Clean but does not return "." for
// empty inputs, instead returns "empty" as is.
func pathClean(p string) string {
	cp := path.Clean(p)
	if cp == "." {
		return ""
	}
	return cp
}

func trimLeadingSlash(ep string) string {
	if len(ep) > 0 && ep[0] == '/' {
		// Path ends with '/' preserve it
		if ep[len(ep)-1] == '/' && len(ep) > 1 {
			ep = path.Clean(ep)
			ep += slashSeparator
		} else {
			ep = path.Clean(ep)
		}
		ep = ep[1:]
	}
	return ep
}

// unescapeGeneric is similar to url.PathUnescape or url.QueryUnescape
// depending on input, additionally also handles situations such as
// `//` are normalized as `/`, also removes any `/` prefix before
// returning.
func unescapeGeneric(p string, escapeFn func(string) (string, error)) (string, error) {
	ep, err := escapeFn(p)
	if err != nil {
		return "", err
	}
	return trimLeadingSlash(ep), nil
}

// unescapePath is similar to unescapeGeneric but for specifically
// path unescaping.
func unescapePath(p string) (string, error) {
	return unescapeGeneric(p, url.PathUnescape)
}

// similar to unescapeGeneric but never returns any error if the unescaping
// fails, returns the input as is in such occasion, not meant to be
// used where strict validation is expected.
func likelyUnescapeGeneric(p string, escapeFn func(string) (string, error)) string {
	ep, err := unescapeGeneric(p, escapeFn)
	if err != nil {
		return p
	}
	return ep
}

// Returns context with ReqInfo details set in the context.
func newContext(r *http.Request, w http.ResponseWriter, api string) context.Context {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object := likelyUnescapeGeneric(vars["object"], url.PathUnescape)
	prefix := likelyUnescapeGeneric(vars["prefix"], url.QueryUnescape)
	if prefix != "" {
		object = prefix
	}
	uid, _ := JudgeUserID(r.Context())
	reqInfo := &logger.ReqInfo{
		Uid:          uid,
		DeploymentID: globalDeploymentID,
		RequestID:    w.Header().Get(xhttp.AmzRequestID),
		RemoteHost:   handlers.GetSourceIP(r),
		Host:         getHostName(r),
		UserAgent:    r.UserAgent(),
		API:          api,
		BucketName:   bucket,
		ObjectName:   object,
	}
	return logger.SetReqInfo(r.Context(), reqInfo)
}

// Used for registering with rest handlers (have a look at registerStorageRESTHandlers for usage example)
// If it is passed ["aaaa", "bbbb"], it returns ["aaaa", "{aaaa:.*}", "bbbb", "{bbbb:.*}"]
func restQueries(keys ...string) []string {
	var accumulator []string
	for _, key := range keys {
		accumulator = append(accumulator, key, "{"+key+":.*}")
	}
	return accumulator
}

// Suffix returns the longest common suffix of the provided strings
func lcpSuffix(strs []string) string {
	return lcp(strs, false)
}

func lcp(strs []string, pre bool) string {
	// short-circuit empty list
	if len(strs) == 0 {
		return ""
	}
	xfix := strs[0]
	// short-circuit single-element list
	if len(strs) == 1 {
		return xfix
	}
	// compare first to rest
	for _, str := range strs[1:] {
		xfixl := len(xfix)
		strl := len(str)
		// short-circuit empty strings
		if xfixl == 0 || strl == 0 {
			return ""
		}
		// maximum possible length
		maxl := xfixl
		if strl < maxl {
			maxl = strl
		}
		// compare letters
		if pre {
			// prefix, iterate left to right
			for i := 0; i < maxl; i++ {
				if xfix[i] != str[i] {
					xfix = xfix[:i]
					break
				}
			}
		} else {
			// suffix, iterate right to left
			for i := 0; i < maxl; i++ {
				xi := xfixl - i - 1
				si := strl - i - 1
				if xfix[xi] != str[si] {
					xfix = xfix[xi+1:]
					break
				}
			}
		}
	}
	return xfix
}

// Returns the mode in which MinIO is running
func getMinioMode() string {
	mode := globalMinioModeFS
	mode = globalMinioModeGatewayPrefix + globalGatewayName
	return mode
}

func iamPolicyClaimNameOpenID() string {
	return globalOpenIDConfig.ClaimPrefix + globalOpenIDConfig.ClaimName
}

func iamPolicyClaimNameSA() string {
	return "sa-policy"
}

// timedValue contains a synchronized value that is considered valid
// for a specific amount of time.
// An Update function must be set to provide an updated value when needed.
type timedValue struct {
	// Update must return an updated value.
	// If an error is returned the cached value is not set.
	// Only one caller will call this function at any time, others will be blocking.
	// The returned value can no longer be modified once returned.
	// Should be set before calling Get().
	Update func() (interface{}, error)

	// TTL for a cached value.
	// If not set 1 second TTL is assumed.
	// Should be set before calling Get().
	TTL time.Duration

	// Once can be used to initialize values for lazy initialization.
	// Should be set before calling Get().
	Once sync.Once

	// Managed values.
	value      interface{}
	lastUpdate time.Time
	mu         sync.RWMutex
}

// Get will return a cached value or fetch a new one.
// If the Update function returns an error the value is forwarded as is and not cached.
func (t *timedValue) Get() (interface{}, error) {
	v := t.get()
	if v != nil {
		return v, nil
	}

	v, err := t.Update()
	if err != nil {
		return v, err
	}

	t.update(v)
	return v, nil
}

func (t *timedValue) get() (v interface{}) {
	ttl := t.TTL
	if ttl <= 0 {
		ttl = time.Second
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	v = t.value
	if time.Since(t.lastUpdate) < ttl {
		return v
	}
	return nil
}

func (t *timedValue) update(v interface{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.value = v
	t.lastUpdate = time.Now()
}

// On MinIO a directory object is stored as a regular object with "__XLDIR__" suffix.
// For ex. "prefix/" is stored as "prefix__XLDIR__"
func encodeDirObject(object string) string {
	if HasSuffix(object, slashSeparator) {
		return strings.TrimSuffix(object, slashSeparator) + globalDirSuffix
	}
	return object
}

// Reverse process of encodeDirObject()
func decodeDirObject(object string) string {
	if HasSuffix(object, globalDirSuffix) {
		return strings.TrimSuffix(object, globalDirSuffix) + slashSeparator
	}
	return object
}

// This is used by metrics to show the number of failed RPC calls
// between internodes
func loadAndResetRPCNetworkErrsCounter() uint64 {
	defer rest.ResetNetworkErrsCounter()
	return rest.GetNetworkErrsCounter()
}

// AuditLogOptions takes options for audit logging subsystem activity
type AuditLogOptions struct {
	Trigger   string
	APIName   string
	Status    string
	VersionID string
}

// sends audit logs for internal subsystem activity
/*
func auditLogInternal(ctx context.Context, bucket, object string, opts AuditLogOptions) {
	entry := audit.NewEntry(globalDeploymentID)
	entry.Trigger = opts.Trigger
	entry.API.Name = opts.APIName
	entry.API.Bucket = bucket
	entry.API.Object = object
	if opts.VersionID != "" {
		entry.ReqQuery = make(map[string]string)
		entry.ReqQuery[xhttp.VersionID] = opts.VersionID
	}
	entry.API.Status = opts.Status
	ctx = logger.SetAuditEntry(ctx, &entry)
	logger.AuditLog(ctx, nil, nil, nil)
}
*/
