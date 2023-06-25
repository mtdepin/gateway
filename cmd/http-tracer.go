

package cmd

import (
	"bytes"
	"github.com/gorilla/mux"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/minio/madmin-go"
	"github.com/minio/minio/internal/handlers"
	"github.com/minio/minio/internal/logger"
)

// recordRequest - records the first recLen bytes
// of a given io.Reader
type recordRequest struct {
	// Data source to record
	io.Reader
	// Response body should be logged
	logBody bool
	// Internal recording buffer
	buf bytes.Buffer
	// request headers
	headers http.Header
	// total bytes read including header size
	bytesRead int
}

func (r *recordRequest) Read(p []byte) (n int, err error) {
	n, err = r.Reader.Read(p)
	r.bytesRead += n

	if r.logBody {
		r.buf.Write(p[:n])
	}
	if err != nil {
		return n, err
	}
	return n, err
}
func (r *recordRequest) Size() int {
	sz := r.bytesRead
	for k, v := range r.headers {
		sz += len(k) + len(v)
	}
	return sz
}

// Return the bytes that were recorded.
func (r *recordRequest) Data() []byte {
	// If body logging is enabled then we return the actual body
	if r.logBody {
		return r.buf.Bytes()
	}
	// ... otherwise we return <BODY> placeholder
	return logger.BodyPlaceHolder
}

var ldapPwdRegex = regexp.MustCompile("(^.*?)LDAPPassword=([^&]*?)(&(.*?))?$")

// redact LDAP password if part of string
func redactLDAPPwd(s string) string {
	parts := ldapPwdRegex.FindStringSubmatch(s)
	if len(parts) > 0 {
		return parts[1] + "LDAPPassword=*REDACTED*" + parts[3]
	}
	return s
}

// getOpName sanitizes the operation name for mc
func getOpName(name string) (op string) {
	op = strings.TrimPrefix(name, "github.com/minio/minio/cmd.")
	op = strings.TrimSuffix(op, "Handler-fm")
	op = strings.Replace(op, "objectAPIHandlers", "s3", 1)
	op = strings.Replace(op, "adminAPIHandlers", "admin", 1)
	op = strings.Replace(op, "(*webAPIHandlers)", "web", 1)
	op = strings.Replace(op, "(*storageRESTServer)", "internal", 1)
	op = strings.Replace(op, "(*peerRESTServer)", "internal", 1)
	op = strings.Replace(op, "(*lockRESTServer)", "internal", 1)
	op = strings.Replace(op, "(*stsAPIHandlers)", "sts", 1)
	op = strings.Replace(op, "LivenessCheckHandler", "healthcheck", 1)
	op = strings.Replace(op, "ReadinessCheckHandler", "healthcheck", 1)
	op = strings.Replace(op, "-fm", "", 1)
	return op
}

// Trace gets trace of http request
func Trace(f http.HandlerFunc, logBody bool, w http.ResponseWriter, r *http.Request) madmin.TraceInfo {
	name := getOpName(runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name())
	// Setup a http request body recorder
	reqHeaders := r.Header.Clone()
	reqHeaders.Set("Host", r.Host)
	if len(r.TransferEncoding) == 0 {
		reqHeaders.Set("Content-Length", strconv.Itoa(int(r.ContentLength)))
	} else {
		reqHeaders.Set("Transfer-Encoding", strings.Join(r.TransferEncoding, ","))
	}

	reqBodyRecorder := &recordRequest{Reader: r.Body, logBody: logBody, headers: reqHeaders}
	r.Body = ioutil.NopCloser(reqBodyRecorder)

	now := time.Now().UTC()
	t := madmin.TraceInfo{TraceType: madmin.TraceHTTP, FuncName: name, Time: now}
	//add by zk
	vars := mux.Vars(r)
	t.StorageStats = madmin.TraceStorageStats{
		Path: vars["bucket"],
	}
	//end
	t.NodeName = r.Host

	if t.NodeName == "" {
		t.NodeName = globalLocalNodeName
	}

	// strip only standard port from the host address
	if host, port, err := net.SplitHostPort(t.NodeName); err == nil {
		if port == "443" || port == "80" {
			t.NodeName = host
		}
	}

	rq := madmin.TraceRequestInfo{
		Time:     now,
		Proto:    r.Proto,
		Method:   r.Method,
		RawQuery: redactLDAPPwd(r.URL.RawQuery),
		Client:   handlers.GetSourceIP(r),
		Headers:  reqHeaders,
	}

	path := r.URL.RawPath
	if path == "" {
		path = r.URL.Path
	}
	rq.Path = path

	rw := logger.NewResponseWriter(w)
	rw.LogErrBody = true
	rw.LogAllBody = logBody

	// Execute call.
	f(rw, r)

	rs := madmin.TraceResponseInfo{
		Time:       time.Now().UTC(),
		Headers:    rw.Header().Clone(),
		StatusCode: rw.StatusCode,
		Body:       rw.Body(),
	}

	// Transfer request body
	rq.Body = reqBodyRecorder.Data()

	if rs.StatusCode == 0 {
		rs.StatusCode = http.StatusOK
	}

	t.ReqInfo = rq
	t.RespInfo = rs

	t.CallStats = madmin.TraceCallStats{
		Latency:         rs.Time.Sub(rw.StartTime),
		InputBytes:      reqBodyRecorder.Size(),
		OutputBytes:     rw.Size(),
		TimeToFirstByte: rw.TimeToFirstByte,
	}
	return t
}
