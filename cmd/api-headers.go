package cmd

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio/internal/crypto"
	xhttp "github.com/minio/minio/internal/http"
)

// Utility to create random string of strlen length
func randomString(strlen int) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, strlen)
	seed := rand.NewSource(time.Now().UnixNano())
	rnd := rand.New(seed)
	for i := 0; i < strlen; i++ {
		result[i] = chars[rnd.Intn(len(chars))]
	}
	return string(result)
}

// Returns a hexadecimal representation of time at the
// time response is sent to the client.
func mustGetRequestID(t time.Time) string {
	return fmt.Sprintf("%X-%s", t.UnixNano(), MustGetUUID())
}

// setEventStreamHeaders to allow proxies to avoid buffering proxy responses
func setEventStreamHeaders(w http.ResponseWriter) {
	w.Header().Set(xhttp.ContentType, "text/event-stream")
	w.Header().Set(xhttp.CacheControl, "no-cache") // nginx to turn off buffering
	w.Header().Set("X-Accel-Buffering", "no")      // nginx to turn off buffering
}

// Write http common headers
func setCommonHeaders(w http.ResponseWriter) {
	// Set the "Server" http header.
	w.Header().Set(xhttp.ServerInfo, "MaitianOSS")

	// Set `x-amz-bucket-region` only if region is set on the server
	// by default minio uses an empty region.
	if region := globalServerRegion; region != "" {
		w.Header().Set(xhttp.AmzBucketRegion, region)
	}
	w.Header().Set(xhttp.AcceptRanges, "bytes")

	// Remove sensitive information
	crypto.RemoveSensitiveHeaders(w.Header())
}

// Encodes the response headers into XML format.
func encodeResponse(response interface{}) []byte {
	var bytesBuffer bytes.Buffer
	bytesBuffer.WriteString(xml.Header)
	e := xml.NewEncoder(&bytesBuffer)
	e.Encode(response)
	return bytesBuffer.Bytes()
}

// Encodes the response headers into JSON format.
func encodeResponseJSON(response interface{}) []byte {
	var bytesBuffer bytes.Buffer
	e := json.NewEncoder(&bytesBuffer)
	e.Encode(response)
	return bytesBuffer.Bytes()
}

// Write parts count
func setPartsCountHeaders(w http.ResponseWriter, objInfo ObjectInfo) {
	if strings.Contains(objInfo.ETag, "-") && len(objInfo.Parts) > 0 {
		w.Header()[xhttp.AmzMpPartsCount] = []string{strconv.Itoa(len(objInfo.Parts))}
	}
}

// Write object header
func setObjectHeaders(w http.ResponseWriter, objInfo ObjectInfo, rs *HTTPRangeSpec, opts ObjectOptions) (err error) {
	// set common headers
	setCommonHeaders(w)

	// Set last modified time.
	lastModified := objInfo.ModTime.UTC().Format(http.TimeFormat)
	w.Header().Set(xhttp.LastModified, lastModified)
	w.Header()[xhttp.AmzDeleteMarker] = []string{strconv.FormatBool(objInfo.DeleteMarker)}
	// Set Etag if available.
	if objInfo.ETag != "" {
		w.Header()[xhttp.ETag] = []string{"\"" + objInfo.ETag + "\""}
	}

	if objInfo.ContentType != "" {
		w.Header().Set(xhttp.ContentType, objInfo.ContentType)
	}

	if objInfo.StorageClass != "" {
		w.Header().Set(xhttp.StorageClass, objInfo.StorageClass)
	}

	if objInfo.ContentEncoding != "" {
		w.Header().Set(xhttp.ContentEncoding, objInfo.ContentEncoding)
	}

	if !objInfo.Expires.IsZero() {
		w.Header().Set(xhttp.Expires, objInfo.Expires.UTC().Format(http.TimeFormat))
	}

	//if globalCacheConfig.Enabled {
	//	w.Header().Set(xhttp.XCache, objInfo.CacheStatus.String())
	//	w.Header().Set(xhttp.XCacheLookup, objInfo.CacheLookupStatus.String())
	//}

	// Set tag count if object has tags
	if len(objInfo.UserTags) > 0 {
		tags, _ := url.ParseQuery(objInfo.UserTags)
		if len(tags) > 0 {
			w.Header()[xhttp.AmzTagCount] = []string{strconv.Itoa(len(tags))}
		}
	}

	// Set all other user defined metadata.
	for k, v := range objInfo.UserDefined {
		if strings.HasPrefix(strings.ToLower(k), ReservedMetadataPrefixLower) {
			// Do not need to send any internal metadata
			// values to client.
			continue
		}

		// https://github.com/google/security-research/security/advisories/GHSA-76wf-9vgp-pj7w
		//if equals(k, xhttp.AmzMetaUnencryptedContentLength, xhttp.AmzMetaUnencryptedContentMD5) {
		//	continue
		//}

		var isSet bool
		for _, userMetadataPrefix := range userMetadataKeyPrefixes {
			if !strings.HasPrefix(strings.ToLower(k), strings.ToLower(userMetadataPrefix)) {
				continue
			}
			w.Header()[strings.ToLower(k)] = []string{v}
			isSet = true
			break
		}

		if !isSet {
			w.Header().Set(k, v)
		}
	}

	var start, rangeLen int64
	totalObjectSize, err := objInfo.GetActualSize()
	if err != nil {
		return err
	}

	if rs == nil && opts.PartNumber > 0 {
		rs = partNumberToRangeSpec(objInfo, opts.PartNumber)
	}

	// For providing ranged content
	start, rangeLen, err = rs.GetOffsetLength(totalObjectSize)
	if err != nil {
		return err
	}

	// Set content length.
	if _, ok := opts.UserDefined[xhttp.ContentLength]; ok {
		w.Header().Set(xhttp.ContentLength, opts.UserDefined[xhttp.ContentLength])
	} else {
		w.Header().Set(xhttp.ContentLength, strconv.FormatInt(rangeLen, 10))
	}

	if rs != nil {
		contentRange := fmt.Sprintf("bytes %d-%d/%d", start, start+rangeLen-1, totalObjectSize)
		w.Header().Set(xhttp.ContentRange, contentRange)
	}

	// Set the relevant version ID as part of the response header.
	if objInfo.VersionID != "" {
		w.Header()[xhttp.AmzVersionID] = []string{objInfo.VersionID}
	}

	if objInfo.ReplicationStatus.String() != "" {
		w.Header()[xhttp.AmzBucketReplicationStatus] = []string{objInfo.ReplicationStatus.String()}
	}

	if objInfo.Cid != "" {
		w.Header()["Cid"] = []string{objInfo.Cid}
	}

	return nil
}
