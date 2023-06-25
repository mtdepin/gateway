package cmd

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio-go/v7/pkg/tags"
	sse "github.com/minio/minio/internal/bucket/encryption"
	"github.com/minio/minio/internal/bucket/lifecycle"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/s3select"
)

const (
	// Disabled means the lifecycle rule is inactive
	Disabled = "Disabled"
	// TransitionStatus status of transition
	TransitionStatus = "transition-status"
	// TransitionedObjectName name of transitioned object
	TransitionedObjectName = "transitioned-object"
	// TransitionedVersionID is version of remote object
	TransitionedVersionID = "transitioned-versionID"
	// TransitionTier name of transition storage class
	TransitionTier = "transition-tier"
)

// LifecycleSys - Bucket lifecycle subsystem.
type LifecycleSys struct{}

// Get - gets lifecycle config associated to a given bucket name.
func (sys *LifecycleSys) Get(bucketName string) (lc *lifecycle.Lifecycle, err error) {
	objAPI := newObjectLayerFn()
	if objAPI == nil {
		return nil, errServerNotInitialized
	}

	return nil, BucketLifecycleNotFound{Bucket: bucketName}

}

// NewLifecycleSys - creates new lifecycle system.
func NewLifecycleSys() *LifecycleSys {
	return &LifecycleSys{}
}

type expiryTask struct {
	objInfo       ObjectInfo
	versionExpiry bool
}

type expiryState struct {
	once     sync.Once
	expiryCh chan expiryTask
}

func (es *expiryState) queueExpiryTask(oi ObjectInfo, rmVersion bool) {
	select {
	case <-GlobalContext.Done():
		es.once.Do(func() {
			close(es.expiryCh)
		})
	case es.expiryCh <- expiryTask{objInfo: oi, versionExpiry: rmVersion}:
	default:
	}
}

var (
	globalExpiryState *expiryState
)

func newExpiryState() *expiryState {
	return &expiryState{
		expiryCh: make(chan expiryTask, 10000),
	}
}

type transitionState struct {
	once sync.Once
	// add future metrics here
	transitionCh chan ObjectInfo
}

func (t *transitionState) queueTransitionTask(oi ObjectInfo) {
	select {
	case <-GlobalContext.Done():
		t.once.Do(func() {
			close(t.transitionCh)
		})
	case t.transitionCh <- oi:
	default:
	}
}

var (
	globalTransitionState      *transitionState
	globalTransitionConcurrent = runtime.GOMAXPROCS(0) / 2
)

func newTransitionState() *transitionState {
	// fix minimum concurrent transition to 1 for single CPU setup
	if globalTransitionConcurrent == 0 {
		globalTransitionConcurrent = 1
	}
	return &transitionState{
		transitionCh: make(chan ObjectInfo, 10000),
	}
}

var errInvalidStorageClass = errors.New("invalid storage class")

// expireAction represents different actions to be performed on expiry of a
// restored/transitioned object
type expireAction int

const (
	// ignore the zero value
	_ expireAction = iota
	// expireObj indicates expiry of 'regular' transitioned objects.
	expireObj
	// expireRestoredObj indicates expiry of restored objects.
	expireRestoredObj
)

// RestoreRequestType represents type of restore.
type RestoreRequestType string

const (
	// SelectRestoreRequest specifies select request. This is the only valid value
	SelectRestoreRequest RestoreRequestType = "SELECT"
)

// Encryption specifies encryption setting on restored bucket
type Encryption struct {
	EncryptionType sse.SSEAlgorithm `xml:"EncryptionType"`
	KMSContext     string           `xml:"KMSContext,omitempty"`
	KMSKeyID       string           `xml:"KMSKeyId,omitempty"`
}

// MetadataEntry denotes name and value.
type MetadataEntry struct {
	Name  string `xml:"Name"`
	Value string `xml:"Value"`
}

// S3Location specifies s3 location that receives result of a restore object request
type S3Location struct {
	BucketName   string          `xml:"BucketName,omitempty"`
	Encryption   Encryption      `xml:"Encryption,omitempty"`
	Prefix       string          `xml:"Prefix,omitempty"`
	StorageClass string          `xml:"StorageClass,omitempty"`
	Tagging      *tags.Tags      `xml:"Tagging,omitempty"`
	UserMetadata []MetadataEntry `xml:"UserMetadata"`
}

// OutputLocation specifies bucket where object needs to be restored
type OutputLocation struct {
	S3 S3Location `xml:"S3,omitempty"`
}

// IsEmpty returns true if output location not specified.
func (o *OutputLocation) IsEmpty() bool {
	return o.S3.BucketName == ""
}

// SelectParameters specifies sql select parameters
type SelectParameters struct {
	s3select.S3Select
}

// IsEmpty returns true if no select parameters set
func (sp *SelectParameters) IsEmpty() bool {
	return sp == nil
}

var (
	selectParamsXMLName = "SelectParameters"
)

// UnmarshalXML - decodes XML data.
func (sp *SelectParameters) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	// Essentially the same as S3Select barring the xml name.
	if start.Name.Local == selectParamsXMLName {
		start.Name = xml.Name{Space: "", Local: "SelectRequest"}
	}
	return sp.S3Select.UnmarshalXML(d, start)
}

// RestoreObjectRequest - xml to restore a transitioned object
type RestoreObjectRequest struct {
	XMLName          xml.Name           `xml:"http://s3.amazonaws.com/doc/2006-03-01/ RestoreRequest" json:"-"`
	Days             int                `xml:"Days,omitempty"`
	Type             RestoreRequestType `xml:"Type,omitempty"`
	Tier             string             `xml:"Tier,-"`
	Description      string             `xml:"Description,omitempty"`
	SelectParameters *SelectParameters  `xml:"SelectParameters,omitempty"`
	OutputLocation   OutputLocation     `xml:"OutputLocation,omitempty"`
}

// Maximum 2MiB size per restore object request.
const maxRestoreObjectRequestSize = 2 << 20

// parseRestoreRequest parses RestoreObjectRequest from xml
func parseRestoreRequest(reader io.Reader) (*RestoreObjectRequest, error) {
	req := RestoreObjectRequest{}
	if err := xml.NewDecoder(io.LimitReader(reader, maxRestoreObjectRequestSize)).Decode(&req); err != nil {
		return nil, err
	}
	return &req, nil
}

// validate a RestoreObjectRequest as per AWS S3 spec https://docs.aws.amazon.com/AmazonS3/latest/API/API_RestoreObject.html
func (r *RestoreObjectRequest) validate(ctx context.Context, objAPI ObjectLayer) error {
	if r.Type != SelectRestoreRequest && !r.SelectParameters.IsEmpty() {
		return fmt.Errorf("Select parameters can only be specified with SELECT request type")
	}
	if r.Type == SelectRestoreRequest && r.SelectParameters.IsEmpty() {
		return fmt.Errorf("SELECT restore request requires select parameters to be specified")
	}

	if r.Type != SelectRestoreRequest && !r.OutputLocation.IsEmpty() {
		return fmt.Errorf("OutputLocation required only for SELECT request type")
	}
	if r.Type == SelectRestoreRequest && r.OutputLocation.IsEmpty() {
		return fmt.Errorf("OutputLocation required for SELECT requests")
	}

	if r.Days != 0 && r.Type == SelectRestoreRequest {
		return fmt.Errorf("Days cannot be specified with SELECT restore request")
	}
	if r.Days == 0 && r.Type != SelectRestoreRequest {
		return fmt.Errorf("restoration days should be at least 1")
	}
	// Check if bucket exists.
	if !r.OutputLocation.IsEmpty() {
		if _, err := objAPI.GetBucketInfo(ctx, r.OutputLocation.S3.BucketName); err != nil {
			return err
		}
		if r.OutputLocation.S3.Prefix == "" {
			return fmt.Errorf("Prefix is a required parameter in OutputLocation")
		}
		if r.OutputLocation.S3.Encryption.EncryptionType != xhttp.AmzEncryptionAES {
			return NotImplemented{}
		}
	}
	return nil
}

var errRestoreHDRMalformed = fmt.Errorf("x-amz-restore header malformed")

// IsRemote returns true if this object version's contents are in its remote
// tier.
func (oi ObjectInfo) IsRemote() bool {
	if oi.TransitionStatus != lifecycle.TransitionComplete {
		return false
	}
	return !isRestoredObjectOnDisk(oi.UserDefined)
}

// restoreObjStatus represents a restore-object's status. It can be either
// ongoing or completed.
type restoreObjStatus struct {
	ongoing bool
	expiry  time.Time
}

// ongoingRestoreObj constructs restoreObjStatus for an ongoing restore-object.
func ongoingRestoreObj() restoreObjStatus {
	return restoreObjStatus{
		ongoing: true,
	}
}

// completeRestoreObj constructs restoreObjStatus for a completed restore-object with given expiry.
func completedRestoreObj(expiry time.Time) restoreObjStatus {
	return restoreObjStatus{
		ongoing: false,
		expiry:  expiry.UTC(),
	}
}

// String returns x-amz-restore compatible representation of r.
func (r restoreObjStatus) String() string {
	if r.Ongoing() {
		return "ongoing-request=true"
	}
	return fmt.Sprintf("ongoing-request=false, expiry-date=%s", r.expiry.Format(http.TimeFormat))
}

// Expiry returns expiry of restored object and true if restore-object has completed.
// Otherwise returns zero value of time.Time and false.
func (r restoreObjStatus) Expiry() (time.Time, bool) {
	if r.Ongoing() {
		return time.Time{}, false
	}
	return r.expiry, true
}

// Ongoing returns true if restore-object is ongoing.
func (r restoreObjStatus) Ongoing() bool {
	return r.ongoing
}

// OnDisk returns true if restored object contents exist in MinIO. Otherwise returns false.
// The restore operation could be in one of the following states,
// - in progress (no content on MinIO's disks yet)
// - completed
// - completed but expired (again, no content on MinIO's disks)
func (r restoreObjStatus) OnDisk() bool {
	if expiry, ok := r.Expiry(); ok && time.Now().UTC().Before(expiry) {
		// completed
		return true
	}
	return false // in progress or completed but expired
}

// parseRestoreObjStatus parses restoreHdr from AmzRestore header. If the value is valid it returns a
// restoreObjStatus value with the status and expiry (if any). Otherwise returns
// the empty value and an error indicating the parse failure.
func parseRestoreObjStatus(restoreHdr string) (restoreObjStatus, error) {
	tokens := strings.SplitN(restoreHdr, ",", 2)
	progressTokens := strings.SplitN(tokens[0], "=", 2)
	if len(progressTokens) != 2 {
		return restoreObjStatus{}, errRestoreHDRMalformed
	}
	if strings.TrimSpace(progressTokens[0]) != "ongoing-request" {
		return restoreObjStatus{}, errRestoreHDRMalformed
	}

	switch progressTokens[1] {
	case "true":
		if len(tokens) == 1 {
			return ongoingRestoreObj(), nil
		}

	case "false":
		if len(tokens) != 2 {
			return restoreObjStatus{}, errRestoreHDRMalformed
		}
		expiryTokens := strings.SplitN(tokens[1], "=", 2)
		if len(expiryTokens) != 2 {
			return restoreObjStatus{}, errRestoreHDRMalformed
		}
		if strings.TrimSpace(expiryTokens[0]) != "expiry-date" {
			return restoreObjStatus{}, errRestoreHDRMalformed
		}

		expiry, err := time.Parse(http.TimeFormat, expiryTokens[1])
		if err != nil {
			return restoreObjStatus{}, errRestoreHDRMalformed
		}
		return completedRestoreObj(expiry), nil
	}
	return restoreObjStatus{}, errRestoreHDRMalformed
}

// isRestoredObjectOnDisk returns true if the restored object is on disk. Note
// this function must be called only if object version's transition status is
// complete.
func isRestoredObjectOnDisk(meta map[string]string) (onDisk bool) {
	if restoreHdr, ok := meta[xhttp.AmzRestore]; ok {
		if restoreStatus, err := parseRestoreObjStatus(restoreHdr); err == nil {
			return restoreStatus.OnDisk()
		}
	}
	return onDisk
}

// ToLifecycleOpts returns lifecycle.ObjectOpts value for oi.
func (oi ObjectInfo) ToLifecycleOpts() lifecycle.ObjectOpts {
	return lifecycle.ObjectOpts{
		Name:                   oi.Name,
		UserTags:               oi.UserTags,
		VersionID:              oi.VersionID,
		ModTime:                oi.ModTime,
		IsLatest:               oi.IsLatest,
		NumVersions:            oi.NumVersions,
		DeleteMarker:           oi.DeleteMarker,
		SuccessorModTime:       oi.SuccessorModTime,
		RestoreOngoing:         oi.RestoreOngoing,
		RestoreExpires:         oi.RestoreExpires,
		TransitionStatus:       oi.TransitionStatus,
		RemoteTiersImmediately: globalDebugRemoteTiersImmediately,
	}
}
