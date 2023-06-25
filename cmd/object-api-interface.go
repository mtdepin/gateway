package cmd

import (
	"context"
	"io"
	"net/http"
	"time"

	bucketsse "github.com/minio/minio/internal/bucket/encryption"

	"github.com/minio/minio/internal/bucket/lifecycle"

	"github.com/minio/madmin-go"
	"github.com/minio/minio-go/v7/pkg/encrypt"
	"github.com/minio/minio-go/v7/pkg/tags"
	"github.com/minio/minio/internal/bucket/versioning"
	"github.com/minio/pkg/bucket/policy"
)

// CheckPreconditionFn returns true if precondition check failed.
type CheckPreconditionFn func(o ObjectInfo) bool

// GetObjectInfoFn is the signature of GetObjectInfo function.
type GetObjectInfoFn func(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error)

// ObjectOptions represents object options for ObjectLayer object operations
type ObjectOptions struct {
	ServerSideEncryption encrypt.ServerSide
	VersionSuspended     bool      // indicates if the bucket was previously versioned but is currently suspended.
	Versioned            bool      // indicates if the bucket is versioned
	WalkVersions         bool      // indicates if the we are interested in walking versions
	VersionID            string    // Specifies the versionID which needs to be overwritten or read
	MTime                time.Time // Is only set in POST/PUT operations
	Expires              time.Time // Is only used in POST/PUT operations

	DeleteMarker                  bool                // Is only set in DELETE operations for delete marker replication
	UserDefined                   map[string]string   // only set in case of POST/PUT operations
	PartNumber                    int                 // only useful in case of GetObject/HeadObject
	CheckPrecondFn                CheckPreconditionFn // only set during GetObject/HeadObject/CopyObjectPart preconditional valuation
	DeleteMarkerReplicationStatus string              // Is only set in DELETE operations
	Transition                    TransitionOptions

	NoLock         bool                                                  // indicates to lower layers if the caller is expecting to hold locks.
	ProxyRequest   bool                                                  // only set for GET/HEAD in active-active replication scenario
	ProxyHeaderSet bool                                                  // only set for GET/HEAD in active-active replication scenario
	ParentIsObject func(ctx context.Context, bucket, parent string) bool // Used to verify if parent is an object.

	DeletePrefix bool //  set true to enforce a prefix deletion, only application for DeleteObject API,

	// Use the maximum parity (N/2), used when saving server configuration files
	MaxParity   bool
	FetchDelete bool // is only Remove completely
}

// TransitionOptions represents object options for transition ObjectLayer operation
type TransitionOptions struct {
	Status         string
	Tier           string
	ETag           string
	RestoreRequest *RestoreObjectRequest
	RestoreExpiry  time.Time
	ExpireRestored bool
}

// BucketOptions represents bucket options for ObjectLayer bucket operations
type BucketOptions struct {
	Location          string
	LockEnabled       bool
	VersioningEnabled bool
	StorageClass      string
	Acl               string
}

// LockType represents required locking for ObjectLayer operations
type LockType int

const (
	noLock LockType = iota
	readLock
	writeLock
)

// BackendMetrics - represents bytes served from backend
type BackendMetrics struct {
	bytesReceived uint64
	bytesSent     uint64
	requestStats  RequestStats
}

// ObjectLayer implements primitives for object API layer.
type ObjectLayer interface {
	// Locking operations on object.
	//NewNSLock(bucket string, objects ...string) RWLocker

	// Storage operations.
	Shutdown(context.Context) error
	//NSScanner(ctx context.Context, bf *bloomFilter, updates chan<- madmin.DataUsageInfo) error

	BackendInfo() madmin.BackendInfo
	StorageInfo(ctx context.Context) (StorageInfo, []error)
	LocalStorageInfo(ctx context.Context) (StorageInfo, []error)

	// Bucket operations.
	MakeBucketWithLocation(ctx context.Context, bucket string, opts BucketOptions) error
	GetBucketInfo(ctx context.Context, bucket string) (bucketInfo BucketInfo, err error)
	GetBucketInfoDetail(ctx context.Context, bucket string) (bucketInfo BucketInfoDetail, err error)
	ListBuckets(ctx context.Context) (buckets []BucketInfo, err error)
	DeleteBucket(ctx context.Context, bucket string, forceDelete bool) error
	ListObjects(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int, fetchDelete bool) (result ListObjectsInfo, err error)
	ListObjectsV2(ctx context.Context, bucket, prefix, continuationToken, delimiter string, maxKeys int, fetchOwner, fetchDelete bool, startAfter string) (result ListObjectsV2Info, err error)
	ListObjectVersions(ctx context.Context, bucket, prefix, marker, versionMarker, delimiter string, maxKeys int, fetchDelete bool) (result ListObjectVersionsInfo, err error)
	// Walk lists all objects including versions, delete markers.
	Walk(ctx context.Context, bucket, prefix string, results chan<- ObjectInfo, opts ObjectOptions) error
	IsBucketEncryption(ctx context.Context, bucket string) (bool, error)
	GetBucketEncryption(ctx context.Context, bucket string) (*bucketsse.BucketSSEConfig, error)
	DeleteBucketEncryption(ctx context.Context, bucket string) error
	PutBucketEncryption(ctx context.Context, bucket string, encConfig bucketsse.BucketSSEConfig) error
	// Object operations.

	// GetObjectNInfo returns a GetObjectReader that satisfies the
	// ReadCloser interface. The Close method unlocks the object
	// after reading, so it must always be called after usage.
	//
	// IMPORTANTLY, when implementations return err != nil, this
	// function MUST NOT return a non-nil ReadCloser.
	GetObjectNInfo(ctx context.Context, bucket, object string, rs *HTTPRangeSpec, h http.Header, lockType LockType, opts ObjectOptions) (reader *GetObjectReader, err error)
	GetObjectInfo(ctx context.Context, bucket, object string, opts ObjectOptions) (objInfo ObjectInfo, err error)
	PutObject(ctx context.Context, bucket, object string, data *PutObjReader, opts ObjectOptions) (objInfo ObjectInfo, err error)
	PostObject(ctx context.Context, bucket, object string, data *PutObjReader, opts ObjectOptions) (objInfo ObjectInfo, err error)
	CopyObject(ctx context.Context, srcBucket, srcObject, destBucket, destObject string, srcInfo ObjectInfo, srcOpts, dstOpts ObjectOptions) (objInfo ObjectInfo, err error)
	DeleteObject(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error)
	DeleteObjects(ctx context.Context, bucket string, objects []ObjectToDelete, opts ObjectOptions) ([]DeletedObject, []error)
	TransitionObject(ctx context.Context, bucket, object string, opts ObjectOptions) error
	RestoreTransitionedObject(ctx context.Context, bucket, object string, opts ObjectOptions) error

	// Multipart operations.
	ListMultipartUploads(ctx context.Context, bucket, prefix, keyMarker, uploadIDMarker, delimiter string, maxUploads int) (result ListMultipartsInfo, err error)
	NewMultipartUpload(ctx context.Context, bucket, object string, opts ObjectOptions) (uploadID string, err error)
	CopyObjectPart(ctx context.Context, srcBucket, srcObject, destBucket, destObject string, uploadID string, partID int,
		startOffset int64, length int64, srcInfo ObjectInfo, srcOpts, dstOpts ObjectOptions) (info PartInfo, err error)
	PutObjectPart(ctx context.Context, bucket, object, uploadID string, partID int, data *PutObjReader, opts ObjectOptions) (info PartInfo, err error)
	GetMultipartInfo(ctx context.Context, bucket, object, uploadID string, opts ObjectOptions) (info MultipartInfo, err error)
	ListObjectParts(ctx context.Context, bucket, object, uploadID string, partNumberMarker int, maxParts int, opts ObjectOptions) (result ListPartsInfo, err error)
	AbortMultipartUpload(ctx context.Context, bucket, object, uploadID string, opts ObjectOptions) error
	CompleteMultipartUpload(ctx context.Context, bucket, object, uploadID string, uploadedParts []CompletePart, opts ObjectOptions) (objInfo ObjectInfo, err error)

	// Policy operations
	SetBucketPolicy(context.Context, string, *policy.Policy) error
	GetBucketPolicy(context.Context, string) (*policy.Policy, error)
	DeleteBucketPolicy(context.Context, string) error

	// Versioning Operations
	PutBucketVersioning(context.Context, string, []byte) error
	GetBucketVersioning(context.Context, string) (*versioning.Versioning, error)

	// Supported operations check
	IsNotificationSupported() bool
	IsListenSupported() bool
	IsEncryptionSupported() bool
	IsTaggingSupported() bool
	IsCompressionSupported() bool

	// IsCommonEncryptionSupported 常规加密
	IsCommonEncryptionSupported() bool

	SetDriveCounts() []int // list of erasure stripe size for each pool in order.

	// Healing operations.
	HealFormat(ctx context.Context, dryRun bool) (madmin.HealResultItem, error)
	HealBucket(ctx context.Context, bucket string, opts madmin.HealOpts) (madmin.HealResultItem, error)
	HealObject(ctx context.Context, bucket, object, versionID string, opts madmin.HealOpts) (madmin.HealResultItem, error)
	//HealObjects(ctx context.Context, bucket, prefix string, opts madmin.HealOpts, fn HealObjectFn) error

	// Backend related metrics
	GetMetrics(ctx context.Context) (*BackendMetrics, error)

	// Returns health of the backend
	//Health(ctx context.Context, opts HealthOptions) HealthResult
	ReadHealth(ctx context.Context) bool

	// Metadata operations
	PutObjectMetadata(context.Context, string, string, ObjectOptions) (ObjectInfo, error)

	// ObjectTagging operations
	PutObjectTags(context.Context, string, string, string, ObjectOptions) (ObjectInfo, error)
	GetObjectTags(context.Context, string, string, ObjectOptions) (*tags.Tags, error)
	DeleteObjectTags(context.Context, string, string, ObjectOptions) (ObjectInfo, error)

	// bucketTagging operations
	PutBucketTags(context.Context, string, string, ObjectOptions) (BucketInfo, error)
	GetBucketTags(context.Context, string, ObjectOptions) (*tags.Tags, error)
	DeleteBucketTags(context.Context, string, ObjectOptions) (BucketInfo, error)

	//MtCompatible
	GetBucketLogging(context.Context, string) (BucketLoggingRet, error)
	PutBucketLogging(context.Context, string, BucketLoggingRet) error
	DeleteBucketLogging(context.Context, string) error
	//MtCompatible lifecycle
	PutBucketLifeCycle(ctx context.Context, bucket string, sys *lifecycle.Lifecycle) error

	GetBucketLifeCycle(ctx context.Context, bucket string) (*lifecycle.Lifecycle, error)
	DeleteBucketLifeCycle(ctx context.Context, bucket string) error

	ListBucketSize(ctx context.Context) (map[string]BucketObjectSizeAndCount, error)

	GetNameServerAddress(ctx context.Context) string

	//mt BucketACL
	GetBucketACL(ctx context.Context, bucket string) (string, error)
	SetBucketACL(ctx context.Context, bucket string, acl string) error
	DeleteBucketACL(ctx context.Context, bucket string) error

	//mt ObjectACL
	GetObjectACL(ctx context.Context, bucket string, object string, opts ObjectOptions) (string, error)
	SetObjectACL(ctx context.Context, bucket string, object string, acl string, opts ObjectOptions) error
	DeleteObjectACL(ctx context.Context, bucket string, object string, opts ObjectOptions) error

	// GetDagTree mt dag tree
	GetDagTree(ctx context.Context, bucket, object, cid string, opts ObjectOptions) ([]byte, error)
}

type BucketObjectSizeAndCount struct {
	Size         uint64
	ObjectsCount uint64
}

// GetObject - TODO(aead): This function just acts as an adapter for GetObject tests and benchmarks
// since the GetObject method of the ObjectLayer interface has been removed. Once, the
// tests are adjusted to use GetObjectNInfo this function can be removed.
func GetObject(ctx context.Context, api ObjectLayer, bucket, object string, startOffset int64, length int64, writer io.Writer, etag string, opts ObjectOptions) (err error) {
	var header http.Header
	if etag != "" {
		header.Set("ETag", etag)
	}
	Range := &HTTPRangeSpec{Start: startOffset, End: startOffset + length}

	reader, err := api.GetObjectNInfo(ctx, bucket, object, Range, header, readLock, opts)
	if err != nil {
		return err
	}
	defer reader.Close()

	_, err = io.Copy(writer, reader)
	return err
}
