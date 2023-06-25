

package cmd

import "github.com/minio/minio/internal/bucket/versioning"

// BucketVersioningSys - policy subsystem.
type BucketVersioningSys struct{}

// Enabled enabled versioning?
func (sys *BucketVersioningSys) Enabled(bucket string) bool {
	objAPI := newObjectLayerFn()
	if objAPI == nil {
		return false
	}
	vc, err := objAPI.GetBucketVersioning(GlobalContext, bucket)
	if err != nil {
		return false
	}
	return vc.Enabled()
}

// Suspended suspended versioning?
func (sys *BucketVersioningSys) Suspended(bucket string) bool {
	objAPI := newObjectLayerFn()
	if objAPI == nil {
		return false
	}
	vc, err := objAPI.GetBucketVersioning(GlobalContext, bucket)
	if err != nil {
		return false
	}
	return vc.Suspended()
}

// Get returns stored bucket policy
func (sys *BucketVersioningSys) Get(bucket string) (*versioning.Versioning, error) {
	objAPI := newObjectLayerFn()
	if objAPI == nil {
		return nil, errServerNotInitialized
	}

	return objAPI.GetBucketVersioning(GlobalContext, bucket)
}

// Reset BucketVersioningSys to initial state.
func (sys *BucketVersioningSys) Reset() {
	// There is currently no internal state.
}

// NewBucketVersioningSys - creates new versioning system.
func NewBucketVersioningSys() *BucketVersioningSys {
	return &BucketVersioningSys{}
}
