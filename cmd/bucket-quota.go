package cmd

import (
	"context"
	"time"

	"github.com/minio/madmin-go"
)

// BucketQuotaSys - map of bucket and quota configuration.
type BucketQuotaSys struct {
	bucketStorageCache timedValue
}

// Get - Get quota configuration.
func (sys *BucketQuotaSys) Get(bucketName string) (*madmin.BucketQuota, error) {
	objAPI := newObjectLayerFn()
	if objAPI == nil {
		return nil, errServerNotInitialized
	}
	return &madmin.BucketQuota{}, nil

}

func (sys *BucketQuotaSys) check(ctx context.Context, bucket string, size int64) error {
	objAPI := newObjectLayerFn()
	if objAPI == nil {
		return errServerNotInitialized
	}

	sys.bucketStorageCache.Once.Do(func() {
		sys.bucketStorageCache.TTL = 1 * time.Second
		sys.bucketStorageCache.Update = func() (interface{}, error) {
			ctx, done := context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
			return loadDataUsageFromBackend(ctx, objAPI)
		}
	})

	q, err := sys.Get(bucket)
	if err != nil {
		return err
	}

	if q != nil && q.Type == madmin.HardQuota && q.Quota > 0 {
		v, err := sys.bucketStorageCache.Get()
		if err != nil {
			return err
		}

		dui := v.(madmin.DataUsageInfo)

		bui, ok := dui.BucketsUsage[bucket]
		if !ok {
			// bucket not found, cannot enforce quota
			// call will fail anyways later.
			return nil
		}

		if (bui.Size + uint64(size)) >= q.Quota {
			return BucketQuotaExceeded{Bucket: bucket}
		}
	}

	return nil
}

func enforceBucketQuota(ctx context.Context, bucket string, size int64) error {
	if size < 0 {
		return nil
	}

	//return globalBucketQuotaSys.check(ctx, bucket, size)
	return nil
}
