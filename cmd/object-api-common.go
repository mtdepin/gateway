package cmd

import (
	"sync"

	"github.com/dustin/go-humanize"
)

const (
	// Block size used for all internal operations version 1.

	// TLDR..
	// Not used anymore xl.meta captures the right blockSize
	// so blockSizeV2 should be used for all future purposes.
	// this value is kept here to calculate the max API
	// requests based on RAM size for existing content.
	blockSizeV1 = 10 * humanize.MiByte

	// Block size used in erasure coding version 2.
	blockSizeV2 = 1 * humanize.MiByte

	// Buckets meta prefix.
	bucketMetaPrefix = "buckets"

	// ETag (hex encoded md5sum) of empty string.
	emptyETag = "d41d8cd98f00b204e9800998ecf8427e"
)

// Global object layer mutex, used for safely updating object layer.
var globalObjLayerMutex sync.RWMutex

// Global object layer, only accessed by globalObjectAPI.
var globalObjectAPI ObjectLayer
