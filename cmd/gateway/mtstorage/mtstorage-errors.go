package mtstorage

import (
	"github.com/minio/minio/cmd"
)

type mtstorageError struct{
	Code           string
	Description    string
	Bucket string
	Object string
}

// convert error message to object error
func toObjectError(msg mtstorageError) error {
	switch msg.Code{
	// bucket error code
	case "NoSuchBucket":
		return cmd.BucketNotFound{Bucket: msg.Bucket}
	case "BucketNotEmpty":
		return cmd.BucketNotEmpty{Bucket: msg.Bucket}
	case "BucketAlreadyOwnedByYou":
		return cmd.BucketAlreadyOwnedByYou{Bucket: msg.Bucket}
	case "NoSuchBucketPolicy":
		return cmd.BucketPolicyNotFound{Bucket: msg.Bucket}
	case "NoSuchLifecycleConfiguration":
		return cmd.BucketLifecycleNotFound{Bucket: msg.Bucket}
	case "NoSuchTagSet":
		return cmd.BucketTaggingNotFound{Bucket: msg.Bucket}
	case "NoSuchLogSet":
		return cmd.BucketLoggingNotFound{Bucket: msg.Bucket}
	case "NoSuchAclSet":
		return cmd.BucketACLNotFound{Bucket: msg.Bucket}

	// object error code
	case "NoSuchKey":
		return cmd.ObjectNotFound{Bucket: msg.Bucket, Object: msg.Object}
	case "NoSuchObjectTagSet":
		return cmd.ObjectTaggingNotFound{Bucket: msg.Bucket, Object: msg.Object}

	// database error code
	case "WriteDatabaseFailed":
		return cmd.WriteDataBaseFailed{Bucket: msg.Description}

	default:
		return nil
	}
}