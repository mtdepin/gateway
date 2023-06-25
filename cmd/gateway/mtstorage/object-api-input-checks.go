

package mtstorage

import (
	"context"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7/pkg/s3utils"
	"github.com/minio/minio/cmd"
	"github.com/minio/minio/internal/logger"
)

// Checks on GetObject arguments, bucket and object.
func checkGetObjArgs(ctx context.Context, bucket, object string) error {
	return checkBucketAndObjectNames(ctx, bucket, object)
}

// Checks on DeleteObject arguments, bucket and object.
func checkDelObjArgs(ctx context.Context, bucket, object string) error {
	return checkBucketAndObjectNames(ctx, bucket, object)
}

// Checks bucket and object name validity, returns nil if both are valid.
func checkBucketAndObjectNames(ctx context.Context, bucket, object string) error {
	// Verify if bucket is valid.
	if s3utils.CheckValidBucketName(bucket) != nil {
		logger.LogIf(ctx, cmd.BucketNameInvalid{Bucket: bucket})
		return cmd.BucketNameInvalid{Bucket: bucket}
	}
	// Verify if object is valid.
	if len(object) == 0 {
		logger.LogIf(ctx, cmd.ObjectNameInvalid{Bucket: bucket, Object: object})
		return cmd.ObjectNameInvalid{Bucket: bucket, Object: object}
	}
	if !cmd.IsValidObjectPrefix(object) {
		logger.LogIf(ctx, cmd.ObjectNameInvalid{Bucket: bucket, Object: object})
		return cmd.ObjectNameInvalid{Bucket: bucket, Object: object}
	}
	//if runtime.GOOS == cmd.globalWindowsOSName && strings.Contains(object, "\\") {
	//	// Objects cannot be contain \ in Windows and is listed as `Characters to Avoid`.
	//	return cmd.ObjectNameInvalid{Bucket: bucket, Object: object}
	//}
	return nil
}

// Checks for all ListObjects arguments validity.
func checkListObjsArgs(ctx context.Context, bucket, prefix, marker string, obj getBucketInfoI) error {
	// Verify if bucket exists before validating object name.
	// This is done on purpose since the order of errors is
	// important here bucket does not exist error should
	// happen before we return an error for invalid object name.
	// FIXME: should be moved to handler layer.
	if err := checkBucketExist(ctx, bucket, obj); err != nil {
		return err
	}
	// Validates object prefix validity after bucket exists.
	if !cmd.IsValidObjectPrefix(prefix) {
		logger.LogIf(ctx, cmd.ObjectNameInvalid{
			Bucket: bucket,
			Object: prefix,
		})
		return cmd.ObjectNameInvalid{
			Bucket: bucket,
			Object: prefix,
		}
	}
	// Verify if marker has prefix.
	if marker != "" && !cmd.HasPrefix(marker, prefix) {
		logger.LogIf(ctx, cmd.InvalidMarkerPrefixCombination{
			Marker: marker,
			Prefix: prefix,
		})
		return cmd.InvalidMarkerPrefixCombination{
			Marker: marker,
			Prefix: prefix,
		}
	}
	return nil
}

// Checks for all ListMultipartUploads arguments validity.
func checkListMultipartArgs(ctx context.Context, bucket, prefix, keyMarker, uploadIDMarker, delimiter string, obj cmd.ObjectLayer) error {
	if err := checkListObjsArgs(ctx, bucket, prefix, keyMarker, obj); err != nil {
		return err
	}
	if uploadIDMarker != "" {
		if cmd.HasSuffix(keyMarker, cmd.SlashSeparator) {

			logger.LogIf(ctx, cmd.InvalidUploadIDKeyCombination{
				UploadIDMarker: uploadIDMarker,
				KeyMarker:      keyMarker,
			})
			return cmd.InvalidUploadIDKeyCombination{
				UploadIDMarker: uploadIDMarker,
				KeyMarker:      keyMarker,
			}
		}
		if _, err := uuid.Parse(uploadIDMarker); err != nil {
			logger.LogIf(ctx, err)
			return cmd.MalformedUploadID{
				UploadID: uploadIDMarker,
			}
		}
	}
	return nil
}

// Checks for NewMultipartUpload arguments validity, also validates if bucket exists.
func checkNewMultipartArgs(ctx context.Context, bucket, object string, obj cmd.ObjectLayer) error {
	return checkObjectArgs(ctx, bucket, object, obj)
}

// Checks for PutObjectPart arguments validity, also validates if bucket exists.
func checkPutObjectPartArgs(ctx context.Context, bucket, object string, obj cmd.ObjectLayer) error {
	return checkObjectArgs(ctx, bucket, object, obj)
}

// Checks for ListParts arguments validity, also validates if bucket exists.
func checkListPartsArgs(ctx context.Context, bucket, object string, obj cmd.ObjectLayer) error {
	return checkObjectArgs(ctx, bucket, object, obj)
}

// Checks for CompleteMultipartUpload arguments validity, also validates if bucket exists.
func checkCompleteMultipartArgs(ctx context.Context, bucket, object string, obj cmd.ObjectLayer) error {
	return checkObjectArgs(ctx, bucket, object, obj)
}

// Checks for AbortMultipartUpload arguments validity, also validates if bucket exists.
func checkAbortMultipartArgs(ctx context.Context, bucket, object string, obj cmd.ObjectLayer) error {
	return checkObjectArgs(ctx, bucket, object, obj)
}

// Checks Object arguments validity, also validates if bucket exists.
func checkObjectArgs(ctx context.Context, bucket, object string, obj cmd.ObjectLayer) error {
	// Verify if bucket exists before validating object name.
	// This is done on purpose since the order of errors is
	// important here bucket does not exist error should
	// happen before we return an error for invalid object name.
	// FIXME: should be moved to handler layer.
	if err := checkBucketExist(ctx, bucket, obj); err != nil {
		return err
	}

	if err := cmd.CheckObjectNameForLengthAndSlash(bucket, object); err != nil {
		return err
	}

	// Validates object name validity after bucket exists.
	if !cmd.IsValidObjectName(object) {
		return cmd.ObjectNameInvalid{
			Bucket: bucket,
			Object: object,
		}
	}

	return nil
}

// Checks for PutObject arguments validity, also validates if bucket exists.
func checkPutObjectArgs(ctx context.Context, bucket, object string, obj getBucketInfoI) error {
	// Verify if bucket exists before validating object name.
	// This is done on purpose since the order of errors is
	// important here bucket does not exist error should
	// happen before we return an error for invalid object name.
	// FIXME: should be moved to handler layer.
	if err := checkBucketExist(ctx, bucket, obj); err != nil {
		return err
	}

	if err := cmd.CheckObjectNameForLengthAndSlash(bucket, object); err != nil {
		return err
	}
	if len(object) == 0 ||
		!cmd.IsValidObjectPrefix(object) {
		return cmd.ObjectNameInvalid{
			Bucket: bucket,
			Object: object,
		}
	}
	return nil
}

type getBucketInfoI interface {
	GetBucketInfo(ctx context.Context, bucket string) (bucketInfo cmd.BucketInfo, err error)
}

// Checks whether bucket exists and returns appropriate error if not.
func checkBucketExist(ctx context.Context, bucket string, obj getBucketInfoI) error {
	_, err := obj.GetBucketInfo(ctx, bucket)
	if err != nil {
		return err
	}
	return nil
}
