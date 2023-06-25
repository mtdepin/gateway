package cmd

import (
	"context"
	"encoding/json"
	"time"

	"github.com/minio/minio/internal/logger"
	"github.com/minio/minio/maitian/config"
)

type ChargeModel struct {
	RequestId    string     `json:"requestId"`    //请求ID
	UserName     string     `json:"userName"`     //租户名称
	FileName     string     `json:"fileName"`     //文件名称
	Size         int64      `json:"size"`         //文件大小
	RequestType  ChargeType `json:"requestType"`  //请求类型 0上传 1下载 2删除
	StorageClass int        `json:"storageClass"` //存储类型 0标准 1低频 3归档 1冷备
	BucketName   string     `json:"bucketName"`   //桶名称
	RegionId     string     `json:"regionId"`     //区域ID
	BusinessTime int64      `json:"businessTime"` //业务时间(时间戳)
	VersionId    string     `json:"versionId"`    //版本号
}

const (
	CHARGE_UPLOAD   ChargeType = 0
	CHARGE_DOWNLOAD ChargeType = 1
	CHARGE_DELETE   ChargeType = 2
)

const (
	topic_upload   = "uploadTopic"
	topic_download = "downloadTopic"
	topic_delete   = "deleteTopic"
)

/*
存储级别字段：
// Standard storage class
STANDARD = "STANDARD"
// Infrequent Access
IA = "IA"
// Archive
Archive = "Archive"
// Cold Archive
CA = "CA"
*/
const (
	STORAGE_TYPE_STANDARD = 0
	STORAGE_TYPE_IA       = 2
	STORAGE_TYPE_ARCHIVE  = 3
	STORAGE_TYPE_CA       = 1
)

func InitCharge() {
	if config.GetString("mq.uploadTopic") != "" {

	}
}

type ChargeType int

func SendToCharge(ctx context.Context, tpy ChargeType, bucket BucketInfoDetail, object ObjectInfo) {
	info := globalIAMSys.GetAuthInfo(ctx)
	bucket.Bucket.Owner.Name = info.Cred.TenantUserName
	requestId := getRequestId(ctx)
	model := ChargeModel{
		RequestId:    requestId,
		UserName:     bucket.Bucket.Owner.Name,
		FileName:     object.Name,
		Size:         object.Size,
		RequestType:  tpy,
		StorageClass: getStorageType(object.StorageClass),
		BucketName:   object.Bucket,
		RegionId:     bucket.Bucket.Location,
		BusinessTime: time.Now().Unix(),
		VersionId:    object.VersionID,
	}
	jsonBytes, err := json.Marshal(model)
	logger.Infof("SendToCharge: %s", jsonBytes)
	if err != nil {
		logger.Error(err.Error())
	}
	//tp := getTopicByChargeType(tpy)
	//_ = mq.Send(ctx, tp, requestId, jsonBytes)
}

func getStorageType(class string) int {
	switch class {
	case "STANDARD": //标准
		return STORAGE_TYPE_STANDARD
	case "IA": //低频
		return STORAGE_TYPE_IA
	case "Archive":
		return STORAGE_TYPE_ARCHIVE
	case "CA": //cold archive
		return STORAGE_TYPE_CA
	default:
		return STORAGE_TYPE_STANDARD
	}
}

func getTopicByChargeType(tpy ChargeType) string {
	switch tpy {
	case CHARGE_UPLOAD:
		return topic_upload
	case CHARGE_DOWNLOAD:
		return topic_download
	case CHARGE_DELETE:
		return topic_delete
	}
	return "default"
}

func getRequestId(ctx context.Context) string {
	requestId := logger.GetReqInfo(ctx).RequestID
	return requestId
}
