package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	jsoniter "github.com/json-iterator/go"
	"github.com/minio/madmin-go"
	"github.com/minio/minio/maitian/config"
	"io/ioutil"
	"net/http"
)

const (
	dataUsageBucket  = minioMetaBucket + SlashSeparator + bucketMetaPrefix
	dataUsageObjName = ".usage.json"
)

func loadDataUsageFromBackendV1(ctx context.Context) (madmin.DataUsageInfo, error) {
	address := fmt.Sprintf("%s/ns/v1", config.GetString("nameserver-address"))
	client := http.Client{}
	url := fmt.Sprintf("%s/backend", address)
	request, _ := http.NewRequest(http.MethodGet, url, nil)
	resp, e := client.Do(request)
	if e != nil {
		return madmin.DataUsageInfo{}, e
	}
	if resp.StatusCode != http.StatusOK {
		return madmin.DataUsageInfo{}, nil
	}
	retM := make(map[string]interface{})
	rs, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err := json.Unmarshal(rs, &retM); err != nil {
		return madmin.DataUsageInfo{}, err
	}
	return madmin.DataUsageInfo{
		BucketsCount:      uint64(retM["bucketnum"].(float64)),
		ObjectsTotalCount: uint64(retM["objectnum"].(float64)),
		ObjectsTotalSize:  uint64(retM["totalsize"].(float64)),
	}, nil
}

func loadDataUsageFromBackendV2(ctx context.Context, objAPI ObjectLayer) (madmin.DataUsageInfo, error) {
	ret, err := objAPI.ListBucketSize(ctx)
	if err != nil {
		return madmin.DataUsageInfo{}, err
	}
	var (
		dataUsageInfo                       madmin.DataUsageInfo
		ObjectsTotalCount, ObjectsTotalSize uint64
	)

	dataUsageInfo.BucketSizes = make(map[string]uint64, len(ret))
	dataUsageInfo.BucketsUsage = make(map[string]madmin.BucketUsageInfo, len(ret))
	for k, v := range ret {
		dataUsageInfo.BucketSizes[k] = v.Size
		dataUsageInfo.BucketsUsage[k] = madmin.BucketUsageInfo{
			Size:         v.Size,
			ObjectsCount: v.ObjectsCount,
		}
		ObjectsTotalCount += v.ObjectsCount
		ObjectsTotalSize += v.Size
	}
	dataUsageInfo.BucketsCount = uint64(len(ret))
	dataUsageInfo.ObjectsTotalCount = ObjectsTotalCount
	dataUsageInfo.ObjectsTotalSize = ObjectsTotalSize
	return dataUsageInfo, nil
}

func loadDataUsageFromBackend(ctx context.Context, objAPI ObjectLayer) (madmin.DataUsageInfo, error) {
	r, err := objAPI.GetObjectNInfo(ctx, dataUsageBucket, dataUsageObjName, nil, http.Header{}, readLock, ObjectOptions{})
	if err != nil {
		if isErrObjectNotFound(err) || isErrBucketNotFound(err) {
			return madmin.DataUsageInfo{}, nil
		}
		return madmin.DataUsageInfo{}, toObjectErr(err, dataUsageBucket, dataUsageObjName)
	}
	defer r.Close()

	var dataUsageInfo madmin.DataUsageInfo
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	if err = json.NewDecoder(r).Decode(&dataUsageInfo); err != nil {
		return madmin.DataUsageInfo{}, err
	}

	// For forward compatibility reasons, we need to add this code.
	if len(dataUsageInfo.BucketsUsage) == 0 {
		dataUsageInfo.BucketsUsage = make(map[string]madmin.BucketUsageInfo, len(dataUsageInfo.BucketSizes))
		for bucket, size := range dataUsageInfo.BucketSizes {
			dataUsageInfo.BucketsUsage[bucket] = madmin.BucketUsageInfo{Size: size}
		}
	}

	// For backward compatibility reasons, we need to add this code.
	if len(dataUsageInfo.BucketSizes) == 0 {
		dataUsageInfo.BucketSizes = make(map[string]uint64, len(dataUsageInfo.BucketsUsage))
		for bucket, bui := range dataUsageInfo.BucketsUsage {
			dataUsageInfo.BucketSizes[bucket] = bui.Size
		}
	}

	return dataUsageInfo, nil
}
