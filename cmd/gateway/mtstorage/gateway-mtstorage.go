package mtstorage

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/minio/cli"
	"github.com/minio/madmin-go"
	"github.com/minio/minio-go/v7/pkg/s3utils"
	minio "github.com/minio/minio/cmd"
	bucketsse "github.com/minio/minio/internal/bucket/encryption"
	"github.com/minio/minio/internal/bucket/versioning"
	"github.com/minio/minio/internal/crypto"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/minio/maitian/config"
	"github.com/minio/minio/maitian/tracing"
	"go.opencensus.io/trace"
)

func init() {

	const mtstorageGatewayTemplate = `
USAGE:
	minio gateway mtstorage
`
	err := minio.RegisterGatewayCommand(cli.Command{
		Name:               minio.MtStorageGateway,
		Usage:              "Mtstorage s3 gateway",
		Action:             mtstorageGatewayMain,
		HideHelpCommand:    true,
		CustomHelpTemplate: mtstorageGatewayTemplate,
	})
	if err != nil {
		panic(err)
		return
	}
}

func mtstorageGatewayMain(ctx *cli.Context) {
	//init config
	e := config.InitConfig()
	if e != nil {
		panic(e)
		return
	}

	address := config.GetString("nameserver-address")
	profile := config.GetBool("profile")
	minio.StartGateway(ctx, &MtStorage{address: address}, profile)
}

var (
	_      minio.Gateway     = &MtStorage{}
	_      minio.ObjectLayer = &mtStorageObject{}
	client                   = &http.Client{}
)

type MtStorage struct {
	address string
}

func (m *MtStorage) Name() string {

	return minio.MtStorageGateway
}

func (m *MtStorage) NewGatewayLayer() (minio.ObjectLayer, error) {
	mt := &mtStorageObject{
		address: fmt.Sprintf("%s/ns/v1", m.address),
	}
	// start cron job push bucketLogging to ipfs
	//go mt.initBucketCronJobs()
	//go mt.cronJobPushBucketLogging()
	return mt, nil
}

type mtStorageObject struct {
	address string
}

func (m *mtStorageObject) GetNameServerAddress(ctx context.Context) string {
	return fmt.Sprintf("%s/ns/v1", m.address)
}

func (m *mtStorageObject) BackendInfo() madmin.BackendInfo {

	return madmin.BackendInfo{
		Type:          madmin.Gateway,
		GatewayOnline: true,
	}
}

//xxx:8000/ns/v1/storage [get]
func (m *mtStorageObject) StorageInfo(ctx context.Context) (minio.StorageInfo, []error) {

	ctx, span := trace.StartSpan(ctx, "StorageInfo")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	storageURL := fmt.Sprintf("%s/storage", m.address)

	bts, err := doRequest(ctx, http.MethodGet, storageURL, nil, nil)
	if err != nil {
		logger.Error("response: %s", bts)
		return minio.StorageInfo{}, []error{err}
	}
	var ds []madmin.Disk
	err = json.Unmarshal(bts, &ds)
	if err != nil {
		return minio.StorageInfo{}, []error{err}
	}
	return minio.StorageInfo{Disks: ds, Backend: madmin.BackendInfo{
		Type:          madmin.Gateway,
		GatewayOnline: true,
	}}, []error{}

}

func (m *mtStorageObject) LocalStorageInfo(ctx context.Context) (minio.StorageInfo, []error) {

	return minio.StorageInfo{}, nil
}

func (m *mtStorageObject) ListObjectsV2(ctx context.Context, bucket, prefix, continuationToken, delimiter string, maxKeys int, fetchOwner, fetchDelete bool, startAfter string) (result minio.ListObjectsV2Info, err error) {
	marker := continuationToken
	if marker == "" {
		marker = startAfter
	}
	resultV1, err := m.ListObjects(ctx, bucket, prefix, marker, delimiter, maxKeys, fetchDelete)
	if err != nil {
		return minio.ListObjectsV2Info{}, err
	}
	return minio.ListObjectsV2Info{
		Objects:               resultV1.Objects,
		Prefixes:              resultV1.Prefixes,
		ContinuationToken:     continuationToken,
		NextContinuationToken: resultV1.NextMarker,
		IsTruncated:           resultV1.IsTruncated,
	}, nil
}

func (m *mtStorageObject) ListObjectVersions(ctx context.Context, bucket, prefix, marker, versionMarker, delimiter string, maxKeys int, fetchDelete bool) (result minio.ListObjectVersionsInfo, err error) {

	ctx, span := trace.StartSpan(ctx, "ListObjectVersions")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	prefix = strings.TrimSuffix(prefix, "/")
	if !strings.HasPrefix(prefix, "/") {
		prefix = fmt.Sprintf("/%s", prefix)
	}

	nsurl := fmt.Sprintf("%s/object/versions", m.address)

	args := map[string]string{
		"bucket":        bucket,
		"prefix":        prefix,
		"marker":        marker,
		"versionmarker": versionMarker,
		"delimiter":     delimiter,
		"maxkeys":       strconv.Itoa(maxKeys + 1),
		//"fetch-delete":  "true",
	}
	if fetchDelete {
		//nsurl += fmt.Sprintf("&fetch-delete=%s", "true")
		args["fetch-delete"] = "true"
	}
	objects, err := doRequest(ctx, http.MethodGet, nsurl, args, nil)
	if err != nil {
		logger.Error("response: %s", objects)
		return minio.ListObjectVersionsInfo{}, err
	}

	retM := make([]map[string]interface{}, 0)
	err = json.Unmarshal(objects, &retM)
	if err != nil {
		return minio.ListObjectVersionsInfo{}, err
	}

	objs := make([]minio.ObjectInfo, 0)
	prfixes := make([]string, 0)
	var nextMarker, nextVersionIDMarker string
	for index, ele := range retM {
		if index == maxKeys {
			nextMarker = ele["Name"].(string)
			if ele["Version"].(string) != "null" || ele["Version"].(string) != "" {
				nextVersionIDMarker = ele["Version"].(string)
			}
			break
		}

		modTime, _ := time.ParseInLocation(TimeFormat, ele["UpdatedAt"].(string), time.Local)
		etag := ""
		if ele["Etag"] != nil {
			etag = ele["Etag"].(string)
		}
		name := ele["Name"].(string)
		isDir := ele["Isdir"].(bool)
		if isDir {
			prfixes = append(prfixes, fmt.Sprintf("%s/", name))
			continue
		}
		dirname := ele["Dirname"].(string)
		if dirname != "/" {
			name = fmt.Sprintf("%s/%s", dirname, name)
		}

		objs = append(objs, minio.ObjectInfo{
			Bucket:       bucket,
			Name:         name,
			ModTime:      modTime,
			Size:         int64(ele["Content_length"].(float64)),
			IsDir:        ele["Isdir"].(bool),
			ETag:         etag,
			ContentType:  ele["Content_type"].(string),
			VersionID:    ele["Version"].(string),
			DeleteMarker: ele["ismarker"].(bool),
		})
	}

	return minio.ListObjectVersionsInfo{
		NextMarker:          nextMarker,
		NextVersionIDMarker: nextVersionIDMarker,
		Objects:             objs,
		Prefixes:            prfixes,
	}, nil
}

func (m *mtStorageObject) Walk(ctx context.Context, bucket, prefix string, results chan<- minio.ObjectInfo, opts minio.ObjectOptions) error {

	ctx, span := trace.StartSpan(ctx, "Walk")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	return nil
}

func (m *mtStorageObject) CopyObject(ctx context.Context, srcBucket, srcObject, destBucket, destObject string, srcInfo minio.ObjectInfo, srcOpts, dstOpts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {

	ctx, span := trace.StartSpan(ctx, "CopyObject")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	cpSrcDstSame := minio.IsStringEqual(fmt.Sprintf("%s/%s", srcBucket, srcObject), fmt.Sprintf("%s/%s", destBucket, destObject))
	if cpSrcDstSame && srcInfo.VersionID == "" {
		return m.GetObjectInfo(ctx, srcBucket, srcObject, minio.ObjectOptions{})
	}
	return m.PutObject(ctx, destBucket, destObject, srcInfo.PutObjReader, minio.ObjectOptions{
		ServerSideEncryption: dstOpts.ServerSideEncryption,
		UserDefined:          srcInfo.UserDefined,
	})
}

func (m *mtStorageObject) TransitionObject(ctx context.Context, bucket, object string, opts minio.ObjectOptions) error {

	ctx, span := trace.StartSpan(ctx, "TransitionObject")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	return nil
}

func (m *mtStorageObject) RestoreTransitionedObject(ctx context.Context, bucket, object string, opts minio.ObjectOptions) error {

	ctx, span := trace.StartSpan(ctx, "RestoreTransitionedObject")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()
	// todo 实现对象解冻
	return nil
}

func (m *mtStorageObject) ListMultipartUploads(ctx context.Context, bucket, prefix, keyMarker, uploadIDMarker, delimiter string, maxUploads int) (result minio.ListMultipartsInfo, err error) {

	ctx, span := trace.StartSpan(ctx, "ListMultipartUploads")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	return minio.ListMultipartsInfo{}, nil
}

func (m *mtStorageObject) CopyObjectPart(ctx context.Context, srcBucket, srcObject, destBucket, destObject string, uploadID string, partID int, startOffset int64, length int64, srcInfo minio.ObjectInfo, srcOpts, dstOpts minio.ObjectOptions) (info minio.PartInfo, err error) {

	ctx, span := trace.StartSpan(ctx, "CopyObjectPart")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	return m.PutObjectPart(ctx, destBucket, destObject, uploadID, partID, srcInfo.PutObjReader, dstOpts)
}

type MultiPart struct {
	UploadID   string
	Bucket     string
	Object     string
	Chunker    string
	TotalSize  uint64
	Count      int
	CreateTime time.Time
}

func (m *mtStorageObject) NewMultipartUpload(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (uploadID string, err error) {

	ctx, span := trace.StartSpan(ctx, "NewMultipartUpload")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()
	object = checkObject(object)
	if !strings.HasPrefix(object, "/") {
		object = fmt.Sprintf("/%s", object)
	}
	//path := fmt.Sprintf("%s/%s", m.multipartDir, multipartDir)
	//_, err = os.Stat(path)
	//if os.IsNotExist(err) {
	//	if err = os.MkdirAll(path, os.ModePerm); err != nil {
	//		fmt.Println("create multipart dir failed")
	//		return "", err
	//	}
	//}

	chunkerAddr := m.getRandomChunkerNode(ctx, bucket)
	if chunkerAddr == "" {
		return "", fmt.Errorf("chunker node not found ")
	}

	uploadID = minio.MustGetUUID()

	//body := &bytes.Buffer{}
	//writer := multipart.NewWriter(body)
	//writer.WriteField("bucket", bucket)
	//writer.WriteField("object", object)
	//writer.WriteField("uploadID", uploadID)
	//writer.WriteField("content-type", opts.UserDefined["content-type"])
	//writer.WriteField("storageClass", opts.UserDefined[xhttp.AmzStorageClass])

	param := map[string]string{
		"bucket":       bucket,
		"object":       object,
		"uploadID":     uploadID,
		"content-type": opts.UserDefined["content-type"],
		"storageClass": opts.UserDefined[xhttp.AmzStorageClass],
	}

	csUrl := fmt.Sprintf("http://%s/cs/v1/newMultipart", chunkerAddr)
	resp, err := doRequest(ctx, http.MethodPost, csUrl, param, nil)
	if err != nil {
		return "", err
	}

	if resp == nil {

	}

	instance := MultiPart{
		UploadID:   uploadID,
		Bucket:     bucket,
		Object:     object,
		Chunker:    chunkerAddr,
		TotalSize:  0,
		Count:      0,
		CreateTime: time.Time{},
	}

	err = SetMultiPart(instance)
	if err != nil {
		logger.Error(err.Error())
		return "", err
	}

	//if err = os.Mkdir(fmt.Sprintf("%s/%s", path, uploadID), os.ModePerm); err != nil {
	//	return "", err
	//}
	return uploadID, nil
}

// PutObjectPart 上传分片
func (m *mtStorageObject) PutObjectPart(ctx context.Context, bucket, object, uploadID string, partID int, data *minio.PutObjReader, opts minio.ObjectOptions) (info minio.PartInfo, err error) {

	ctx, span := trace.StartSpan(ctx, "PutObjectPart")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	//if err := checkPutObjectPartArgs(ctx, bucket, object, fs); err != nil {
	//	return pi, toObjectErr(err, bucket)
	//}
	object = checkObject(object)
	// Validate input data size and it can never be less than -1.
	if data.Size() < -1 {
		return info, errors.New("invalid argument")
	}

	//get multipart info from cache
	var mp MultiPart
	err = GetMultiPart(uploadID, &mp)
	if err != nil {
		logger.Error(err.Error())
		return info, err
	}
	dataBytes, err := ioutil.ReadAll(data)
	encMd5Sum := fmt.Sprintf("%x", md5.Sum(dataBytes))
	rawMD5sum := data.MD5CurrentHexString()
	csUrl := fmt.Sprintf("http://%s/cs/v1/putObjectPart", mp.Chunker)
	param := map[string]string{
		"bucket":    bucket,
		"object":    object,
		"uploadID":  uploadID,
		"partID":    fmt.Sprintf("%d", partID),
		"encMd5Sum": encMd5Sum,
		"rawMD5sum": rawMD5sum,
	}

	//reqInfo := logger.GetReqInfo(ctx)
	headers := map[string]string{
		"Content-Length": fmt.Sprintf("%d", data.Size()),
		"crypto-key":     opts.UserDefined["crypto-key"],
	}

	resp, err := doRequestWithHeader(ctx, http.MethodPost, csUrl, param, headers, bytes.NewReader(dataBytes))
	if err != nil || resp == nil {
		return
	}

	if string(resp) != encMd5Sum {
		fmt.Println(string(resp))
		fmt.Println(encMd5Sum)
		//err = errors.New("MD5不一致")
		//return
	}
	info.PartNumber = partID
	info.ETag = data.MD5CurrentHexString()
	info.LastModified = minio.UTCNow()
	info.Size = data.Size()

	return
}

func (m *mtStorageObject) CompleteMultipartUpload(ctx context.Context, bucket, object, uploadID string, uploadedParts []minio.CompletePart, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {

	ctx, span := trace.StartSpan(ctx, "CompleteMultipartUpload")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	//if err := checkCompleteMultipartArgs(ctx, bucket, object, fs); err != nil {
	//	return objInfo, err
	//}
	//
	//// Check if an object is present as one of the parent dir.
	//if fs.parentDirIsObject(ctx, bucket, pathutil.Dir(object)) {
	//	return oi, toObjectErr(errFileParentIsFile, bucket, object)
	//}
	object = checkObject(object)
	// ensure that part ETag is canonicalized to strip off extraneous quotes
	for i := range uploadedParts {
		uploadedParts[i].ETag = minio.CanonicalizeETag(uploadedParts[i].ETag)
	}

	s3MD5 := minio.ComputeCompleteMultipartMD5(uploadedParts)
	//get multipart info from cache
	var mp MultiPart
	err = GetMultiPart(uploadID, &mp)
	if err != nil {
		logger.Error(err.Error())
		return objInfo, err
	}

	csUrl := fmt.Sprintf("http://%s/cs/v1/completeMultipart", mp.Chunker)
	param := map[string]interface{}{
		"bucket":       bucket,
		"object":       object,
		"md5":          s3MD5,
		"uploadID":     uploadID,
		"parts":        uploadedParts,
		"storageClass": opts.UserDefined[xhttp.AmzStorageClass],
		"cryptoKey":    opts.UserDefined["crypto-key"],
		"acl":          opts.UserDefined[xhttp.AmzACL],
	}
	jsonbytes, err := json.Marshal(param)

	resp, err := doRequest(ctx, http.MethodPost, csUrl, nil, bytes.NewReader(jsonbytes))
	if err != nil {
	}
	if resp == nil {

	}

	return m.GetObjectInfo(ctx, bucket, object, opts)

}

// GetMultipartInfo - 获取分片信息
func (m *mtStorageObject) GetMultipartInfo(ctx context.Context, bucket, object, uploadID string, opts minio.ObjectOptions) (info minio.MultipartInfo, err error) {

	ctx, span := trace.StartSpan(ctx, "GetMultipartInfo")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()
	////path := fmt.Sprintf("%s/%s/%s", m.multipartDir, multipartDir, uploadID)
	////_, err = os.Stat(path)
	//if os.IsNotExist(err) {
	//	return minio.MultipartInfo{}, err
	//}
	info.Bucket = bucket
	info.Object = object
	info.UploadID = uploadID
	info.UserDefined = opts.UserDefined
	return
}

// ListObjectParts - List object parts
func (m *mtStorageObject) ListObjectParts(ctx context.Context, bucket, object, uploadID string, partNumberMarker int, maxParts int, opts minio.ObjectOptions) (result minio.ListPartsInfo, err error) {

	ctx, span := trace.StartSpan(ctx, "ListObjectParts")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()
	// https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListParts.html
	/*
		path:=fmt.Sprintf("%s/%s",m.multipartDir,multipartDir)

		dirs,err:=ioutil.ReadDir(path)
		if err!=nil{
			return minio.ListPartsInfo{}, err
		}

		for _,ele:=range dirs{
			if ele.IsDir()&&ele.Name()==uploadID{
				return minio.ListPartsInfo{
					Bucket:               bucket,
					Object:               object,
					UploadID:             uploadID,
					StorageClass:         "",
					PartNumberMarker:     0,
					NextPartNumberMarker: 0,
					MaxParts:             0,
					IsTruncated:          false,
					Parts:                nil,
					UserDefined:          nil,
				}, err
			}
		}
	*/
	// seed chunker
	var mp MultiPart
	err = GetMultiPart(uploadID, &mp)
	if err != nil {
		logger.Error(err.Error())
		return
	}
	url := fmt.Sprintf("http://%s/cs/v1/listObjectParts",
		mp.Chunker)
	args := map[string]string{
		"bucket":   bucket,
		"object":   object,
		"uploadID": uploadID,
	}
	partResult, err := doRequest(ctx, http.MethodGet, url, args, nil)
	if err != nil {
		logger.Error(err.Error())
		return
	}
	var parts []minio.PartInfo
	err = json.Unmarshal(partResult, &parts)
	if err != nil {
		return minio.ListPartsInfo{}, err
	}
	// 计算返回的parts的长度
	partsLen := len(parts)
	if maxParts == 0 { // 最大返回长度，如果不传全部返回。
		maxParts = partsLen
	}
	// parts数组排序
	func() {
		sort.Slice(parts, func(i, j int) bool { // ase
			return parts[i].PartNumber < parts[j].PartNumber
		})
	}()

	for _, v := range parts {
		if partNumberMarker < v.PartNumber { // partNumberMarker 起始值
			result.Parts = append(result.Parts, v)
		}
		result.NextPartNumberMarker = v.PartNumber // 当前最大的编号
		if len(result.Parts) >= maxParts {
			break
		}
	}
	result.PartNumberMarker = partNumberMarker //
	result.Object = object
	result.Bucket = bucket
	result.UploadID = uploadID
	if partsLen != len(result.Parts) {
		result.IsTruncated = true // 是否有截断，没有全部返回就是为true
	}
	result.MaxParts = maxParts // 返回了多少切片
	result.StorageClass = opts.UserDefined[xhttp.AmzStorageClass]
	return
}

func (m *mtStorageObject) AbortMultipartUpload(ctx context.Context, bucket, object, uploadID string, opts minio.ObjectOptions) (err error) {

	ctx, span := trace.StartSpan(ctx, "AbortMultipartUpload")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	//path := fmt.Sprintf("%s/%s/%s", m.multipartDir, multipartDir, uploadID)
	//_, err := os.Stat(path)
	//if os.IsNotExist(err) {
	//	return nil
	//}
	var mp MultiPart
	err = GetMultiPart(uploadID, &mp)
	if err != nil {
		logger.Error(err.Error())
		return err
	}
	csUrl := fmt.Sprintf("http://%s/cs/v1/abortMultipartUpload", mp.Chunker)
	param := map[string]interface{}{
		"bucket":   bucket,
		"object":   object,
		"uploadID": uploadID,
	}
	jsonBytes, err := json.Marshal(param)
	resp, err := doRequest(ctx, http.MethodPost, csUrl, nil, bytes.NewReader(jsonBytes))
	if err != nil {
	}
	if resp == nil {

	}
	return err
}

func requestMultipart(client *http.Client, uploadURL, targetPath, bucket, object, uuid string, part, totalParts int, fileSize, avg int64) bool {
	logger.Info("==> requestMultipart %d, totalpart: %d", part, totalParts)
	fmt.Println(object)
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("bucket", bucket)
	_ = writer.WriteField("chunktotal", fmt.Sprintf("%d", totalParts))
	_ = writer.WriteField("uuid", uuid)
	_ = writer.WriteField("filesize", fmt.Sprintf("%v", fileSize))
	_ = writer.WriteField("chunkindex", fmt.Sprintf("%d", part))
	_ = writer.WriteField("filename", object)
	_ = writer.WriteField("avg", fmt.Sprintf("%v", avg))
	multiPart, e := writer.CreateFormFile("object", path.Base(object))
	if e != nil {
		logger.Error("requestMultipart error:", e)
		return false
	}
	needUploadFilePath := path.Join(targetPath, fmt.Sprintf("%d", part))
	source, err := os.Open(needUploadFilePath)
	if err != nil {
		logger.Error("can not open file:%d, error: ", part, err)
		return false
	}
	defer source.Close()
	_, _ = io.Copy(multiPart, source)
	if err = writer.Close(); err != nil {
		logger.Error("requestMultipart writer closed failed:", err)
		return false
	}
	request, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/cs/v1/multipart", uploadURL), body)
	if err != nil {
		logger.Error("requestMultipart newRequest failed:", err)
		return false
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := client.Do(request)
	if err != nil {
		logger.Error("%v", err)
		return false
	}
	bts, _ := ioutil.ReadAll(resp.Body)
	logger.Info("request multi part: %d, resp: %s", part, string(bts))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logger.Error("nameServer return http code %d,err:%v\n", resp.StatusCode, string(bts))
		return false
	}
	result := make(map[string]string)
	err = json.Unmarshal(bts, &result)
	if err != nil {
		return false
	}

	logger.Info("requestMultipart upload success")

	if result["complete"] == "true" {
		return true
	} else {
		return false
	}
}

func (m *mtStorageObject) IsNotificationSupported() bool {

	return false
}

func (m *mtStorageObject) IsListenSupported() bool {

	return false
}

func (m *mtStorageObject) IsCommonEncryptionSupported() bool {
	return false
}

func (m *mtStorageObject) IsEncryptionSupported() bool {

	return true
}

func (m *mtStorageObject) IsTaggingSupported() bool {

	return true
}

func (m *mtStorageObject) IsCompressionSupported() bool {

	return false
}

func (m *mtStorageObject) HealFormat(ctx context.Context, dryRun bool) (madmin.HealResultItem, error) {

	return madmin.HealResultItem{}, nil
}

func (m *mtStorageObject) HealBucket(ctx context.Context, bucket string, opts madmin.HealOpts) (madmin.HealResultItem, error) {

	return madmin.HealResultItem{}, nil
}

func (m *mtStorageObject) HealObject(ctx context.Context, bucket, object, versionID string, opts madmin.HealOpts) (madmin.HealResultItem, error) {

	return madmin.HealResultItem{}, nil
}

func (m *mtStorageObject) HealObjects(ctx context.Context, bucket, prefix string, opts madmin.HealOpts, fn minio.HealObjectFn) error {

	return nil
}

func (m *mtStorageObject) GetMetrics(ctx context.Context) (*minio.BackendMetrics, error) {

	return nil, nil
}

func (m *mtStorageObject) Health(ctx context.Context, opts minio.HealthOptions) minio.HealthResult {

	return minio.HealthResult{}
}

func (m *mtStorageObject) ReadHealth(ctx context.Context) bool {

	return false
}

func (m *mtStorageObject) PutObjectMetadata(ctx context.Context, bucket string, object string, options minio.ObjectOptions) (minio.ObjectInfo, error) {

	//urlPath:=fmt.Sprintf("%s/object/metadata?bucket=%s&object=%s",m.address,bucket,object)
	return minio.ObjectInfo{}, nil
}

func (m *mtStorageObject) Shutdown(ctx context.Context) error {

	return nil
}

// finished
//
//xxx:8000/ns/v1/bucket [post]
func (m *mtStorageObject) MakeBucketWithLocation(ctx context.Context, bucket string, opts minio.BucketOptions) error {
	//span
	ctx, span := trace.StartSpan(ctx, "MakeBucketWithLocation")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	if s3utils.CheckValidBucketName(bucket) != nil {
		return minio.BucketNameInvalid{Bucket: bucket}
	}
	userID, ok := minio.JudgeUserID(ctx)
	if !ok {
		return fmt.Errorf("UserId not found!!")
	}
	nsurl := fmt.Sprintf("%s/bucket", m.address)
	bd := map[string]interface{}{
		"bucket":       bucket,
		"location":     opts.Location,
		"user_id":      userID,
		"storageclass": opts.StorageClass,
		"acl":          opts.Acl,
	}
	body, _ := json.Marshal(bd)
	rs, err := doRequest(ctx, http.MethodPost, nsurl, nil, bytes.NewReader(body))
	if err != nil {
		logger.Error("response: %s", rs)
		return err
	}
	return nil
}

// finished
//
//xxx:8000/ns/v1/bucket?name=xxx [get]
func (m *mtStorageObject) GetBucketInfo(ctx context.Context, bucket string) (bucketInfo minio.BucketInfo, err error) {

	ctx, span := trace.StartSpan(ctx, "GetBucketInfo")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	userID, ok := minio.JudgeUserID(ctx)
	if !ok {
		return bucketInfo, fmt.Errorf("UserId not found!!")
	}
	nsurl := fmt.Sprintf("%s/bucket?userid=%d&bucket=%s", m.address, userID, bucket)
	bs, err := doRequest(ctx, http.MethodGet, nsurl, nil, nil)
	if err != nil {
		if _, ok := err.(minio.NotFound); ok {
			return minio.BucketInfo{}, minio.BucketNotFound{Bucket: bucket}
		}
		logger.Error("response: %s", bs)
		return bucketInfo, err
	}

	retM := make([]map[string]interface{}, 0)
	if err = json.Unmarshal(bs, &retM); err != nil {
		return bucketInfo, err
	}
	if len(retM) == 0 {
		return minio.BucketInfo{}, minio.BucketNotFound{Bucket: bucket}
	}
	actualTime, _ := time.ParseInLocation(TimeFormat, retM[0]["CreateTime"].(string), time.Local)
	bucketInfo.Name = retM[0]["Name"].(string)
	bucketInfo.Location = retM[0]["Location"].(string)
	bucketInfo.StorageClass = retM[0]["StorageClass"].(string)
	bucketInfo.Created = actualTime
	return
}

func (m *mtStorageObject) GetBucketInfoDetail(ctx context.Context, bucket string) (bucketDetails minio.BucketInfoDetail, err error) {

	ctx, span := trace.StartSpan(ctx, "GetBucketInfoDetail")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()
	nsurl := fmt.Sprintf("%s/bucketinfo?bucket=%s", m.address, bucket)
	data, err := doRequest(ctx, http.MethodGet, nsurl, nil, nil)
	if err != nil {
		if _, ok := err.(minio.NotFound); ok {
			return minio.BucketInfoDetail{}, minio.BucketNotFound{Bucket: bucket}
		}
		logger.Error("response: %s", data)
		return minio.BucketInfoDetail{}, err
	}

	bucketinfo := make(map[string]interface{})
	if err = json.Unmarshal(data, &bucketinfo); err != nil {
		return minio.BucketInfoDetail{}, err
	}

	bucketInfo := &bucketDetails.Bucket

	bucketInfo.Name = bucketinfo["Name"].(string)
	bucketInfo.Size = uint64(bucketinfo["Size"].(float64))
	bucketInfo.Created, _ = time.ParseInLocation(TimeFormat, bucketinfo["CreateTime"].(string), time.Local)
	bucketInfo.Owner.Id = int(bucketinfo["Owner"].(float64))
	//todo
	//bucketInfo.Owner.Name = db.GetAccountByUid(bucketInfo.Owner.Id).Username
	//bucketInfo.Owner.Password = db.GetAccountByUid(bucketInfo.Owner.Id).Password

	acl, aclErr := m.GetBucketACL(ctx, bucket)
	if aclErr != nil {
		// return error info if get acl failed
		//acl = err.Error()
		//return minio.BucketInfoDetail{}, err
		if _, ok := aclErr.(minio.BucketACLNotFound); !ok {
			logger.Error("%v", aclErr)
			return
		}
		acl = ""
	}
	bucketInfo.Acl = minio.BucketACL{Grant: acl}
	bucketInfo.Location = bucketinfo["Location"].(string)
	bucketInfo.StorageClass = bucketinfo["StorageClass"].(string)
	return
}

// SpanContextToRequest modifies the given request to include a Stackdriver Trace header.
func SpanContextToRequest(sc trace.SpanContext, req *http.Request) {
	httpHeader := `X-Cloud-Trace-Context`
	sid := binary.BigEndian.Uint64(sc.SpanID[:])
	header := fmt.Sprintf("%s/%d;o=%d", hex.EncodeToString(sc.TraceID[:]), sid, int64(sc.TraceOptions))
	req.Header.Set(httpHeader, header)
}

func (m *mtStorageObject) ListBucketSize(ctx context.Context) (map[string]minio.BucketObjectSizeAndCount, error) {

	mp := make(map[string]minio.BucketObjectSizeAndCount)
	ctx, span := trace.StartSpan(ctx, "gateway ListBucketSizeHandler")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	userID, ok := minio.JudgeUserID(ctx)
	if !ok {
		return nil, fmt.Errorf("UserId not found!!")
	}

	nsurl := fmt.Sprintf("%s/bucket?userid=%d", m.address, userID)
	bs, err := doRequest(ctx, http.MethodGet, nsurl, nil, nil)
	if err != nil {
		logger.Error("response: %s", bs)
		return nil, err
	}
	retM := make([]map[string]interface{}, 0)
	if err = json.Unmarshal(bs, &retM); err != nil {
		return nil, err
	}
	for i := 0; i < len(retM); i++ {
		mp[retM[i]["Name"].(string)] = minio.BucketObjectSizeAndCount{
			Size:         uint64(retM[i]["Size"].(float64)),
			ObjectsCount: uint64(retM[i]["Count"].(float64)),
		}
	}

	return mp, nil
}

// location and storageclass added for maitian
//
//xxx:8000/ns/v1/bucket [get]
func (m *mtStorageObject) ListBuckets(ctx context.Context) (buckets []minio.BucketInfo, err error) {
	ctx, span := trace.StartSpan(ctx, "gateway ListBucketHandler")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	userID, ok := minio.JudgeUserID(ctx)
	if !ok {
		return nil, fmt.Errorf("UserId not found!!")
	}

	nsurl := fmt.Sprintf("%s/bucket?userid=%d", m.address, userID)
	bs, err := doRequest(ctx, http.MethodGet, nsurl, nil, nil)
	if err != nil {
		logger.Error("response: %s", bs)
		return nil, err
	}
	retM := make([]map[string]interface{}, 0)
	if err = json.Unmarshal(bs, &retM); err != nil {
		return nil, err
	}

	for i := 0; i < len(retM); i++ {
		actualTime, _ := time.ParseInLocation(TimeFormat, retM[i]["CreateTime"].(string), time.Local)
		buckets = append(buckets, minio.BucketInfo{
			Name:         retM[i]["Name"].(string),
			Location:     retM[i]["Location"].(string),
			StorageClass: retM[i]["StorageClass"].(string),
			Created:      actualTime,
		})
	}
	// sort by time, fix bug
	sort.SliceStable(buckets, func(i, j int) bool {
		return buckets[i].Created.After(buckets[j].Created)
	})
	return
}

// finished
//
//xxx:8000/ns/v1/bucket/xxx [delete]
func (m *mtStorageObject) DeleteBucket(ctx context.Context, bucket string, forceDelete bool) error {

	ctx, span := trace.StartSpan(ctx, "DeleteBucket")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	if s3utils.CheckValidBucketName(bucket) != nil {
		return minio.BucketNameInvalid{Bucket: bucket}
	}
	userID, ok := minio.JudgeUserID(ctx)
	if !ok {
		return fmt.Errorf("UserId not found!!")
	}
	nsurl := fmt.Sprintf("%s/bucket/%s?userid=%d", m.address, bucket, userID)
	rs, err := doRequest(ctx, http.MethodDelete, nsurl, nil, nil)
	if err != nil {
		logger.Error("response: %s", rs)
		return err
	}
	return nil
}

// put bucket verioning
func (m *mtStorageObject) PutBucketVersioning(ctx context.Context, bucket string, config []byte) error {

	ctx, span := trace.StartSpan(ctx, "PutBucketVersioning")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	var v *versioning.Versioning
	err := xml.Unmarshal(config, &v)
	if err != nil {
		return err
	}

	nsurl := fmt.Sprintf("%s/versioning?bucket=%s&status=%s", m.address, bucket, v.Status)
	rs, err := doRequest(ctx, http.MethodPut, nsurl, nil, nil)
	if err != nil {
		logger.Error("response: %s", rs)
		return err
	}
	return nil
}

// get bucket versioning
func (m *mtStorageObject) GetBucketVersioning(ctx context.Context, bucket string) (*versioning.Versioning, error) {

	ctx, span := trace.StartSpan(ctx, "GetBucketVersioning")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	nsurl := fmt.Sprintf("%s/versioning?bucket=%s", m.address, bucket)

	var v versioning.Versioning
	status, err := doRequest(ctx, http.MethodGet, nsurl, nil, nil)
	if err != nil {
		logger.Error("response: %s", status)
		return &v, err
	}

	v.XMLNS = "http://s3.amazonaws.com/doc/2006-03-01/"
	v.Status = versioning.State(status)

	return &v, nil
}

//xxx:8000/ns/v1/object?bucket=xxx&prefix=xxx [get]
func (m *mtStorageObject) ListObjects(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int, fetchDelete bool) (result minio.ListObjectsInfo, err error) {

	ctx, span := trace.StartSpan(ctx, "ListObjects")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	prefix = strings.TrimSuffix(prefix, "/")
	oss := strings.Split(prefix, "//")
	length := len(oss)
	if length > 1 {
		prefix = oss[length-1]
	} else {
		prefix = oss[0]
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = fmt.Sprintf("/%s", prefix)
	}
	//prefix=strings.Replace(prefix,"//","/",-1)
	reqUrl := fmt.Sprintf("%s/object/list", m.address)

	if marker == "" {
		marker = "0"
	}
	offset, err := strconv.Atoi(marker)
	if err != nil {
		return minio.ListObjectsInfo{}, minio.InvalidArgument{}
	}
	param := map[string]string{
		"bucket":    bucket,
		"prefix":    prefix,
		"marker":    marker,
		"delimiter": delimiter,
		"max-keys":  fmt.Sprintf("%d", maxKeys),
	}
	if fetchDelete {
		param["fetch-delete"] = "true"
	}
	objects, err := doRequest(ctx, http.MethodGet, reqUrl, param, nil)
	if err != nil {
		return minio.ListObjectsInfo{}, err
	}
	retM, err := simplejson.NewJson(objects)
	if err != nil {
		logger.Error(err)
		return minio.ListObjectsInfo{}, err
	}
	cnt := retM.Get("Total").MustInt()
	res := retM.Get("Res").MustArray()
	objs := make([]minio.ObjectInfo, 0)
	prfixes := make([]string, 0)
	var nextMarker string
	for _, e := range res {
		ele := e.(map[string]interface{})
		modTime, _ := time.ParseInLocation(TimeFormat, ele["UpdatedAt"].(string), time.Local)
		etag := ""
		if ele["etag"] != nil {
			etag = ele["etag"].(string)
		}
		dirname := ele["dirname"].(string)
		if dirname == "/" {
			dirname = ""
		}
		dirname = strings.TrimPrefix(dirname, "/")

		name := ele["name"].(string)
		//nextMarker = name
		isDir := ele["isdir"].(bool)
		if isDir {
			prfixes = append(prfixes, fmt.Sprintf("%s/%s/", dirname, name))
			continue
		}
		cid := ele["cid"].(string)
		// if cid[:2] != "Qm" {
		// 	detail, _ := m.GetBucketInfoDetail(ctx, bucket)
		// 	fmt.Println("dag密码====>:", detail.Bucket.Owner.Password)
		// 	_, key := crypto.PasswdToKey(detail.Bucket.Owner.Password)
		// 	decrypt, _ := crypto.Base64Decrypt(key, cid)
		// 	cid = decrypt
		// }
		sz, _ := ele["content_length"].(json.Number).Int64()
		objs = append(objs, minio.ObjectInfo{
			Bucket:       bucket,
			Name:         fmt.Sprintf("%s/%s", dirname, name),
			ModTime:      modTime,
			Cid:          cid,
			Size:         sz,
			IsDir:        ele["isdir"].(bool),
			ETag:         etag,
			ContentType:  ele["content_type"].(string),
			VersionID:    ele["version"].(string),
			StorageClass: ele["storageclass"].(string),

			UserDefined: map[string]string{
				"bucket":       bucket,
				"name":         name,
				"mod-time":     modTime.Format(TimeFormat),
				"content-type": ele["content_type"].(string),
				"version-id":   ele["version"].(string),
				"etag":         etag,
				"size":         fmt.Sprintf("%d", sz),
				"cid":          ele["cid"].(string),
			},
		})
	}

	nextOffset := offset + len(objs) + len(prfixes)

	if cnt != nextOffset {
		nextMarker = fmt.Sprintf("%v", nextOffset)
	}

	return minio.ListObjectsInfo{
		NextMarker: nextMarker,
		Objects:    objs,
		Prefixes:   prfixes,
	}, nil

}

func requestGetObjectData(ctx context.Context, w io.Writer, chunkerAddr, cid, storageClass, ck string, offset, length int64) error {

	ctx, span := trace.StartSpan(ctx, "requestGetObjectData")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()
	chunkerUrl := fmt.Sprintf("http://%s/cs/v1/object/%s?offset=%d&length=%d&storageclass=%s&crypto-key=%s&cid=%s", chunkerAddr, cid, offset, length, storageClass, ck, cid)
	logger.Info("dorequest :", chunkerUrl)
	request, _ := http.NewRequest(http.MethodGet, chunkerUrl, nil)
	tracing.SpanContextToRequest(span, request)
	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Chunkerserver return code:%d", resp.StatusCode)
	}
	defer resp.Body.Close()
	_, err = io.Copy(w, resp.Body)

	return nil
}
func (m *mtStorageObject) getObject(ctx context.Context, bucket, cid, storageClass string, startOffset, length int64, writer io.Writer, etag string, opts minio.ObjectOptions) error {

	ctx, span := trace.StartSpan(ctx, "getObject")
	//host, _ := ctx.Value("Host").(string)
	//span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()
	chunkerAddr := m.getRandomChunkerNode(ctx, bucket)
	if chunkerAddr == "" {
		return fmt.Errorf("Not found available chunker node")
	}
	chunkerAddr = strings.Trim(chunkerAddr, "\"")
	ck := opts.UserDefined["crypto-key"]
	// 避免出现ck为空，但是cid加密的情况
	if ck == "" && cid != "" && cid[:2] != "Qm" {
		bucketInfo, err := m.GetBucketInfoDetail(ctx, bucket)
		if err != nil {
			logger.Error("获取ck失败", err)
			return err
		}
		_, stringKey := crypto.PasswdToKey(bucketInfo.Bucket.Owner.Password)
		ck = stringKey
	}
	return requestGetObjectData(ctx, writer, chunkerAddr, cid, storageClass, ck, startOffset, length)
}

func (m *mtStorageObject) GetObjectNInfo(ctx context.Context, bucket, object string, rs *minio.HTTPRangeSpec, h http.Header, lockType minio.LockType, opts minio.ObjectOptions) (reader *minio.GetObjectReader, err error) {

	ctx, span := trace.StartSpan(ctx, "GetObjectNInfo")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()
	//  todo 测试环境和本地环境效果不同
	objInfo, err := m.GetObjectInfo(ctx, bucket, object, opts)
	if err != nil || objInfo.IsDir {
		// 是文件夹的情况下，返回object不存在
		if err == nil {
			errMsg := mtstorageError{
				Code:        "NoSuchKey",
				Description: "Object not exist.",
			}
			err = toObjectError(errMsg)
		}
		return nil, err
	}

	cid := objInfo.UserDefined["cid"]

	var startOffset, length int64
	startOffset, length, err = rs.GetOffsetLength(objInfo.Size)
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()

	go func() {
		err1 := m.getObject(ctx, bucket, cid, objInfo.StorageClass, startOffset, length, pw, objInfo.ETag, opts)
		pw.CloseWithError(err1)
	}()

	pipeCloser := func() { pr.Close() }
	return minio.NewGetObjectReaderFromReader(pr, objInfo, opts, pipeCloser)
}

func (m *mtStorageObject) GetRecurrenceObjectsInfo(ctx context.Context, bucket, object string) ([]minio.ObjectInfo, error) {

	return nil, nil
}

//xxx:8000/ns/v1/object?bucket=xxx&object=xxx [get]
func (m *mtStorageObject) GetObjectInfo(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {

	ctx, span := trace.StartSpan(ctx, "GetObjectNInfo")
	defer span.End()

	object = strings.TrimSuffix(object, "/")

	if !strings.HasPrefix(object, "/") {
		object = fmt.Sprintf("/%s", object)
	}
	object = strings.Replace(object, "//", "/", -1)
	//url := fmt.Sprintf("%s/object?bucket=%s&&object=%s", m.address, bucket, object)
	url := fmt.Sprintf("%s/object", m.address)
	param := map[string]string{
		"bucket":    bucket,
		"object":    object,
		"versionId": opts.VersionID,
	}

	bts, err := doRequest(ctx, http.MethodGet, url, param, nil)
	if err != nil {
		logger.Error("response: %s", bts)
		return minio.ObjectInfo{}, err
	}
	retM := make(map[string]interface{})
	err = json.Unmarshal(bts, &retM)
	if err != nil {
		return minio.ObjectInfo{}, err
	}
	modTime, err := time.ParseInLocation(TimeFormat, retM["UpdatedAt"].(string), time.Local)
	if err != nil {
		fmt.Println(err.Error())
	}
	var cid string
	if v, ok := retM["cid"].(string); ok {
		cid = v
	}
	retObj := minio.ObjectInfo{
		Bucket:       bucket,
		Name:         object,
		ModTime:      modTime,
		IsDir:        retM["isdir"].(bool),
		ETag:         retM["etag"].(string),
		ContentType:  retM["content_type"].(string),
		VersionID:    retM["version"].(string),
		DeleteMarker: retM["ismarker"].(bool),
		StorageClass: retM["storageclass"].(string),
		UserDefined:  map[string]string{"cid": cid, xhttp.AmzStorageClass: retM["storageclass"].(string)},
	}
	if _, ok := retM["cid"]; ok {
		detail, _ := m.GetBucketInfoDetail(ctx, bucket)
		_, key := crypto.PasswdToKey(detail.Bucket.Owner.Password)
		decrypt, _ := crypto.Base64Decrypt(key, cid)
		retObj.Cid = decrypt
		fmt.Println("cid=====>:", retObj.Cid)

		// 是否加密
		if decrypt != "" {
			retM["content_length"] = retM["ciphertext_size"]
			retObj.UserDefined[crypto.MetaSealedKeyS3] = ""
		}
	}
	if _, ok := retM["content_length"]; ok {
		retObj.Size = int64(retM["content_length"].(float64))
	}
	return retObj, nil
}

func (m *mtStorageObject) getRandomChunkerNode(ctx context.Context, bucket string) string {
	//span
	ctx, span := trace.StartSpan(ctx, "getRandomChunkerNode")
	defer span.End()

	url := fmt.Sprintf("%s/chunker/address?bucket=%s", m.address, bucket)
	rs, err := doRequest(ctx, http.MethodGet, url, nil, nil)
	if err != nil {
		logger.Error("response: %s", rs)
		return ""
	}
	result := make(map[string]interface{})
	if err := json.Unmarshal(rs, &result); err != nil {
		return ""
	}
	return result["url"].(string)
	//return string(rs)
}

func (m *mtStorageObject) checkObjectExist(bucket, object string) bool {

	url := fmt.Sprintf("%s/object/check?bucket=%s&object=%s", m.address, bucket, object)
	request, _ := http.NewRequest(http.MethodGet, url, nil)
	resp, e := client.Do(request)
	if e != nil {
		defer resp.Body.Close()
		return false
	}

	if resp.StatusCode != http.StatusOK {
		return false
	}
	return true
}

func (m *mtStorageObject) PutObject(ctx context.Context, bucket, object string, data *minio.PutObjReader, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	//span trace
	ctx, span := trace.StartSpan(ctx, "PutObject")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()

	//check object prefix
	object = checkObject(object)
	if !strings.HasPrefix(object, "/") {
		object = fmt.Sprintf("/%s", object)
	}

	//get chunker node
	addr := m.getRandomChunkerNode(ctx, bucket)
	if addr == "" {
		return minio.ObjectInfo{}, fmt.Errorf("available chunker node not found")
	}
	addr = strings.Trim(addr, "\"")

	csUrl := fmt.Sprintf("http://%s/cs/v1/postObject", addr)
	param := map[string]string{
		"bucket": bucket,
		"object": object,
		//	"encMd5Sum":    encMd5Sum,
		"storageClass": opts.UserDefined[xhttp.AmzStorageClass],
		"acl":          opts.UserDefined[xhttp.AmzACL],
	}
	// 保持文件类型
	contentType := "multipart/form-data"
	if value, ok := opts.UserDefined["content-type"]; ok && value != "" {
		contentType = value
	}
	headers := map[string]string{
		// 不传Content-Length  data.Size()包含表单参数，传到Chunker和文件大小不一致
		//"Content-Length": fmt.Sprintf("%d", data.Size()),
		"Content-Type": contentType,
		"crypto-key":   opts.UserDefined["crypto-key"],
	}
	resp, err := doRequestWithHeader(ctx, http.MethodPost, csUrl, param, headers, data)
	//resp, err := doRequestWithHeader(ctx, http.MethodPost, csUrl, param, headers, bytes.NewReader(dataBytes))
	if err != nil || resp == nil {
		return minio.ObjectInfo{}, err
	}
	retM := make(map[string]interface{})
	err = json.Unmarshal(resp, &retM)
	if err != nil {
		return minio.ObjectInfo{}, err
	}

	return minio.ObjectInfo{
		Bucket: retM["bucket"].(string),
		Name:   retM["object"].(string),
		Size:   int64(retM["size"].(float64)),
		ETag:   retM["etag"].(string),
		// ETag:         md5SumReader,
		UserDefined:  opts.UserDefined,
		StorageClass: retM["storageclass"].(string),
	}, nil
}

// PostObject 弃用
func (m *mtStorageObject) PostObject(ctx context.Context, bucket, object string, data *minio.PutObjReader, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	return m.PutObject(ctx, bucket, object, data, opts)
}

func (m *mtStorageObject) DeleteObject(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (minio.ObjectInfo, error) {

	objInfo, err := m.GetObjectInfo(ctx, bucket, object, opts)
	if err != nil {
		return minio.ObjectInfo{}, err
	}

	nameServerURL := fmt.Sprintf("%s/object/delete", m.address)
	param := map[string]string{
		"bucket":    bucket,
		"object":    objInfo.Name,
		"versionId": opts.VersionID,
	}
	if opts.FetchDelete {
		param["fetch-delete"] = "true"
	}
	rs, err := doRequest(ctx, http.MethodDelete, nameServerURL, param, nil)
	if err != nil {
		logger.Error("response: %s", rs)
		return minio.ObjectInfo{}, err
	}

	retM := make(map[string]int64)
	err = json.Unmarshal(rs, &retM)
	if err != nil {
		logger.Error("parse return err:%s", err.Error())
		return minio.ObjectInfo{}, err
	}
	return minio.ObjectInfo{
		Bucket: bucket,
		Name:   object,
		Size:   retM["Size"],
	}, nil
}

func (m *mtStorageObject) DeleteObjects(ctx context.Context, bucket string, objects []minio.ObjectToDelete, opts minio.ObjectOptions) ([]minio.DeletedObject, []error) {

	errs := make([]error, len(objects))
	dobjects := make([]minio.DeletedObject, len(objects))
	var dobj minio.ObjectInfo
	for idx, object := range objects {
		opts.VersionID = object.VersionID
		dobj, errs[idx] = m.DeleteObject(ctx, bucket, object.ObjectName, opts)
		if errs[idx] == nil {
			dobjects[idx] = minio.DeletedObject{
				ObjectName: object.ObjectName,
				Size:       dobj.Size,
			}
		}
	}
	return dobjects, errs
}

// IsBucketEncryption 判断桶是否开启加密策略
func (m *mtStorageObject) IsBucketEncryption(ctx context.Context, bucket string) (bool, error) {

	ctx, span := trace.StartSpan(ctx, "IsBucketEncryption")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()
	// 请求获取桶的加密信息
	nsurl := fmt.Sprintf("%s/getEncryption?bucket=%s", m.address, bucket)
	resp, err := doRequest(ctx, http.MethodGet, nsurl, nil, nil)
	if err != nil || len(resp) == 0 {
		return false, nil
	}
	var e bucketsse.EncryptionAction
	if err := json.Unmarshal(resp, &e); err != nil {
		logger.Error("加密信息序列化失败", err)
		return false, err
	}
	//
	if e.Algorithm == bucketsse.AES256 {
		return true, nil
	}
	return false, nil
}
func (m *mtStorageObject) GetBucketEncryption(ctx context.Context, bucket string) (sse *bucketsse.BucketSSEConfig, err error) {
	sse = &bucketsse.BucketSSEConfig{}
	ctx, span := trace.StartSpan(ctx, "GetBucketEncryption")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()
	nsurl := fmt.Sprintf("%s/getEncryption?bucket=%s", m.address, bucket)
	resp := make([]byte, 0)
	resp, err = doRequest(ctx, http.MethodGet, nsurl, nil, nil)
	if err != nil || len(resp) == 0 {
		return
	}
	var e bucketsse.EncryptionAction
	if err = json.Unmarshal(resp, &e); err != nil {
		logger.Error("加密信息序列化失败", err)
		return
	}

	if sse.Rules == nil {
		sse.Rules = make([]bucketsse.SSERule, 0)
	}
	sse.Rules = append(sse.Rules, bucketsse.SSERule{DefaultEncryptionAction: e})
	return
}
func (m *mtStorageObject) DeleteBucketEncryption(ctx context.Context, bucket string) error {
	ctx, span := trace.StartSpan(ctx, "DeleteBucketEncryption")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()
	nsurl := fmt.Sprintf("%s/putEncryption?bucket=%s", m.address, bucket)

	bd := bucketsse.EncryptionAction{}
	body, _ := json.Marshal(bd)
	_, err := doRequest(ctx, http.MethodPost, nsurl, nil, bytes.NewReader(body))
	if err != nil {
		return err
	}
	return nil
}
func (m *mtStorageObject) PutBucketEncryption(ctx context.Context, bucket string, encConfig bucketsse.BucketSSEConfig) error {
	ctx, span := trace.StartSpan(ctx, "DeleteBucketEncryption")
	host, _ := ctx.Value("Host").(string)
	span.AddAttributes(trace.StringAttribute("Host", host))
	defer span.End()
	nsurl := fmt.Sprintf("%s/putEncryption?bucket=%s", m.address, bucket)

	bd := encConfig.Rules[0].DefaultEncryptionAction
	body, _ := json.Marshal(bd)
	_, err := doRequest(ctx, http.MethodPost, nsurl, nil, bytes.NewReader(body))
	if err != nil {
		return err
	}
	return nil
}

func (m *mtStorageObject) SetDriveCounts() []int {
	return []int{}
}
