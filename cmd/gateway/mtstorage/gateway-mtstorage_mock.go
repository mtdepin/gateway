package mtstorage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"

	minio "github.com/minio/minio/cmd"
)

func (m *mtStorageObject) PutObjectV1(ctx context.Context, bucket, object string, data io.ReadCloser, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	objectExist := m.checkObjectExist(bucket, object)
	if objectExist {
		return minio.ObjectInfo{
			Bucket: bucket,
			Name:   object,
		}, nil
	}
	addr := m.getRandomChunkerNode(context.Background(), bucket)
	if addr == "" {
		return minio.ObjectInfo{}, fmt.Errorf("Not found available chunker node")
	}
	//addr "http://xxxx.xxx.xxx.xxx"
	//clean "
	addr = addr[1 : len(addr)-1]
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("object", object)
	if err != nil {
		return minio.ObjectInfo{}, err
	}
	/*
		var buf bytes.Buffer
		ret,e := wr.Write(io.TeeReader(data,&buf))
	*/
	_, err = io.Copy(part, data)
	if err != nil {
		fmt.Println(err)
		return minio.ObjectInfo{}, err
	}
	writer.WriteField("bucket", bucket)
	if err = writer.Close(); err != nil {
		return minio.ObjectInfo{}, err
	}
	request, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/cs/v1/object", addr), body)
	if err != nil {
		fmt.Println(err)
		return minio.ObjectInfo{}, err
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	client := http.Client{}
	resp, e := client.Do(request)
	if e != nil {
		return minio.ObjectInfo{}, e
	}
	defer resp.Body.Close()
	bts, _ := ioutil.ReadAll(resp.Body)
	retM := make(map[string]interface{})
	json.Unmarshal(bts, &retM)

	if resp.StatusCode != http.StatusOK {
		return minio.ObjectInfo{}, fmt.Errorf("nameServer return http code %d,err:%v", resp.StatusCode, retM["error"])
	}
	return minio.ObjectInfo{
		Bucket: retM["bucket"].(string),
		Name:   retM["object"].(string),
		Size:   int64(retM["size"].(float64)),
		ETag:   retM["cid"].(string),
	}, nil
}
