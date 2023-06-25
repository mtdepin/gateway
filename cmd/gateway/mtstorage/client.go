package mtstorage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/minio/minio/cmd"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/minio/maitian/tracing"
	"go.opencensus.io/trace"
)

func doRequest(ctx context.Context, method, url string, args map[string]string, body io.Reader) ([]byte, error) {
	ctx, span := trace.StartSpan(ctx, "doRequest")
	span.AddAttributes(trace.StringAttribute("url", url))
	span.AddAttributes(trace.StringAttribute("method", method))
	argsStr, _ := json.Marshal(args)
	span.AddAttributes(trace.StringAttribute("parameter", string(argsStr)))
	defer span.End()

	request, err := http.NewRequest(method, url, body)
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}
	tracing.SpanContextToRequest(span, request)

	param := request.URL.Query()

	for k, v := range args {
		param.Add(k, v)
	}

	request.URL.RawQuery = param.Encode()
	printReqLog(ctx, request, string(argsStr), body)
	client := http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Error("resolve result failed: ", err.Error())
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		errMsg := mtstorageError{}
		err := json.Unmarshal(result, &errMsg)
		if err != nil {
			return result, nil
		}

		return []byte{}, toObjectError(errMsg)
	}

	return result, nil
}

func doRequestWithHeader(ctx context.Context, method, url string, args map[string]string, headers map[string]string, body io.Reader) ([]byte, error) {
	ctx, span := trace.StartSpan(ctx, "doRequestWithHeader")
	span.AddAttributes(trace.StringAttribute("url", url))
	span.AddAttributes(trace.StringAttribute("method", method))
	argsStr, _ := json.Marshal(args)
	span.AddAttributes(trace.StringAttribute("parameter", string(argsStr)))
	defer span.End()

	request, err := http.NewRequest(method, url, body)
	if err != nil {
		logger.Error("%v", err)
		return nil, err
	}
	tracing.SpanContextToRequest(span, request)
	for k, v := range headers {
		request.Header.Set(k, v)
	}

	if cl := request.Header.Get("Content-Length"); cl != "" {
		length, _ := strconv.ParseInt(cl, 10, 64)
		request.ContentLength = length
	}

	//req.ContentLength = int64(body.Len())
	param := request.URL.Query()
	if args != nil {
		for k, v := range args {
			param.Add(k, v)
		}
	}
	request.URL.RawQuery = param.Encode()
	printReqLog(ctx, request, string(argsStr), nil)
	client := http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, cmd.NotFound{}
		}
		return nil, fmt.Errorf("return code:%d", resp.StatusCode)
	}

	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	return result, nil
}

func printReqLog(ctx context.Context, req *http.Request, args string, body io.Reader) {
	//logger.Info("--------------------------------------------")
	logger.Infof("dorequest: %s", req.URL.String())
	logger.Info(args)
	logger.Info("")

}
