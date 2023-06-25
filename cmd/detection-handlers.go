package cmd

import (
	"encoding/json"
	"net/http"

	"github.com/minio/minio/maitian/config"
)

type detectionAPIHandlers struct{}

func (d detectionAPIHandlers) StatusInfoHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "status")
	// defer logger.AuditLog(ctx, w, r)

	serviceInfo := make(map[string]interface{})

	// todo 服务状态信息，现在从配置文件获取，后续需要对服务状态进行探测
	dbInfo := config.GetString("db.db_url")
	if dbInfo != "" {
		serviceInfo["db"] = dbInfo
	}

	iamInfo := config.GetString("iam.url")
	if iamInfo != "" {
		serviceInfo["iam"] = iamInfo
	}

	mqInfo := config.GetString("mq.server")
	if mqInfo != "" {
		serviceInfo["mq"] = mqInfo
	}

	redisInfo := config.GetString("redis.redis_addr")
	if redisInfo != "" {
		serviceInfo["redis"] = redisInfo
	}

	jaegerInfo := config.GetString("jaeger.jaeger_agent")
	if jaegerInfo != "" {
		serviceInfo["jaeger"] = jaegerInfo
	}

	esInfo := config.GetString("elasticsearch.endpoint")
	if esInfo != "" {
		serviceInfo["elasticsearch"] = esInfo
	}

	gatewayRequestInfo := make(map[string]interface{})

	maxReqNum, curReqNum := GetRequestQueue()
	gatewayRequestInfo["maxReqNum"] = maxReqNum
	gatewayRequestInfo["curReqNum"] = curReqNum

	gatewayStatusInfo := make(map[string]interface{})

	gatewayStatusInfo["service"] = serviceInfo

	gatewayStatusInfo["request"] = gatewayRequestInfo

	gatewayStatusInfo["version"] = minioVersion

	gatewayStatusInfoToJson, err := json.Marshal(gatewayStatusInfo)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAPIError(ctx, err), r.URL)
	}

	writeSuccessResponseJSON(w, gatewayStatusInfoToJson)

}

func (d detectionAPIHandlers) RequestQueueInfoHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "request")
	// defer logger.AuditLog(ctx, w, r)

	gatewayRequestInfo := make(map[string]interface{})

	maxReqNum, curReqNum := GetRequestQueue()
	gatewayRequestInfo["maxReqNum"] = maxReqNum
	gatewayRequestInfo["curReqNum"] = curReqNum

	gatewayRequestInfoToJson, err := json.Marshal(gatewayRequestInfo)
	if err != nil {
		writeErrorResponseJSON(ctx, w, toAPIError(ctx, err), r.URL)
	}

	writeSuccessResponseJSON(w, gatewayRequestInfoToJson)
}
