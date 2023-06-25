

package logger

import (
	"github.com/minio/minio/internal/config"
	"github.com/minio/minio/internal/logger/target/http"
)

// Legacy envs
const (
	legacyEnvAuditLoggerHTTPEndpoint = "MINIO_AUDIT_LOGGER_HTTP_ENDPOINT"
	legacyEnvLoggerHTTPEndpoint      = "MINIO_LOGGER_HTTP_ENDPOINT"
)

// SetLoggerHTTPAudit - helper for migrating older config to newer KV format.
func SetLoggerHTTPAudit(scfg config.Config, k string, args http.Config) {
	if !args.Enabled {
		// Do not enable audit targets, if not enabled
		return
	}
	scfg[config.AuditWebhookSubSys][k] = config.KVS{
		config.KV{
			Key:   config.Enable,
			Value: config.EnableOn,
		},
		config.KV{
			Key:   Endpoint,
			Value: args.Endpoint,
		},
		config.KV{
			Key:   AuthToken,
			Value: args.AuthToken,
		},
	}
}

// SetLoggerHTTP helper for migrating older config to newer KV format.
func SetLoggerHTTP(scfg config.Config, k string, args http.Config) {
	if !args.Enabled {
		// Do not enable logger http targets, if not enabled
		return
	}

	scfg[config.LoggerWebhookSubSys][k] = config.KVS{
		config.KV{
			Key:   config.Enable,
			Value: config.EnableOn,
		},
		config.KV{
			Key:   Endpoint,
			Value: args.Endpoint,
		},
		config.KV{
			Key:   AuthToken,
			Value: args.AuthToken,
		},
	}
}
