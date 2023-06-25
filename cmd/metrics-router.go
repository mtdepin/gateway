

package cmd

import (
	"strings"

	"github.com/gorilla/mux"
	"github.com/minio/pkg/env"
)

const (
	prometheusMetricsPathLegacy    = "/prometheus/metrics"
	prometheusMetricsV2ClusterPath = "/v2/metrics/cluster"
	prometheusMetricsV2NodePath    = "/v2/metrics/node"
)

// Standard env prometheus auth type
const (
	EnvPrometheusAuthType = "MINIO_PROMETHEUS_AUTH_TYPE"
)

type prometheusAuthType string

const (
	prometheusJWT    prometheusAuthType = "jwt"
	prometheusPublic prometheusAuthType = "public"
)

// registerMetricsRouter - add handler functions for metrics.
func registerMetricsRouter(router *mux.Router) {
	// metrics router
	metricsRouter := router.NewRoute().PathPrefix(minioReservedBucketPath).Subrouter()
	authType := strings.ToLower(env.Get(EnvPrometheusAuthType, string(prometheusJWT)))
	switch prometheusAuthType(authType) {
	case prometheusPublic:
		metricsRouter.Handle(prometheusMetricsPathLegacy, metricsHandler())
		metricsRouter.Handle(prometheusMetricsV2ClusterPath, metricsServerHandler())
		metricsRouter.Handle(prometheusMetricsV2NodePath, metricsNodeHandler())
	case prometheusJWT:
		metricsRouter.Handle(prometheusMetricsPathLegacy, AuthMiddleware(metricsHandler()))
		metricsRouter.Handle(prometheusMetricsV2ClusterPath, AuthMiddleware(metricsServerHandler()))
		metricsRouter.Handle(prometheusMetricsV2NodePath, AuthMiddleware(metricsNodeHandler()))
	}
}
