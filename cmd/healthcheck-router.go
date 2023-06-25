package cmd

const (
	healthCheckPath            = "/health"
	healthCheckLivenessPath    = "/live"
	healthCheckReadinessPath   = "/ready"
	healthCheckClusterPath     = "/cluster"
	healthCheckClusterReadPath = "/cluster/read"
	healthCheckPathPrefix      = minioReservedBucketPath + healthCheckPath
)
