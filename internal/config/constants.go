

package config

// Config value separator
const (
	ValueSeparator = ","
)

// Top level common ENVs
const (
	EnvAccessKey    = "MINIO_ACCESS_KEY"
	EnvSecretKey    = "MINIO_SECRET_KEY"
	EnvRootUser     = "MINIO_ROOT_USER"
	EnvRootPassword = "MINIO_ROOT_PASSWORD"

	EnvBrowser    = "MINIO_BROWSER"
	EnvDomain     = "MINIO_DOMAIN"
	EnvRegionName = "MINIO_REGION_NAME"
	EnvPublicIPs  = "MINIO_PUBLIC_IPS"
	EnvFSOSync    = "MINIO_FS_OSYNC"
	EnvArgs       = "MINIO_ARGS"
	EnvDNSWebhook = "MINIO_DNS_WEBHOOK_ENDPOINT"

	EnvMinIOServerURL          = "MINIO_SERVER_URL"
	EnvMinIOBrowserRedirectURL = "MINIO_BROWSER_REDIRECT_URL"
	EnvRootDiskThresholdSize   = "MINIO_ROOTDISK_THRESHOLD_SIZE"

	EnvUpdate = "MINIO_UPDATE"

	EnvKMSSecretKey  = "MINIO_KMS_SECRET_KEY"
	EnvKESEndpoint   = "MINIO_KMS_KES_ENDPOINT"
	EnvKESKeyName    = "MINIO_KMS_KES_KEY_NAME"
	EnvKESClientKey  = "MINIO_KMS_KES_KEY_FILE"
	EnvKESClientCert = "MINIO_KMS_KES_CERT_FILE"
	EnvKESServerCA   = "MINIO_KMS_KES_CAPATH"

	EnvEndpoints = "MINIO_ENDPOINTS" // legacy
	EnvWorm      = "MINIO_WORM"      // legacy
	EnvRegion    = "MINIO_REGION"    // legacy
)
