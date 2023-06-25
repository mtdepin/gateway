package cmd

import (
	"crypto/x509"
	"os"
	"sync"
	"time"

	"github.com/minio/minio/internal/kms"

	"github.com/dustin/go-humanize"
	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/config/compress"
	"github.com/minio/minio/internal/config/identity/openid"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/pubsub"
	"github.com/minio/pkg/certs"
	xnet "github.com/minio/pkg/net"
)

const (
	GlobalMinioDefaultPort = "9000"

	globalMinioDefaultRegion = ""
	// This is a sha256 output of ``arn:aws:iam::minio:user/admin``,
	// this is kept in present form to be compatible with S3 owner ID
	// requirements -
	//
	// ```
	//    The canonical user ID is the Amazon S3–only concept.
	//    It is 64-character obfuscated version of the account ID.
	// ```
	// http://docs.aws.amazon.com/AmazonS3/latest/dev/example-walkthroughs-managing-access-example4.html
	globalMinioDefaultOwnerID      = "02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4"
	globalMinioDefaultStorageClass = "STANDARD"
	globalWindowsOSName            = "windows"
	globalMacOSName                = "darwin"
	globalMinioModeFS              = "mode-server-fs"
	globalMinioModeErasure         = "mode-server-xl"
	globalMinioModeDistErasure     = "mode-server-distributed-xl"
	globalMinioModeGatewayPrefix   = "mode-gateway-"
	globalDirSuffix                = "__XLDIR__"

	// Add new global values here.
)

const (
	// Limit fields size (except file) to 1Mib since Policy document
	// can reach that size according to https://aws.amazon.com/articles/1434
	maxFormFieldSize = int64(1 * humanize.MiByte)

	// Limit memory allocation to store multipart data
	maxFormMemory = int64(5 * humanize.MiByte)

	// The maximum allowed time difference between the incoming request
	// date and server date during signature verification.
	globalMaxSkewTime = 150000 * time.Minute // 15 minutes skew allowed.

	// Maximum size of default bucket encryption configuration allowed
	maxBucketSSEConfigSize = 1 * humanize.MiByte

	// Limit of location constraint XML for unauthenticated PUT bucket operations.
	maxLocationConstraintSize = 3 * humanize.MiByte
)

var globalCLIContext = struct {
	JSON, Quiet    bool
	Anonymous      bool
	StrictS3Compat bool
}{}

var (

	// Name of gateway server, e.g S3, GCS, Azure, etc
	globalGatewayName = ""

	// This flag is set to 'true' by default
	globalBrowserEnabled = false

	// Custom browser redirect URL, not set by default
	// and it is automatically deduced.
	globalBrowserRedirectURL *xnet.URL

	// This flag is set to 'us-east-1' by default
	globalServerRegion = globalMinioDefaultRegion

	// MinIO local server address (in `host:port` format)
	globalMinioAddr = ""

	// MinIO default port, can be changed through command line.
	globalMinioPort        = GlobalMinioDefaultPort
	globalMinioConsolePort = "13333"

	// Holds the host that was passed using --address
	globalMinioHost = ""

	globalIAMSys *IAMSys

	// globalAPIConfig controls S3 API requests throttling,
	// healthcheck readiness deadlines and cors settings.
	globalAPIConfig = apiConfig{listQuorum: 30}

	globalOpenIDConfig openid.Config

	// CA root certificates, a nil value means system certs pool will be used
	globalRootCAs *x509.CertPool

	// IsSSL indicates if the server is configured with SSL.
	globalIsTLS bool

	globalTLSCerts *certs.Manager

	globalHTTPServer        *xhttp.Server
	globalHTTPServerErrorCh = make(chan error)
	globalOSSignalCh        = make(chan os.Signal, 1)
	globalFlushLogging      = make(chan struct{}, 1)

	// global Trace system to send HTTP request/response
	// and Storage/OS calls info to registered listeners.
	globalTrace = pubsub.New()

	// The name of this local node, fetched from arguments
	globalLocalNodeName string

	// Global server's network statistics
	globalConnStats = newConnStats()

	// Global HTTP request statisitics
	globalHTTPStats = newHTTPStats()

	// Time when the server is started
	globalBootTime = UTCNow()

	globalActiveCred auth.Credentials

	globalPublicCerts []*x509.Certificate

	globalDomainNames []string // Root domains for virtual host style requests

	globalBucketVersioningSys *BucketVersioningSys

	// GlobalKMS initialized KMS configuration
	GlobalKMS kms.KMS

	// Is compression enabled?
	globalCompressConfigMu sync.Mutex
	globalCompressConfig   compress.Config

	// Some standard object extensions which we strictly dis-allow for compression.
	standardExcludeCompressExtensions = []string{".gz", ".bz2", ".rar", ".zip", ".7z", ".xz", ".mp4", ".mkv", ".mov", ".jpg", ".png", ".gif"}

	// Some standard content-types which we strictly dis-allow for compression.
	standardExcludeCompressContentTypes = []string{"video/*", "audio/*", "application/zip", "application/x-gzip", "application/x-zip-compressed", " application/x-compress", "application/x-spoon"}

	// Deployment ID - unique per deployment
	globalDeploymentID string

	// GlobalGatewaySSE sse options
	GlobalGatewaySSE gatewaySSE

	//globalTierJournal *tierJournal

	globalDebugRemoteTiersImmediately []string
	// Add new variable global values here.
)
