package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/minio/minio/maitian/config"

	"github.com/minio/minio/maitian/mq"
	"github.com/minio/minio/maitian/redispool"
	"github.com/minio/minio/maitian/tracing"

	"github.com/gorilla/mux"
	"github.com/minio/cli"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/pkg/certs"
	"github.com/minio/pkg/env"
)

var (
	gatewayCmd = cli.Command{
		Name:            "gateway",
		Usage:           "start object storage gateway",
		Flags:           GlobalFlags,
		HideHelpCommand: true,
	}
)

// RegisterGatewayCommand registers a new command for gateway.
func RegisterGatewayCommand(cmd cli.Command) error {
	cmd.Flags = append(append(cmd.Flags, ServerFlags...), GlobalFlags...)
	gatewayCmd.Subcommands = append(gatewayCmd.Subcommands, cmd)
	return nil
}

// ParseGatewayEndpoint - Return endpoint.
func ParseGatewayEndpoint(arg string) (endPoint string, secure bool, err error) {
	schemeSpecified := len(strings.Split(arg, "://")) > 1
	if !schemeSpecified {
		// Default connection will be "secure".
		arg = "https://" + arg
	}

	u, err := url.Parse(arg)
	if err != nil {
		return "", false, err
	}

	switch u.Scheme {
	case "http":
		return u.Host, false, nil
	case "https":
		return u.Host, true, nil
	default:
		return "", false, fmt.Errorf("Unrecognized scheme %s", u.Scheme)
	}
}

// ValidateGatewayArguments - Validate gateway arguments.
func ValidateGatewayArguments(serverAddr, endpointAddr string) error {
	if err := CheckLocalServerAddr(serverAddr); err != nil {
		return err
	}

	if endpointAddr != "" {
		// Reject the endpoint if it points to the gateway handler itself.
		sameTarget, err := sameLocalAddrs(endpointAddr, serverAddr)
		if err != nil {
			return err
		}
		if sameTarget {
			return fmt.Errorf("endpoint points to the local gateway")
		}
	}
	return nil
}

// StartGateway - handler for 'minio gateway <name>'.
func StartGateway(ctx *cli.Context, gw Gateway, pprofEnable bool) {

	//init jeager
	jaeger := tracing.SetupJaegerTracing("mtoss")
	defer func() {
		if jaeger != nil {
			jaeger.Flush()
		}
	}()

	//start mq
	mq.StartMQ()

	signal.Notify(globalOSSignalCh, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)

	go handleSignals()

	// This is only to uniquely identify each gateway deployments.
	globalDeploymentID = env.Get("GATEWAY_DEPLOYMENT_ID", mustGetUUID())
	logger.SetDeploymentID(globalDeploymentID)

	if gw == nil {
		logger.FatalIf(errUnexpected, "Gateway implementation not initialized")
	}

	// Validate if we have access, secret set through environment.
	globalGatewayName = gw.Name()
	gatewayName := gw.Name()
	if ctx.Args().First() == "help" {
		cli.ShowCommandHelpAndExit(ctx, gatewayName, 1)
	}

	// Handle common command args.
	handleCommonCmdArgs(ctx)

	// Check and load TLS certificates.
	var err error
	globalPublicCerts, globalTLSCerts, globalIsTLS, err = getTLSConfig()
	logger.FatalIf(err, "Invalid TLS certificate file")

	// Check and load Root CAs.
	globalRootCAs, err = certs.GetRootCAs(globalCertsCADir.Get())
	logger.FatalIf(err, "Failed to read root CAs (%v)", err)

	// Add the global public crts as part of global root CAs
	for _, publicCrt := range globalPublicCerts {
		globalRootCAs.AddCert(publicCrt)
	}

	// Register root CAs for remote ENVs
	env.RegisterGlobalCAs(globalRootCAs)

	// On macOS, if a process already listens on LOCALIPADDR:PORT, net.Listen() falls back
	// to IPv6 address ie minio will start listening on IPv6 address whereas another
	// (non-)minio process is listening on IPv4 of given port.
	// To avoid this error situation we check for port availability.
	logger.FatalIf(checkPortAvailability(globalMinioHost, globalMinioPort), "Unable to start the gateway")

	// Handle gateway specific env
	gatewayHandleEnvVars()

	// Set system resources to maximum.
	err = setMaxResources()
	if err != nil {
		logger.Error(err)
		return
	}

	// Initialize router. `SkipClean(true)` stops gorilla/mux from
	// normalizing URL path minio/minio#3256
	// avoid URL path encoding minio/minio#8950
	router := mux.NewRouter().SkipClean(true).UseEncodedPath()

	// Enable IAM admin APIs if etcd is enabled, if not just enable basic
	// operations such as profiling, server info etc.
	registerAdminRouter(router)

	// Add server metrics router
	registerMetricsRouter(router)

	// Add API router.
	registerAPIRouter(router)

	if pprofEnable {
		//Profile router
		logger.Info("start pprof ...")
		//go-torch -u http://localhost:10086/debug/pprof/ -p -t 60 > local.svg
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/debug/pprof/", pprof.Index)
			mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
			mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
			mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
			mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
			http.ListenAndServe(":9002", mux)
		}()

		//registerProfileRouter(router)
	}

	// 状态探测
	detectionEnable := config.GetBool("detection")
	if detectionEnable {
		go initDetectionRouter()
	}

	// Use all the middlewares
	router.Use(globalHandlers...)

	var getCert certs.GetCertificateFunc
	if globalTLSCerts != nil {
		getCert = globalTLSCerts.GetCertificate
	}

	httpServer := xhttp.NewServer([]string{globalMinioAddr},
		criticalErrorHandler{CORS(router)}, getCert)
	httpServer.BaseContext = func(listener net.Listener) context.Context {
		return GlobalContext
	}
	go func() {
		globalHTTPServerErrorCh <- httpServer.Start()
	}()

	globalObjLayerMutex.Lock()
	globalHTTPServer = httpServer
	globalObjLayerMutex.Unlock()

	//init objectLayer
	newObject, err := gw.NewGatewayLayer()
	if err != nil {
		globalHTTPServer.Shutdown()
		logger.FatalIf(err, "Unable to initialize gateway backend")
	}

	// Calls all New() for all sub-systems.
	newAllSubsystems()

	// Once endpoints are finalized, initialize the new object api in safe mode.
	globalObjLayerMutex.Lock()
	globalObjectAPI = newObject
	globalObjLayerMutex.Unlock()

	//init redis client
	redispool.InitRedisClient(redispool.GetRedisOption())

	// Verify if object layer supports
	// - encryption
	// - compression
	verifyObjectLayerFeatures("gateway "+gatewayName, newObject)

	// Prints the formatted startup message once object layer is initialized.
	if !globalCLIContext.Quiet {
		// Print gateway startup message.
		printGatewayStartupMessage(getAPIEndpoints(), gatewayName)
	}
	<-globalOSSignalCh
}

func newAllSubsystems() {

	// Create new IAM system.
	globalIAMSys = NewIAMSys()
	globalIAMSys.InitIam()

}

func initDetectionRouter() {
	logger.Info("init detection router")

	router := mux.NewRouter().SkipClean(true).UseEncodedPath()

	// Add Detection router
	registerDetectionRouter(router)

	// 探测端口默认本地 9001
	addr := ":9001"

	httpServer := xhttp.NewServer([]string{addr}, router, nil)
	httpServer.BaseContext = func(listener net.Listener) context.Context {
		return context.Background()
	}

	if err := httpServer.Start(); err != nil {
		logger.Error("detection server start fail", err)
	}

}
