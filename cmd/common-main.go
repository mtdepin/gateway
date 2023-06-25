package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	fcolor "github.com/fatih/color"
	dns2 "github.com/miekg/dns"
	"github.com/minio/cli"
	"github.com/minio/kes"
	"github.com/minio/minio/internal/config"
	"github.com/minio/minio/internal/kms"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/pkg/certs"
	"github.com/minio/pkg/console"
	"github.com/minio/pkg/ellipses"
	"github.com/minio/pkg/env"
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())

	initGlobalContext()

	globalTransitionState = newTransitionState()

	console.SetColor("Debug", fcolor.New())

	gob.Register(StorageErr(""))

}

func verifyObjectLayerFeatures(name string, objAPI ObjectLayer) {
	if (GlobalKMS != nil) && !objAPI.IsEncryptionSupported() {
		logger.Fatal(errInvalidArgument,
			"Encryption support is requested but '%s' does not support encryption", name)
	}

	if strings.HasPrefix(name, "gateway") {
		if GlobalGatewaySSE.IsSet() && GlobalKMS == nil {
			uiErr := config.ErrInvalidGWSSEEnvValue(nil).Msg("MINIO_GATEWAY_SSE set but KMS is not configured")
			logger.Fatal(uiErr, "Unable to start gateway with SSE")
		}
	}

	globalCompressConfigMu.Lock()
	if globalCompressConfig.Enabled && !objAPI.IsCompressionSupported() {
		logger.Fatal(errInvalidArgument,
			"Compression support is requested but '%s' does not support compression", name)
	}
	globalCompressConfigMu.Unlock()
}

func handleCommonCmdArgs(ctx *cli.Context) {

	// Fetch address option
	addr := ctx.GlobalString("address")
	if addr == "" || addr == ":"+GlobalMinioDefaultPort {
		addr = ctx.String("address")
	}

	globalMinioHost, globalMinioPort = mustSplitHostPort(addr)

	if globalMinioPort == globalMinioConsolePort {
		logger.FatalIf(errors.New("--console-address port cannot be same as --address port"), "Unable to start the server")
	}

	globalMinioAddr = addr

	// Check "no-compat" flag from command line argument.
	globalCLIContext.StrictS3Compat = true
	if ctx.IsSet("no-compat") || ctx.GlobalIsSet("no-compat") {
		globalCLIContext.StrictS3Compat = false
	}

	// Set all config, certs and CAs directories.

	globalCertsCADir = &ConfigDir{path: filepath.Join(globalCertsDir.Get(), certsCADir)}

	logger.FatalIf(mkdirAllIgnorePerm(globalCertsCADir.Get()), "Unable to create certs CA directory at %s", globalCertsCADir.Get())
}

func handleCommonEnvVars() {

	domains := env.Get(config.EnvDomain, "")
	if len(domains) != 0 {
		for _, domainName := range strings.Split(domains, config.ValueSeparator) {
			if _, ok := dns2.IsDomainName(domainName); !ok {
				logger.Fatal(config.ErrInvalidDomainValue(nil).Msg("Unknown value `%s`", domainName),
					"Invalid MINIO_DOMAIN value in environment variable")
			}
			globalDomainNames = append(globalDomainNames, domainName)
		}
		sort.Strings(globalDomainNames)
		lcpSuf := lcpSuffix(globalDomainNames)
		for _, domainName := range globalDomainNames {
			if domainName == lcpSuf && len(globalDomainNames) > 1 {
				logger.Fatal(config.ErrOverlappingDomainValue(nil).Msg("Overlapping domains `%s` not allowed", globalDomainNames),
					"Invalid MINIO_DOMAIN value in environment variable")
			}
		}
	}

	// Check if the supported credential env vars, "MINIO_ROOT_USER" and
	// "MINIO_ROOT_PASSWORD" are provided
	// Warn user if deprecated environment variables,
	// "MINIO_ACCESS_KEY" and "MINIO_SECRET_KEY", are defined
	// Check all error conditions first
	if !env.IsSet(config.EnvRootUser) && env.IsSet(config.EnvRootPassword) {
		logger.Fatal(config.ErrMissingEnvCredentialRootUser(nil), "Unable to start MinIO")
	} else if env.IsSet(config.EnvRootUser) && !env.IsSet(config.EnvRootPassword) {
		logger.Fatal(config.ErrMissingEnvCredentialRootPassword(nil), "Unable to start MinIO")
	} else if !env.IsSet(config.EnvRootUser) && !env.IsSet(config.EnvRootPassword) {
		if !env.IsSet(config.EnvAccessKey) && env.IsSet(config.EnvSecretKey) {
			logger.Fatal(config.ErrMissingEnvCredentialAccessKey(nil), "Unable to start MinIO")
		} else if env.IsSet(config.EnvAccessKey) && !env.IsSet(config.EnvSecretKey) {
			logger.Fatal(config.ErrMissingEnvCredentialSecretKey(nil), "Unable to start MinIO")
		}
	}

	if env.IsSet(config.EnvKESEndpoint) {
		var endpoints []string
		for _, endpoint := range strings.Split(env.Get(config.EnvKESEndpoint, ""), ",") {
			if strings.TrimSpace(endpoint) == "" {
				continue
			}
			if !ellipses.HasEllipses(endpoint) {
				endpoints = append(endpoints, endpoint)
				continue
			}
			patterns, err := ellipses.FindEllipsesPatterns(endpoint)
			if err != nil {
				logger.Fatal(err, fmt.Sprintf("Invalid KES endpoint %q", endpoint))
			}
			for _, lbls := range patterns.Expand() {
				endpoints = append(endpoints, strings.Join(lbls, ""))
			}
		}
		certificate, err := tls.LoadX509KeyPair(env.Get(config.EnvKESClientCert, ""), env.Get(config.EnvKESClientKey, ""))
		if err != nil {
			logger.Fatal(err, "Unable to load KES client certificate as specified by the shell environment")
		}
		rootCAs, err := certs.GetRootCAs(env.Get(config.EnvKESServerCA, globalCertsCADir.Get()))
		if err != nil {
			logger.Fatal(err, fmt.Sprintf("Unable to load X.509 root CAs for KES from %q", env.Get(config.EnvKESServerCA, globalCertsCADir.Get())))
		}

		var defaultKeyID = env.Get(config.EnvKESKeyName, "")
		KMS, err := kms.NewWithConfig(kms.Config{
			Endpoints:    endpoints,
			DefaultKeyID: defaultKeyID,
			Certificate:  certificate,
			RootCAs:      rootCAs,
		})
		if err != nil {
			logger.Fatal(err, "Unable to initialize a connection to KES as specified by the shell environment")
		}

		// We check that the default key ID exists or try to create it otherwise.
		// This implicitly checks that we can communicate to KES. We don't treat
		// a policy error as failure condition since MinIO may not have the permission
		// to create keys - just to generate/decrypt data encryption keys.
		if err = KMS.CreateKey(defaultKeyID); err != nil && !errors.Is(err, kes.ErrKeyExists) && !errors.Is(err, kes.ErrNotAllowed) {
			logger.Fatal(err, "Unable to initialize a connection to KES as specified by the shell environment")
		}
		GlobalKMS = KMS
	}
}

func logStartupMessage(msg string) {
	logger.Infof(msg)
}

func getTLSConfig() (x509Certs []*x509.Certificate, manager *certs.Manager, secureConn bool, err error) {
	if !(isFile(getPublicCertFile()) && isFile(getPrivateKeyFile())) {
		return nil, nil, false, nil
	}

	if x509Certs, err = config.ParsePublicCertFile(getPublicCertFile()); err != nil {
		return nil, nil, false, err
	}

	manager, err = certs.NewManager(GlobalContext, getPublicCertFile(), getPrivateKeyFile(), config.LoadX509KeyPair)
	if err != nil {
		return nil, nil, false, err
	}

	// MinIO has support for multiple certificates. It expects the following structure:
	//  certs/
	//   │
	//   ├─ public.crt
	//   ├─ private.key
	//   │
	//   ├─ example.com/
	//   │   │
	//   │   ├─ public.crt
	//   │   └─ private.key
	//   └─ foobar.org/
	//      │
	//      ├─ public.crt
	//      └─ private.key
	//   ...
	//
	// Therefore, we read all filenames in the cert directory and check
	// for each directory whether it contains a public.crt and private.key.
	// If so, we try to add it to certificate manager.
	root, err := os.Open(globalCertsDir.Get())
	if err != nil {
		return nil, nil, false, err
	}
	defer root.Close()

	files, err := root.Readdir(-1)
	if err != nil {
		return nil, nil, false, err
	}
	for _, file := range files {
		// Ignore all
		// - regular files
		// - "CAs" directory
		// - any directory which starts with ".."
		if file.Mode().IsRegular() || file.Name() == "CAs" || strings.HasPrefix(file.Name(), "..") {
			continue
		}
		if file.Mode()&os.ModeSymlink == os.ModeSymlink {
			file, err = os.Stat(filepath.Join(root.Name(), file.Name()))
			if err != nil {
				// not accessible ignore
				continue
			}
			if !file.IsDir() {
				continue
			}
		}

		var (
			certFile = filepath.Join(root.Name(), file.Name(), publicCertFile)
			keyFile  = filepath.Join(root.Name(), file.Name(), privateKeyFile)
		)
		if !isFile(certFile) || !isFile(keyFile) {
			continue
		}
		if err = manager.AddCertificate(certFile, keyFile); err != nil {
			err = fmt.Errorf("Unable to load TLS certificate '%s,%s': %w", certFile, keyFile, err)
			logger.LogIf(GlobalContext, err, logger.Minio)
		}
	}
	secureConn = true
	return x509Certs, manager, secureConn, nil
}

// contextCanceled returns whether a context is canceled.
func contextCanceled(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
