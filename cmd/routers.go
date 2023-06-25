package cmd

import (
	"github.com/gorilla/mux"
)

// List of some generic handlers which are applied for all incoming requests.
var globalHandlers = []mux.MiddlewareFunc{
	// filters HTTP headers which are treated as metadata and are reserved
	// for internal use only.
	filterReservedMetadata,
	// Enforce rules specific for TLS requests
	setSSETLSHandler,
	// set x-amz-request-id header.
	addCustomHeaders,
	// Auth handler verifies incoming authorization headers and
	// routes them accordingly. Client receives a HTTP error for
	// invalid/unsupported signatures.
	setAuthHandler,
	// Validates all incoming requests to have a valid date header.
	setTimeValidityHandler,
	// Validates if incoming request is for restricted buckets.
	setReservedBucketHandler,
	// Redirect some pre-defined browser request paths to a static location prefix.
	setBrowserRedirectHandler,
	// Adds 'crossdomain.xml' policy handler to serve legacy flash clients.
	setCrossDomainPolicy,
	// Limits all header sizes to a maximum fixed limit
	setRequestHeaderSizeLimitHandler,
	// Limits all requests size to a maximum fixed limit
	setRequestSizeLimitHandler,
	// Network statistics
	setHTTPStatsHandler,
	// Validate all the incoming requests.
	setRequestValidityHandler,
	// Forward path style requests to actual host in a bucket federated setup.
	setBucketForwardingHandler,
	// set HTTP security headers such as Content-Security-Policy.
	addSecurityHeaders,
	// set x-amz-request-id header.
	//addCustomHeaders,
	// add redirect handler to redirect
	// requests when object layer is not
	// initialized.
	setRedirectHandler,
	// Add new handlers here.
}
