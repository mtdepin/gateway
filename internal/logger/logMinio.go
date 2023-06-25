package logger

import (
	"context"
	"errors"
	"net/http"
)

const (
	// Minio errors
	Minio Kind = "MINIO"
	// Application errors
	Application Kind = "APPLICATION"
	// All errors
	All Kind = "ALL"
)

type Kind string

var globalDeploymentID string

func CriticalIf(_ context.Context, err error, errKind ...interface{}) {
	if err != nil {
		logger.Panic(err, errKind)
	}
}

// func LogOnceIf(ctx context.Context, err error, id interface{}, errKind ...interface{}) {
// 	if err == nil {
// 		return
// 	}

// 	if errors.Is(err, context.Canceled) {
// 		return
// 	}

// 	if err.Error() == http.ErrServerClosed.Error() || err.Error() == "disk not found" {
// 		return
// 	}

// 	logger.Error(errKind...)
// }
func LogIf(ctx context.Context, err error, errKind ...interface{}) {
	if err == nil {
		return
	}

	if errors.Is(err, context.Canceled) {
		return
	}

	if err.Error() == http.ErrServerClosed.Error() || err.Error() == "disk not found" {
		return
	}

	logger.Error(errKind...)
}

// SetDeploymentID -- Deployment Id from the main package is set here
func SetDeploymentID(deploymentID string) {
	globalDeploymentID = deploymentID
}

// FatalIf is similar to Fatal() but it ignores passed nil error
func FatalIf(err error, msg string, data ...interface{}) {
	if err == nil {
		return
	}
	logger.Fatal(err, msg, data)
}

var ErrCritical struct{}
var Disable = false
var (
	quietFlag, jsonFlag, anonFlag bool
	// Custom function to format error
	errorFmtFunc func(string, error, bool) string
)

// IsJSON - returns true if jsonFlag is true
func IsJSON() bool {
	return jsonFlag
}

// TimeFormat - logging time format.
const TimeFormat string = "15:04:05 MST 01/02/2006"
