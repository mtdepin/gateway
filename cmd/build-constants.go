

package cmd

import (
	"fmt"
	"runtime"
)

var ProgramName = "node"
var minioVersion string = "0.0.8"
var CommitSHA string = ""
var BuildDate string = "1970.1.1"


// DO NOT EDIT THIS FILE DIRECTLY. These are build-time constants
// set through ‘buildscripts/gen-ldflags.go’.
var (
	// GOPATH - GOPATH value at the time of build.
	GOPATH = ""

	// GOROOT - GOROOT value at the time of build.
	GOROOT = ""

	// Version - version time.RFC3339.
	Version = "DEVELOPMENT.GOGET"

	// ReleaseTag - release tag in TAG.%Y-%m-%dT%H-%M-%SZ.
	ReleaseTag = GetInfo()

	// CommitID - latest commit id.
	CommitID = "DEVELOPMENT.GOGET"

	// ShortCommitID - first 12 characters from CommitID.
	ShortCommitID = "DEVELOPMENT.GOGET"
)

// GetInfo returns version information for the peer
func GetInfo() string {
	if minioVersion == "" {
		minioVersion = "development build"
	}

	if CommitSHA == "" {
		CommitSHA = "development build"
	}

	return fmt.Sprintf("Version: %s\n Commit SHA: %s\n Go version: %s\n"+
		" OS/Arch: %s\n build date: %s\n",
		minioVersion, CommitSHA, runtime.Version(),
		fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH), BuildDate)
}
