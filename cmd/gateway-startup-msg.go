package cmd

import (
	"fmt"
	"strings"

	"github.com/minio/minio/internal/color"
)

// Prints the formatted startup message.
func printGatewayStartupMessage(apiEndPoints []string, backendType string) {
	strippedAPIEndpoints := stripStandardPorts(apiEndPoints, globalMinioHost)

	printGatewayCommonMsg(strippedAPIEndpoints)

}

// Prints common server startup message. Prints credential, region and browser access.
func printGatewayCommonMsg(apiEndpoints []string) {
	apiEndpointStr := strings.Join(apiEndpoints, "  ")

	// Colorize the message and print.
	logStartupMessage(color.Blue("Listen API: ") + color.Bold(fmt.Sprintf("%s ", apiEndpointStr)))

}
