package cmd

import (
	"fmt"
	"strings"

	"github.com/tidwall/gjson"

	"github.com/spf13/cobra"
)

var gatewayReqQueue bool

var gatewayCmd = &cobra.Command{
	Use:   "gateway",
	Short: "gateway server status",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 0 {
			return fmt.Errorf("command line arguments are incorrect")
		}

		cmd.SilenceUsage = true

		if gatewayReqQueue {
			fmt.Println("gateway request queue info:")
			requestQueueInfo := getServerStatus(fmt.Sprintf("%s:%d", Localhost, GatewayPort), "/status/request")
			if requestQueueInfo != nil {
				fmt.Println("  maxReqNum: ", gjson.Get(string(requestQueueInfo), "maxReqNum").Int())
				fmt.Println("  curReqNum: ", gjson.Get(string(requestQueueInfo), "curReqNum").Int())
			}

		} else {
			statusInfo := getServerStatus(fmt.Sprintf("%s:%d", Localhost, GatewayPort), "/status")
			if statusInfo != nil {
				gatewayFormat(string(statusInfo))
			}
		}

		return nil
	},
}

func gatewayFormat(info string) {
	in := strings.Builder{}
	in.WriteString("gateway info\n")
	in.WriteString(fmt.Sprintf("%s%s\n", "  version: ", gjson.Get(info, "version").String()))
	in.WriteString("gateway service\n")
	serviceMap := gjson.Get(info, "service").Map()
	for key, value := range serviceMap {
		in.WriteString(fmt.Sprintf("  %s: %s\n", key, value))
	}
	in.WriteString("gateway request\n")
	requestMap := gjson.Get(info, "request").Map()
	for key, value := range requestMap {
		in.WriteString(fmt.Sprintf("  %s: %s\n", key, value))
	}

	fmt.Println(in.String())
}

func init() {
	gatewayCmd.Flags().BoolVarP(&gatewayReqQueue, "request", "r", false, "get gateway requestQueue info")
	rootCmd.AddCommand(gatewayCmd)
}
