package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/tidwall/gjson"

	"github.com/spf13/cobra"
)

var nameserverReqQueue bool
var storage bool

var nameserverCmd = &cobra.Command{
	Use:   "nameserver",
	Short: "nameserver server status",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 0 {
			return fmt.Errorf("command line arguments are incorrect")
		}

		cmd.SilenceUsage = true

		if nameserverReqQueue || storage {
			if nameserverReqQueue {
				fmt.Println("nameserver request queue info:")
				requestQueueInfo := getServerStatus(fmt.Sprintf("%s:%d", Localhost, NameserverPort), "/status/request")
				if requestQueueInfo != nil {
					fmt.Println("  maxReqNum: ", gjson.Get(string(requestQueueInfo), "maxReqNum").Int())
					fmt.Println("  curReqNum: ", gjson.Get(string(requestQueueInfo), "curReqNum").Int())
				}
			}

			if storage {
				fmt.Println("storage info:")
				storageInfo := getServerStatus(fmt.Sprintf("%s:%d", Localhost, NameserverPort), "/status/storage")
				if storageInfo != nil {
					fmt.Println("  repoSize: ", gjson.Get(string(storageInfo), "repoSize").Int())
					fmt.Println("  storageMax: ", gjson.Get(string(storageInfo), "storageMax").Int())
				}
			}

		} else {
			statusInfo := getServerStatus(fmt.Sprintf("%s:%d", Localhost, NameserverPort), "/status")
			if statusInfo != nil {
				nameserverFormat(statusInfo)
			}
		}

		return nil
	},
}

func nameserverFormat(info []byte) {
	var out bytes.Buffer

	if err := json.Indent(&out, info, "", "\t"); err != nil {
		fmt.Println(err)
		return
	}

	out.WriteTo(os.Stdout)
}

func init() {
	nameserverCmd.Flags().BoolVarP(&nameserverReqQueue, "request", "r", false, "get nameserver requestQueue info")
	nameserverCmd.Flags().BoolVarP(&storage, "storage", "s", false, "get ipfs cluster storage info")
	rootCmd.AddCommand(nameserverCmd)
}
