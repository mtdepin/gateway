package cmd

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"
)

const (
	Localhost      = "127.0.0.1"
	GatewayPort    = 9001
	NameserverPort = 9002
)

func ExecuteCommand(name string, args ...string) (string, error) {
	// 执行cmd命令
	cmd := exec.Command(name, args...)
	bytes, err := cmd.CombinedOutput()

	return string(bytes), err
}

func Error(cmd *cobra.Command, args []string, err error) {
	fmt.Fprintf(os.Stderr, "execute %s args:%v error:%v\n", cmd.Name(), args, err)
	os.Exit(1)
}

func getVersion() string {
	return "detect version 1.0"
}

func getServerStatus(address, path string) []byte {
	url := fmt.Sprintf("http://%s%s", address, path)

	request, _ := http.NewRequest(http.MethodGet, url, nil)

	client := http.Client{
		Transport: http.DefaultTransport,
		Timeout:   time.Second,
	}

	resp, err := client.Do(request)
	if err != nil {
		fmt.Println("get gateway status fail: ", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("get gateway status: ", resp.StatusCode)
		return nil
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("read response body fail: ", err)
		return nil
	}

	return respBody
}
