

package main // import "github.com/minio/minio"

import (
	// Import gateway
	minio "github.com/minio/minio/cmd"
	_ "github.com/minio/minio/cmd/gateway"
	"os"
)

func main() {
	minio.Main(os.Args)
}
