

package ioutil

import (
	"io"
	"os"

	"github.com/minio/minio/internal/lock"
)

// AppendFile - appends the file "src" to the file "dst"
func AppendFile(dst string, src string, osync bool) error {
	appendFile, err := lock.Open(dst, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer appendFile.Close()

	srcFile, err := lock.Open(src, os.O_RDONLY, 0666)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	_, err = io.Copy(appendFile, srcFile)
	return err
}
