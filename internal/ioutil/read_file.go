

package ioutil

import (
	"io"
	"os"
)

// ReadFile reads the named file and returns the contents.
// A successful call returns err == nil, not err == EOF.
// Because ReadFile reads the whole file, it does not treat an EOF from Read
// as an error to be reported.
//
// passes NOATIME flag for reads on Unix systems to avoid atime updates.
func ReadFile(name string) ([]byte, error) {
	f, err := os.OpenFile(name, readMode, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(f)
}
