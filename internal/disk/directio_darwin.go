

package disk

import (
	"os"

	"github.com/ncw/directio"
	"golang.org/x/sys/unix"
)

// OpenFileDirectIO - bypass kernel cache.
func OpenFileDirectIO(filePath string, flag int, perm os.FileMode) (*os.File, error) {
	return directio.OpenFile(filePath, flag, perm)
}

// DisableDirectIO - disables directio mode.
func DisableDirectIO(f *os.File) error {
	fd := f.Fd()
	_, err := unix.FcntlInt(fd, unix.F_NOCACHE, 0)
	return err
}

// AlignedBlock - pass through to directio implementation.
func AlignedBlock(BlockSize int) []byte {
	return directio.AlignedBlock(BlockSize)
}
