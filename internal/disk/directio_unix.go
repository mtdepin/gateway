// +build linux netbsd freebsd



package disk

import (
	"os"
	"syscall"

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
	flag, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	flag = flag & ^(syscall.O_DIRECT)
	_, err = unix.FcntlInt(fd, unix.F_SETFL, flag)
	return err
}

// AlignedBlock - pass through to directio implementation.
func AlignedBlock(BlockSize int) []byte {
	return directio.AlignedBlock(BlockSize)
}
