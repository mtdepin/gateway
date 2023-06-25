// +build freebsd netbsd openbsd darwin



package disk

import (
	"os"
	"syscall"
)

// Fdatasync is fsync on freebsd/darwin
func Fdatasync(f *os.File) error {
	return syscall.Fsync(int(f.Fd()))
}
