// +build !linux,!netbsd,!freebsd,!darwin,!openbsd



package disk

import (
	"os"
)

// Fdatasync is a no-op
func Fdatasync(f *os.File) error {
	return nil
}
