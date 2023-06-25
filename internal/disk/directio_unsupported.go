// +build !linux,!netbsd,!freebsd,!darwin



package disk

import (
	"os"
)

// OpenBSD, Windows, and illumos do not support O_DIRECT.
// On Windows there is no documentation on disabling O_DIRECT.
// For these systems we do not attempt to build the 'directio' dependency since
// the O_DIRECT symbol may not be exposed resulting in a failed build.
//
//
// On illumos an explicit O_DIRECT flag is not necessary for two primary
// reasons. Note that ZFS is effectively the default filesystem on illumos
// systems.
//
// One benefit of using DirectIO on Linux is that the page cache will not be
// polluted with single-access data. The ZFS read cache (ARC) is scan-resistant
// so there is no risk of polluting the entire cache with data accessed once.
// Another goal of DirectIO is to minimize the mutation of data by the kernel
// before issuing IO to underlying devices. ZFS users often enable features like
// compression and checksumming which currently necessitates mutating data in
// the kernel.
//
// DirectIO semantics for a filesystem like ZFS would be quite different than
// the semantics on filesystems like XFS, and these semantics are not
// implemented at this time.
// For more information on why typical DirectIO semantics do not apply to ZFS
// see this ZFS-on-Linux commit message:
// https://github.com/openzfs/zfs/commit/a584ef26053065f486d46a7335bea222cb03eeea

// OpenFileDirectIO wrapper around os.OpenFile nothing special
func OpenFileDirectIO(filePath string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(filePath, flag, perm)
}

// DisableDirectIO is a no-op
func DisableDirectIO(f *os.File) error {
	return nil
}

// AlignedBlock simply returns an unaligned buffer
// for systems that do not support DirectIO.
func AlignedBlock(BlockSize int) []byte {
	return make([]byte, BlockSize)
}
