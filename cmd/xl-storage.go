package cmd

import (
	"errors"
	"github.com/dustin/go-humanize"
	"os"
)

const (
	nullVersionID  = "null"
	blockSizeSmall = 128 * humanize.KiByte // Default r/w block size for smaller objects.
	blockSizeLarge = 2 * humanize.MiByte   // Default r/w block size for larger objects.
)

func osIsNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}

func osIsPermission(err error) bool {
	return errors.Is(err, os.ErrPermission)
}
