

package ioutil

import (
	"io"
	"sync"
)

// PipeWriter is similar to io.PipeWriter with wait group
type PipeWriter struct {
	*io.PipeWriter
	done func()
}

// CloseWithError close with supplied error the writer end.
func (w *PipeWriter) CloseWithError(err error) error {
	err = w.PipeWriter.CloseWithError(err)
	w.done()
	return err
}

// PipeReader is similar to io.PipeReader with wait group
type PipeReader struct {
	*io.PipeReader
	wait func()
}

// CloseWithError close with supplied error the reader end
func (r *PipeReader) CloseWithError(err error) error {
	err = r.PipeReader.CloseWithError(err)
	r.wait()
	return err
}

// WaitPipe implements wait-group backend io.Pipe to provide
// synchronization between read() end with write() end.
func WaitPipe() (*PipeReader, *PipeWriter) {
	r, w := io.Pipe()
	var wg sync.WaitGroup
	wg.Add(1)
	return &PipeReader{
			PipeReader: r,
			wait:       wg.Wait,
		}, &PipeWriter{
			PipeWriter: w,
			done:       wg.Done,
		}
}
