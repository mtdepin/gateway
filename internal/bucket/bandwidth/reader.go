

package bandwidth

import (
	"context"
	"io"
	"math"
)

// MonitoredReader represents a throttled reader subject to bandwidth monitoring
type MonitoredReader struct {
	r        io.Reader
	throttle *throttle
	ctx      context.Context // request context
	lastErr  error           // last error reported, if this non-nil all reads will fail.
	m        *Monitor
	opts     *MonitorReaderOptions
}

// MonitorReaderOptions provides configurable options for monitor reader implementation.
type MonitorReaderOptions struct {
	Bucket     string
	HeaderSize int
}

// Read implements a throttled read
func (r *MonitoredReader) Read(buf []byte) (n int, err error) {
	if r.throttle == nil {
		return r.r.Read(buf)
	}
	if r.lastErr != nil {
		err = r.lastErr
		return
	}
	b := r.throttle.Burst()  // maximum available tokens
	need := len(buf)         // number of bytes requested by caller
	hdr := r.opts.HeaderSize // remaining header bytes
	var tokens int           // number of tokens to request

	if hdr > 0 { // available tokens go towards header first
		if hdr < b { // all of header can be accommodated
			r.opts.HeaderSize = 0
			need = int(math.Min(float64(b-hdr), float64(need))) // use remaining tokens towards payload
			tokens = need + hdr

		} else { // part of header can be accommodated
			r.opts.HeaderSize -= b - 1
			need = 1 // to ensure we read at least one byte for every Read
			tokens = b
		}

	} else { // all tokens go towards payload
		need = int(math.Min(float64(b), float64(need)))
		tokens = need
	}

	err = r.throttle.WaitN(r.ctx, tokens)
	if err != nil {
		return
	}

	n, err = r.r.Read(buf[:need])
	if err != nil {
		r.lastErr = err
		return
	}
	r.m.updateMeasurement(r.opts.Bucket, uint64(tokens))
	return
}

// NewMonitoredReader returns reference to a monitored reader that throttles reads to configured bandwidth for the
// bucket.
func NewMonitoredReader(ctx context.Context, m *Monitor, r io.Reader, opts *MonitorReaderOptions) *MonitoredReader {
	reader := MonitoredReader{
		r:        r,
		throttle: m.throttle(opts.Bucket),
		m:        m,
		opts:     opts,
		ctx:      ctx,
	}
	reader.m.track(opts.Bucket)
	return &reader
}
