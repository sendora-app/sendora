// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"errors"
	"io"
	"net/http"
	"time"
)

func (s *Server) transferTimeout() time.Duration {
	if s.transferIdleTimeout > 0 {
		return s.transferIdleTimeout
	}
	return 60 * time.Second
}

// Transfers must not only keep moving but keep a minimum average speed, so a
// client trickling a few bytes per minute cannot hold a slot or lock for hours.
// 16 KiB/s (128 kbit/s) is far below any normal connection.
const (
	transferMinRate  = 16 << 10
	transferMinGrace = 90 * time.Second
)

var errTransferTooSlow = errors.New("transfer too slow")

type rateGuard struct {
	start time.Time
	bytes int64
}

func (g *rateGuard) tooSlow(n int) bool {
	if g.start.IsZero() {
		g.start = time.Now()
	}
	g.bytes += int64(n)
	elapsed := time.Since(g.start)
	return elapsed > transferMinGrace && float64(g.bytes) < elapsed.Seconds()*transferMinRate
}

// Chunk uploads may run for minutes, but must keep making read progress.
type idleRequestBody struct {
	io.ReadCloser
	controller *http.ResponseController
	timeout    time.Duration
	rate       rateGuard
}

func (b *idleRequestBody) Read(p []byte) (int, error) {
	if err := b.controller.SetReadDeadline(time.Now().Add(b.timeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return 0, err
	}
	n, err := b.ReadCloser.Read(p)
	if b.rate.tooSlow(n) {
		return n, errTransferTooSlow
	}
	return n, err
}

// No ReaderFrom method: io.Copy must pass bounded chunks through Write so a
// continuously progressing large download is not subject to a total time cap.
type idleResponseWriter struct {
	http.ResponseWriter
	controller *http.ResponseController
	timeout    time.Duration
	rate       rateGuard
}

func (w *idleResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *idleResponseWriter) WriteHeader(code int) {
	_ = w.controller.SetWriteDeadline(time.Now().Add(w.timeout))
	w.ResponseWriter.WriteHeader(code)
}

func (w *idleResponseWriter) Write(p []byte) (int, error) {
	if err := w.controller.SetWriteDeadline(time.Now().Add(w.timeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return 0, err
	}
	n, err := w.ResponseWriter.Write(p)
	if err == nil && w.rate.tooSlow(n) {
		return n, errTransferTooSlow
	}
	return n, err
}
