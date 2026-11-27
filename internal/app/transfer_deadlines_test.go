// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIncompleteAuthBodyReleasesSlot(t *testing.T) {
	e := newEnv(t)
	e.s.requestBodyTimeout = 50 * time.Millisecond
	conn, err := net.Dial("tcp", strings.TrimPrefix(e.ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = fmt.Fprintf(conn, "POST /api/auth/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{")
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d", response.StatusCode)
	}
	if len(e.s.authSlots) != 0 {
		t.Fatal("incomplete body retained authentication slot")
	}
	e.want(e.do("POST", "/api/auth/login", "", map[string]any{}), 401, "authentication remains available")
}

func TestStalledDownloadReleasesSnapshotSlot(t *testing.T) {
	e := newEnv(t)
	e.s.transferIdleTimeout = 100 * time.Millisecond
	admin := e.setup()
	share := e.share(admin, map[string]string{"large.bin": strings.Repeat("x", 8<<20)}, nil)
	e.want(share, 201, "create share")
	finished := make(chan struct{}, 1)
	router := e.s.Router()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		router.ServeHTTP(w, r)
		finished <- struct{}{}
	}))
	defer ts.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "GET /api/shares/%s/download HTTP/1.1\r\nHost: localhost\r\n\r\n", share.S("long_id"))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("download status: %d", response.StatusCode)
	}
	// A single isolated local connection intentionally does not drain its body.
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("stalled response retained download slot")
	}
	if len(integritySlots) != 0 {
		t.Fatal("snapshot slot not released")
	}
	var count int
	if err := e.s.St.DB.QueryRow(`SELECT COUNT(*) FROM downloads`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("download start not recorded: count=%d err=%v", count, err)
	}
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	reads, writes []time.Time
}

func (w *deadlineRecorder) SetReadDeadline(t time.Time) error {
	w.reads = append(w.reads, t)
	return nil
}
func (w *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	w.writes = append(w.writes, t)
	return nil
}

func TestTransferDeadlinesRenewOnProgress(t *testing.T) {
	r := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	controller := http.NewResponseController(r)
	body := &idleRequestBody{ReadCloser: io.NopCloser(strings.NewReader("abc")), controller: controller, timeout: time.Minute}
	for i := 0; i < 3; i++ {
		if _, err := body.Read(make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
	}
	w := &idleResponseWriter{ResponseWriter: r, controller: controller, timeout: time.Minute}
	w.WriteHeader(200)
	for i := 0; i < 3; i++ {
		if _, err := w.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.reads) != 3 || len(r.writes) != 4 {
		t.Fatal("deadlines not renewed per read/write")
	}
	if !r.reads[2].After(r.reads[0]) || !r.writes[3].After(r.writes[0]) {
		t.Fatal("transfer has fixed total deadline")
	}
}
