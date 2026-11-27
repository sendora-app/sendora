// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"github.com/sendora-app/sendora/internal/netguard"
	"github.com/sendora-app/sendora/internal/store"
)

// Off-host forwarding of the audit log.
//
// After every successful append the record (all fields, including seq,
// prev_hash and hash, so the receiver can check the chain) is queued for each
// configured sink and delivered by that sink's own goroutine:
//
//   - stdout: one JSON line {"sendora_audit":{...}} on standard output;
//   - syslog: RFC 5424 over TCP or TLS with octet-counting framing (RFC 6587 /
//     RFC 5425), the same JSON as the message;
//   - webhook: HTTPS POST of a JSON array of such objects, with an optional
//     bearer token read from SENDORA_AUDIT_FORWARD_WEBHOOK_TOKEN_FILE.
//
// Forwarding never blocks or fails the request path: each sink has a bounded
// queue (a full queue drops and counts the record), delivery is retried with
// exponential backoff, and failures are counted and reported (error class
// only, never a secret) in /api/audit/status and /api/logs/status. Every five
// minutes, at start and at an orderly stop, a chain_head heartbeat with the
// last seq and hash is forwarded ({"sendora_audit_chain_head":{...}}); it is
// not part of the chain. A receiver that sees the head move backwards, or
// records missing below it, knows the local log was changed or truncated.
//
// Targets are dialled through a guard that refuses link-local (including cloud
// metadata) and unspecified addresses after name resolution; private (RFC 1918)
// and loopback addresses stay allowed, a local log relay is common.

// Variables so tests can shorten or redirect them.
var (
	forwardQueueMax                      = 10000
	forwardBatchMax                      = 100
	forwardHeartbeatEvery                = 5 * time.Minute
	forwardBackoffMin                    = time.Second
	forwardBackoffMax                    = 5 * time.Minute
	forwardRetireGrace                   = 5 * time.Second
	forwardRetireMax                     = time.Minute
	forwardConfigTTL                     = 30 * time.Second
	forwardTimeout                       = 10 * time.Second
	forwardStdout         io.Writer      = os.Stdout
	forwardRootCAs        *x509.CertPool // nil = the system roots
)

// forwardStopWait bounds how long an orderly stop waits for the queues to drain.
const forwardStopWait = 3 * time.Second

const forwardTokenEnv = "SENDORA_AUDIT_FORWARD_WEBHOOK_TOKEN_FILE"

const (
	sinkStdout  = "stdout"
	sinkSyslog  = "syslog"
	sinkWebhook = "webhook"
)

var forwardSinkKinds = []string{sinkStdout, sinkSyslog, sinkWebhook}

// auditForwardKeys are the forwarding settings.
var auditForwardKeys = map[string]bool{"audit_forward_stdout": true, "audit_forward_syslog": true,
	"audit_forward_syslog_tls": true, "audit_forward_webhook_url": true}

var (
	errForwardToken   = errors.New("webhook token file rejected")
	errForwardInvalid = errors.New("invalid forwarding target")
)

// chainHead is the heartbeat: the end of the chain at a moment in time.
type chainHead struct {
	LastSeq int64  `json:"last_seq"`
	Hash    string `json:"hash"`
	TS      string `json:"ts"`
	Reason  string `json:"reason"` // start, periodic or stop
}

type forwardItem struct {
	rec  *store.AuditRecord
	head *chainHead
}

func (it forwardItem) envelope() any {
	if it.head != nil {
		return map[string]any{"sendora_audit_chain_head": it.head}
	}
	return map[string]any{"sendora_audit": it.rec}
}

// forwardStats are kept per sink kind, across reconfigurations.
type forwardStats struct {
	enabled                    atomic.Bool
	delivered, failed, dropped atomic.Int64
	mu                         sync.Mutex
	lastOK, lastErrAt          time.Time
	lastErr                    string
}

func (st *forwardStats) ok() {
	st.mu.Lock()
	st.lastOK = time.Now().UTC()
	st.mu.Unlock()
}

func (st *forwardStats) fail(class string) {
	st.mu.Lock()
	st.lastErr, st.lastErrAt = class, time.Now().UTC()
	st.mu.Unlock()
}

// forwardSink is one configured destination with its queue and worker.
type forwardSink struct {
	kind, key  string
	stats      *forwardStats
	q          chan forwardItem
	inflight   atomic.Int64 // queued or being delivered
	retireAt   time.Time    // guarded by auditForwarder.mu; zero while configured
	retired    chan struct{}
	retireOnce sync.Once
	deliver    func(ctx context.Context, items []forwardItem) error
	closeFn    func()
	// Tunables, fixed when the sink is created.
	batchMax                      int
	backoffMin, backoffMax, maxRt time.Duration
}

func (k *forwardSink) enqueue(it forwardItem) {
	k.inflight.Add(1)
	select {
	case k.q <- it:
	default:
		k.inflight.Add(-1)
		k.stats.dropped.Add(1)
	}
}

func (k *forwardSink) retire() { k.retireOnce.Do(func() { close(k.retired) }) }

// run delivers the queue in batches until the context ends or, once the sink
// was removed from the configuration, its queue is empty (or forwardRetireMax
// passed; what is left then is dropped and counted).
func (k *forwardSink) run(ctx context.Context, done func()) {
	defer done()
	if k.closeFn != nil {
		defer k.closeFn()
	}
	backoff := k.backoffMin
	var pending []forwardItem
	retired := (<-chan struct{})(k.retired)
	var deadline <-chan time.Time
	draining := false
	giveUp := func() {
		n := int64(len(pending))
		for {
			select {
			case <-k.q:
				n++
				continue
			default:
			}
			break
		}
		k.stats.dropped.Add(n)
		k.inflight.Add(-n)
	}
	for {
		if len(pending) == 0 {
			if draining && len(k.q) == 0 {
				return
			}
			select {
			case it := <-k.q:
				pending = append(pending, it)
			case <-retired:
				retired, draining = nil, true
				deadline = time.After(k.maxRt)
				continue
			case <-deadline:
				giveUp()
				return
			case <-ctx.Done():
				return
			}
		fill:
			for len(pending) < k.batchMax {
				select {
				case it := <-k.q:
					pending = append(pending, it)
				default:
					break fill
				}
			}
		}
		if err := k.deliver(ctx, pending); err != nil {
			k.stats.failed.Add(1)
			k.stats.fail(forwardErrClass(err))
			select {
			case <-time.After(backoff):
			case <-deadline:
				giveUp()
				return
			case <-ctx.Done():
				return
			}
			backoff = min(backoff*2, k.backoffMax)
			continue
		}
		k.stats.delivered.Add(int64(len(pending)))
		k.inflight.Add(-int64(len(pending)))
		k.stats.ok()
		pending, backoff = nil, k.backoffMin
	}
}

// auditForwarder holds the configured sinks. The zero value is ready; workers
// start when a sink is first configured.
type auditForwarder struct {
	mu      sync.Mutex
	loaded  bool
	gen     uint64
	at      time.Time
	active  map[string]*forwardSink // configured sink per kind
	all     map[*forwardSink]bool   // configured and retiring sinks with a running worker
	stats   map[string]*forwardStats
	ctx     context.Context
	cancel  context.CancelFunc
	stopped bool
	hbOnce  sync.Once
	// stopping: the final chain head is being forwarded; no periodic one follows it.
	stopping atomic.Bool
	hbMu     sync.Mutex // orders the stopping flag against heartbeats being queued
}

func (f *auditForwarder) statsFor(kind string) *forwardStats {
	if f.stats == nil {
		f.stats = map[string]*forwardStats{}
	}
	st := f.stats[kind]
	if st == nil {
		st = &forwardStats{}
		f.stats[kind] = st
	}
	return st
}

// forwardConfig is the forwarding part of the settings.
type forwardConfig struct {
	stdout    bool
	syslog    string
	syslogTLS bool
	webhook   string
	// strict: targets a guarded tenant's administrator configured; their
	// connections also refuse private networks (internal/netguard).
	strictSyslog, strictWebhook bool
}

func (s *Server) forwardConfig() forwardConfig {
	return forwardConfig{
		stdout:        s.St.SettingBool("audit_forward_stdout"),
		syslog:        strings.TrimSpace(s.St.Setting("audit_forward_syslog")),
		syslogTLS:     !strings.EqualFold(s.St.Setting("audit_forward_syslog_tls"), "false"),
		webhook:       strings.TrimSpace(s.St.Setting("audit_forward_webhook_url")),
		strictSyslog:  s.guardTargets() && !s.isManagedSetting("audit_forward_syslog"),
		strictWebhook: s.guardTargets() && !s.isManagedSetting("audit_forward_webhook_url"),
	}
}

// sinks returns the sinks a record goes to now: the configured ones and those
// removed less than forwardRetireGrace ago (so the record of the settings
// change that removed or redirected a sink still reaches the old destination).
func (f *auditForwarder) sinks(s *Server) []*forwardSink {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopped {
		return nil
	}
	if gen := s.St.SettingsGen(); !f.loaded || gen != f.gen || time.Since(f.at) >= forwardConfigTTL {
		f.loaded, f.gen, f.at = true, gen, time.Now()
		f.reconfigure(s.forwardConfig())
	}
	var out []*forwardSink
	now := time.Now()
	for k := range f.all {
		if k.retireAt.IsZero() || now.Before(k.retireAt) {
			out = append(out, k)
		}
	}
	return out
}

// reconfigure starts, keeps or retires sinks to match cfg. Called with f.mu held.
func (f *auditForwarder) reconfigure(cfg forwardConfig) {
	want := map[string]string{} // kind -> key
	if cfg.stdout {
		want[sinkStdout] = sinkStdout
	}
	if cfg.syslog != "" {
		want[sinkSyslog] = sinkSyslog + "|" + cfg.syslog + "|tls=" + strconv.FormatBool(cfg.syslogTLS)
	}
	if cfg.webhook != "" {
		want[sinkWebhook] = sinkWebhook + "|" + cfg.webhook
	}
	if f.active == nil {
		f.active = map[string]*forwardSink{}
		f.all = map[*forwardSink]bool{}
	}
	for _, kind := range forwardSinkKinds {
		cur, key := f.active[kind], want[kind]
		if cur != nil && cur.key == key {
			continue
		}
		st := f.statsFor(kind)
		if cur != nil {
			delete(f.active, kind)
			cur.retireAt = time.Now().Add(forwardRetireGrace)
			time.AfterFunc(forwardRetireGrace, cur.retire)
		}
		st.enabled.Store(false)
		if key == "" {
			continue
		}
		k, err := newForwardSink(kind, key, cfg, st)
		if err != nil {
			st.fail(forwardErrClass(err))
			continue
		}
		if f.ctx == nil {
			f.ctx, f.cancel = context.WithCancel(context.Background())
		}
		st.enabled.Store(true)
		f.active[kind] = k
		f.all[k] = true
		go k.run(f.ctx, func() {
			f.mu.Lock()
			delete(f.all, k)
			f.mu.Unlock()
		})
	}
}

func newForwardSink(kind, key string, cfg forwardConfig, st *forwardStats) (*forwardSink, error) {
	k := &forwardSink{kind: kind, key: key, stats: st, q: make(chan forwardItem, forwardQueueMax), retired: make(chan struct{}),
		batchMax: forwardBatchMax, backoffMin: forwardBackoffMin, backoffMax: forwardBackoffMax, maxRt: forwardRetireMax}
	switch kind {
	case sinkStdout:
		k.deliver = deliverStdout
	case sinkSyslog:
		addr, err := validateForwardSyslog(cfg.syslog)
		if err != nil {
			return nil, errForwardInvalid
		}
		sl := &syslogSink{addr: addr, tls: cfg.syslogTLS, roots: forwardRootCAs, control: forwardDialControl}
		if cfg.strictSyslog {
			sl.control = netguard.Control
		}
		k.deliver, k.closeFn = sl.deliver, sl.close
	case sinkWebhook:
		u, err := validateForwardWebhook(cfg.webhook)
		if err != nil {
			return nil, errForwardInvalid
		}
		control := forwardDialControl
		if cfg.strictWebhook {
			control = netguard.Control
		}
		wh := &webhookSink{url: u, client: newForwardHTTPClient(control)}
		k.deliver, k.closeFn = wh.deliver, wh.client.CloseIdleConnections
	}
	return k, nil
}

// forward queues one stored record for every sink. It never blocks.
func (f *auditForwarder) forward(s *Server, rec *store.AuditRecord) {
	sinks := f.sinks(s)
	if len(sinks) == 0 {
		return
	}
	cp := *rec
	for _, k := range sinks {
		k.enqueue(forwardItem{rec: &cp})
	}
}

// auditChainHead returns the last seq and hash of the chain (the checkpoint
// when every record was purged).
func (s *Server) auditChainHead() (int64, string) {
	chain := s.St.Repos().AuditChain()
	if seq, hash, err := chain.Last(context.Background()); err == nil {
		return seq, hash
	}
	seq, hash, _ := chain.CheckpointHead(context.Background())
	return seq, hash
}

// heartbeat forwards the current chain head to every sink.
func (f *auditForwarder) heartbeat(s *Server, reason string) {
	f.hbMu.Lock()
	defer f.hbMu.Unlock()
	if reason != "stop" && f.stopping.Load() {
		return
	}
	sinks := f.sinks(s)
	if len(sinks) == 0 {
		return
	}
	seq, hash := s.auditChainHead()
	h := &chainHead{LastSeq: seq, Hash: hash, TS: time.Now().UTC().Format(store.AuditTimeLayout), Reason: reason}
	for _, k := range sinks {
		k.enqueue(forwardItem{head: h})
	}
}

// startHeartbeat forwards the chain head now and every forwardHeartbeatEvery
// until ctx ends. Only the first call starts it.
func (f *auditForwarder) startHeartbeat(s *Server, ctx context.Context) {
	f.hbOnce.Do(func() {
		f.heartbeat(s, "start")
		go func() {
			t := time.NewTicker(forwardHeartbeatEvery)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					f.heartbeat(s, "periodic")
				}
			}
		}()
	})
}

// stop forwards the final chain head, waits (bounded) until the queues are
// delivered, then stops the workers. Records written afterwards are not
// forwarded.
func (f *auditForwarder) stop(s *Server, wait time.Duration) {
	f.hbMu.Lock()
	f.stopping.Store(true)
	f.hbMu.Unlock()
	f.heartbeat(s, "stop")
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		var n int64
		for k := range f.all {
			n += k.inflight.Load()
		}
		f.mu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.mu.Lock()
	f.stopped = true
	if f.cancel != nil {
		f.cancel()
	}
	f.mu.Unlock()
}

// queued is the number of records waiting for a sink kind.
func (f *auditForwarder) queued(kind string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for k := range f.all {
		if k.kind == kind {
			n += int64(len(k.q))
		}
	}
	return n
}

// status is the per-sink state for the status endpoints.
func (f *auditForwarder) status(s *Server) map[string]any {
	f.sinks(s) // apply a changed configuration first
	out := map[string]any{}
	for _, kind := range forwardSinkKinds {
		f.mu.Lock()
		st := f.statsFor(kind)
		f.mu.Unlock()
		st.mu.Lock()
		m := map[string]any{"enabled": st.enabled.Load(), "queued": f.queued(kind), "dropped": st.dropped.Load(),
			"failed": st.failed.Load(), "delivered": st.delivered.Load(), "last_success": nil, "last_error": st.lastErr, "last_error_at": nil}
		if !st.lastOK.IsZero() {
			m["last_success"] = st.lastOK.Format(time.RFC3339)
		}
		if !st.lastErrAt.IsZero() {
			m["last_error_at"] = st.lastErrAt.Format(time.RFC3339)
		}
		st.mu.Unlock()
		out[kind] = m
	}
	return out
}

// ---------- sinks ----------

var stdoutMu sync.Mutex

func deliverStdout(_ context.Context, items []forwardItem) error {
	var buf bytes.Buffer
	for _, it := range items {
		b, err := json.Marshal(it.envelope())
		if err != nil {
			return err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	_, err := forwardStdout.Write(buf.Bytes())
	return err
}

type syslogSink struct {
	addr    string
	tls     bool
	roots   *x509.CertPool
	control func(network, address string, c syscall.RawConn) error
	conn    net.Conn // used only by the sink's worker
}

func (sl *syslogSink) close() {
	if sl.conn != nil {
		sl.conn.Close()
		sl.conn = nil
	}
}

func (sl *syslogSink) deliver(ctx context.Context, items []forwardItem) error {
	if sl.conn == nil {
		dctx, cancel := context.WithTimeout(ctx, forwardTimeout)
		defer cancel()
		var err error
		if sl.tls {
			host, _, _ := net.SplitHostPort(sl.addr)
			d := &tls.Dialer{NetDialer: forwardDialer(sl.control), Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: sl.roots}}
			sl.conn, err = d.DialContext(dctx, "tcp", sl.addr)
		} else {
			sl.conn, err = forwardDialer(sl.control).DialContext(dctx, "tcp", sl.addr)
		}
		if err != nil {
			sl.conn = nil
			return err
		}
	}
	var buf bytes.Buffer
	host, pid := syslogHostname(), os.Getpid()
	for _, it := range items {
		msg, err := json.Marshal(it.envelope())
		if err != nil {
			return err
		}
		buf.Write(syslogFrame(host, pid, it, msg))
	}
	sl.conn.SetWriteDeadline(time.Now().Add(forwardTimeout))
	if _, err := sl.conn.Write(buf.Bytes()); err != nil {
		sl.close() // the next attempt reconnects; the batch is sent again (at least once)
		return err
	}
	return nil
}

// syslogFrame is one RFC 5424 message with octet-counting framing:
// "LEN SP <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID - MSG". Facility 13
// (log audit); severity 4 (warning) for denied or failed outcomes, 6 otherwise.
func syslogFrame(host string, pid int, it forwardItem, msg []byte) []byte {
	sev, ts, msgID := 6, "", "audit"
	if it.head != nil {
		ts, msgID = it.head.TS, "chain_head"
	} else {
		ts = it.rec.TS
		if it.rec.Outcome == "denied" || it.rec.Outcome == "failed" {
			sev = 4
		}
	}
	if ts == "" {
		ts = "-"
	}
	body := fmt.Sprintf("<%d>1 %s %s sendora %d %s - %s", 13*8+sev, ts, host, pid, msgID, msg)
	return []byte(strconv.Itoa(len(body)) + " " + body)
}

// syslogHostname is the HOSTNAME field: printable US-ASCII, at most 255 bytes.
func syslogHostname() string {
	h, _ := os.Hostname()
	h = strings.Map(func(r rune) rune {
		if r < 33 || r > 126 {
			return -1
		}
		return r
	}, h)
	if h == "" {
		return "-"
	}
	if len(h) > 255 {
		h = h[:255]
	}
	return h
}

type webhookSink struct {
	url    string
	client *http.Client
}

type forwardHTTPError struct{ code int }

func (e forwardHTTPError) Error() string { return "webhook answered " + strconv.Itoa(e.code) }

func (wh *webhookSink) deliver(ctx context.Context, items []forwardItem) error {
	token, err := forwardWebhookToken()
	if err != nil {
		return err
	}
	batch := make([]any, 0, len(items))
	for _, it := range items {
		batch = append(batch, it.envelope())
	}
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, 2*forwardTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, wh.url, bytes.NewReader(body))
	if err != nil {
		return errForwardInvalid
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "sendora-audit-forward")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := wh.client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return forwardHTTPError{resp.StatusCode}
	}
	return nil
}

// forwardWebhookToken reads the bearer token ("" when no file is configured).
// The file must pass the same permission check as every other secret file.
func forwardWebhookToken() (string, error) {
	p := os.Getenv(forwardTokenEnv)
	if p == "" {
		return "", nil
	}
	tok, err := readSecretToken(forwardTokenEnv, p)
	if err != nil {
		log.Printf("audit forwarding: %v", err)
		return "", errForwardToken
	}
	return tok, nil
}

// readSecretToken reads a one-line token from a secret file that passes
// checkSecretFile. Messages name the variable, never the contents.
func readSecretToken(varName, p string) (string, error) {
	if err := checkSecretFile(varName, p); err != nil {
		return "", err
	}
	f, err := os.Open(p)
	if err != nil {
		return "", fmt.Errorf("%s: file cannot be opened", varName)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, configMaxFileBytes+1))
	if err != nil || len(b) > configMaxFileBytes {
		return "", fmt.Errorf("%s: unreadable or larger than 64 KiB", varName)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" || strings.IndexFunc(tok, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("%s: the file must hold one non-empty line", varName)
	}
	return tok, nil
}

// ---------- target checks ----------

// blockedForwardAddr: link-local (cloud metadata lives there), unspecified,
// multicast and the metadata addresses outside link-local are refused.
// Loopback and private ranges are allowed (local relays, internal collectors).
func blockedForwardAddr(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() || a.IsMulticast() {
		return true
	}
	for _, p := range metadataPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// forwardDialControl checks the address about to be connected, after DNS.
func forwardDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || blockedForwardAddr(ip) {
		return fmt.Errorf("%w: %s", errBlockedTarget, host)
	}
	return nil
}

func forwardDialer(control func(network, address string, c syscall.RawConn) error) *net.Dialer {
	if control == nil {
		control = forwardDialControl
	}
	return &net.Dialer{Timeout: forwardTimeout, Control: control}
}

func newForwardHTTPClient(control func(network, address string, c syscall.RawConn) error) *http.Client {
	tr := &http.Transport{
		Proxy:                 nil, // the guard must see the real destination
		DialContext:           forwardDialer(control).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: forwardRootCAs},
		TLSHandshakeTimeout:   forwardTimeout,
		ResponseHeaderTimeout: forwardTimeout,
		MaxIdleConns:          2,
		IdleConnTimeout:       90 * time.Second,
	}
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// validateForwardSyslog checks host:port ("" = off).
func validateForwardSyslog(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	host, port, err := net.SplitHostPort(v)
	p, ok := parseStrictInt(port, 1, 65535)
	if err != nil || host == "" || !ok || len(host) > 253 || strings.ContainsAny(host, " /\\@") || !plainText(host, 253) {
		return "", fmt.Errorf("audit_forward_syslog must be host:port")
	}
	if ip, err := netip.ParseAddr(host); err == nil && blockedForwardAddr(ip) {
		return "", fmt.Errorf("audit log forwarding to link-local or cloud metadata addresses is not allowed")
	}
	return net.JoinHostPort(host, strconv.Itoa(p)), nil
}

// validateForwardWebhook checks the webhook URL ("" = off): https, or http to
// a loopback address; no credentials or fragment in the URL.
func validateForwardWebhook(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || !plainText(v, 2000) ||
		(u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname()))) {
		return "", fmt.Errorf("audit_forward_webhook_url must be an https:// URL without credentials (http only for localhost)")
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && blockedForwardAddr(ip) {
		return "", fmt.Errorf("audit log forwarding to link-local or cloud metadata addresses is not allowed")
	}
	return v, nil
}

// forwardErrClass names an error without its details (no address, URL or token).
func forwardErrClass(err error) string {
	var he forwardHTTPError
	var ne net.Error
	var ue x509.UnknownAuthorityError
	var he2 x509.HostnameError
	var ce *tls.CertificateVerificationError
	var re tls.RecordHeaderError
	var oe *net.OpError
	switch {
	case errors.Is(err, errBlockedTarget):
		return "blocked_target"
	case errors.Is(err, errForwardToken):
		return "token_file"
	case errors.Is(err, errForwardInvalid):
		return "invalid_target"
	case errors.As(err, &he):
		return "http_status_" + strconv.Itoa(he.code)
	case errors.As(err, &ce), errors.As(err, &ue), errors.As(err, &he2), errors.As(err, &re):
		return "tls"
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.As(err, &oe) && oe.Op == "dial":
		return "connect"
	}
	return "write"
}
