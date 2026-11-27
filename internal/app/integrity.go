// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sendora-app/sendora/internal/filecrypt"
	"github.com/sendora-app/sendora/internal/keyring"
	"github.com/sendora-app/sendora/internal/store"
)

// Three preparations bound temporary disk usage to three times the per-response limit.
// Snapshots are private and removed after serving; no source descriptors are retained.
var integritySlots = make(chan struct{}, 3)
var errIntegrity = errors.New("file integrity check failed")

// decryptFailureInterval limits file_decrypt_failed audit records to one per
// file per interval, so a client repeating requests (or a media player
// issuing range after range) for a modified file cannot flood the audit log.
const decryptFailureInterval = 10 * time.Minute

type decryptFailureKey struct {
	s  *Server
	id int64
}

var decryptFailures = struct {
	sync.Mutex
	at map[decryptFailureKey]time.Time
}{at: map[decryptFailureKey]time.Time{}}

// noteDecryptFailure records that a stored file could not be decrypted or
// failed authentication (row id only), at most once per file per interval.
func (s *Server) noteDecryptFailure(fileID int64) {
	decryptFailures.Lock()
	now := time.Now()
	if len(decryptFailures.at) > 4096 {
		for k, t := range decryptFailures.at {
			if now.Sub(t) >= decryptFailureInterval {
				delete(decryptFailures.at, k)
			}
		}
	}
	k := decryptFailureKey{s, fileID}
	last, seen := decryptFailures.at[k]
	allowed := !seen || now.Sub(last) >= decryptFailureInterval
	if allowed {
		decryptFailures.at[k] = now
	}
	decryptFailures.Unlock()
	if allowed {
		s.auditDecryptFailed(fileID)
	}
}

// corruptWatch reports an authentication failure seen while streaming an
// encrypted file (preview and range responses fail mid-stream, after the
// headers were sent, so this is the only place it can be noticed).
type corruptWatch struct {
	io.ReadSeeker
	onCorrupt func()
}

func (c corruptWatch) Read(p []byte) (int, error) {
	n, err := c.ReadSeeker.Read(p)
	if err != nil && errors.Is(err, filecrypt.ErrCorrupt) {
		c.onCorrupt()
	}
	return n, err
}

// One client address may hold at most two of the three verified-download slots:
// a person can download two files at once, while a single slow client can never
// block every download on the instance.
const downloadSlotsPerClient = 2

var (
	downloadClientsMu sync.Mutex
	downloadClients   = map[string]int{}
)

func acquireDownloadClient(ctx context.Context, client string) bool {
	deadline := time.Now().Add(5 * time.Second)
	for {
		downloadClientsMu.Lock()
		if downloadClients[client] < downloadSlotsPerClient {
			downloadClients[client]++
			downloadClientsMu.Unlock()
			return true
		}
		downloadClientsMu.Unlock()
		if time.Now().After(deadline) || ctx.Err() != nil {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func releaseDownloadClient(client string) {
	downloadClientsMu.Lock()
	if downloadClients[client] <= 1 {
		delete(downloadClients, client)
	} else {
		downloadClients[client]--
	}
	downloadClientsMu.Unlock()
}

// Verified snapshots are shared by the requests of one client for the same
// files: a download manager opening several connections, or a client resuming
// with Range requests, uses one snapshot and one set of slots instead of one
// per request. A snapshot is reference counted and removed when its last
// reader ends.
//
// Hold limit: a snapshot (preparation plus transfer) may hold its slots for
// slotHoldMax. When that is reached it is closed only if no reader made
// progress during the last snapshotProgressCheck; while bytes keep flowing it
// is checked again every snapshotProgressCheck. Stalled and very slow
// transfers are already ended by the idle and minimum-rate guards of
// idleResponseWriter, so this only stops a snapshot that is held but unused.
type snapshotKey struct {
	s       *Server
	client  string
	shareID int64
	files   string // ids, sizes and checksums: a changed file set is a new snapshot
}

type snapshot struct {
	key      snapshotKey
	ready    chan struct{} // closed when preparation ended
	err      error         // preparation error, valid after ready
	file     *os.File      // nil unless preparation succeeded
	size     int64
	modTime  time.Time
	checksum string
	free     func()       // gives back the file and the slots; guarded by snapshotsMu
	timer    *time.Timer  // guarded by snapshotsMu
	lastRead atomic.Int64 // unix nanoseconds of the last read progress, 0 = none
	refs     int          // guarded by snapshotsMu
	closed   bool         // guarded by snapshotsMu: no new readers may join
}

var (
	snapshotsMu sync.Mutex
	snapshots   = map[snapshotKey]*snapshot{}
)

// snapshotProgressCheck is how often a snapshot past slotHoldMax is checked
// for reader progress. Default: 1 minute.
var snapshotProgressCheck = time.Minute

func snapshotFilesKey(files []FileInfo) string {
	var b strings.Builder
	for _, f := range files {
		fmt.Fprintf(&b, "%d:%d:%s;", f.ID, f.Size, f.SHA256)
	}
	return b.String()
}

// snapshotReader is one reader's own position in a shared snapshot.
type snapshotReader struct {
	*io.SectionReader
	sn *snapshot
}

func (r *snapshotReader) Read(p []byte) (int, error) {
	n, err := r.SectionReader.Read(p)
	if n > 0 {
		r.sn.lastRead.Store(time.Now().UnixNano())
	}
	return n, err
}

// ModTime is the time the snapshot was written.
func (r *snapshotReader) ModTime() time.Time { return r.sn.modTime }

// prepareClientDownload returns a reader of a verified snapshot of files for
// one client, its SHA-256 and a release function the caller must call exactly
// once (defer it; further calls do nothing). A new snapshot takes a per-share
// slot (downloadSlotsPerShare), a per-client slot (downloadSlotsPerClient)
// and a global slot (integritySlots); a request of the same client for the
// same files joins the existing snapshot instead.
func (s *Server) prepareClientDownload(ctx context.Context, client string, shareID int64, files []FileInfo) (*snapshotReader, string, func(), error) {
	key := snapshotKey{s: s, client: client, shareID: shareID, files: snapshotFilesKey(files)}
	for attempt := 0; ; attempt++ {
		snapshotsMu.Lock()
		sn := snapshots[key]
		if sn != nil && !sn.closed {
			sn.refs++
			snapshotsMu.Unlock()
			select {
			case <-sn.ready:
			case <-ctx.Done():
				dropSnapshot(sn)
				return nil, "", nil, errDownloadBusy
			}
			if sn.err != nil {
				dropSnapshot(sn)
				// The request that prepared it went away: prepare anew.
				if (errors.Is(sn.err, context.Canceled) || errors.Is(sn.err, context.DeadlineExceeded)) && ctx.Err() == nil && attempt < 3 {
					continue
				}
				return nil, "", nil, sn.err
			}
			return sn.reader(), sn.checksum, onceRelease(sn), nil
		}
		sn = &snapshot{key: key, ready: make(chan struct{}), refs: 1}
		snapshots[key] = sn
		snapshotsMu.Unlock()
		if err := s.buildSnapshot(ctx, sn, client, shareID, files); err != nil {
			snapshotsMu.Lock()
			sn.err, sn.closed = err, true
			if snapshots[key] == sn {
				delete(snapshots, key)
			}
			snapshotsMu.Unlock()
			close(sn.ready)
			dropSnapshot(sn)
			return nil, "", nil, err
		}
		close(sn.ready)
		return sn.reader(), sn.checksum, onceRelease(sn), nil
	}
}

func (sn *snapshot) reader() *snapshotReader {
	return &snapshotReader{SectionReader: io.NewSectionReader(sn.file, 0, sn.size), sn: sn}
}

func onceRelease(sn *snapshot) func() {
	var once sync.Once
	return func() { once.Do(func() { dropSnapshot(sn) }) }
}

// buildSnapshot takes the slots and writes the verified snapshot into sn.
func (s *Server) buildSnapshot(ctx context.Context, sn *snapshot, client string, shareID int64, files []FileInfo) error {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, slotHoldMax)
	defer cancel()
	if !acquireDownloadShare(ctx, shareID) {
		return errDownloadBusy
	}
	if !acquireDownloadClient(ctx, client) {
		releaseDownloadShare(shareID)
		return errDownloadBusy
	}
	f, sum, err := s.prepareDownload(ctx, files)
	if err != nil {
		releaseDownloadClient(client)
		releaseDownloadShare(shareID)
		return err
	}
	free := func() {
		f.Close()
		os.Remove(f.Name())
		<-integritySlots
		releaseDownloadClient(client)
		releaseDownloadShare(shareID)
	}
	st, err := f.Stat()
	if err != nil {
		free()
		return err
	}
	sn.file, sn.size, sn.modTime, sn.checksum = f, st.Size(), st.ModTime(), sum
	snapshotsMu.Lock()
	sn.free = free
	sn.timer = time.AfterFunc(max(slotHoldMax-time.Since(start), time.Millisecond), sn.holdCheck)
	snapshotsMu.Unlock()
	return nil
}

// holdCheck runs once slotHoldMax is reached: it closes a snapshot nobody read
// from during the last snapshotProgressCheck (its readers then fail and
// release it), and otherwise checks again later.
func (sn *snapshot) holdCheck() {
	snapshotsMu.Lock()
	defer snapshotsMu.Unlock()
	if sn.free == nil {
		return // already released
	}
	if last := sn.lastRead.Load(); last != 0 && time.Since(time.Unix(0, last)) < snapshotProgressCheck {
		sn.timer = time.AfterFunc(snapshotProgressCheck, sn.holdCheck)
		return
	}
	sn.closed = true
	if snapshots[sn.key] == sn {
		delete(snapshots, sn.key)
	}
	sn.file.Close()
}

// dropSnapshot ends one reference; the last one removes the snapshot and
// gives back its slots.
func dropSnapshot(sn *snapshot) {
	snapshotsMu.Lock()
	sn.refs--
	if sn.refs > 0 {
		snapshotsMu.Unlock()
		return
	}
	sn.closed = true
	if snapshots[sn.key] == sn {
		delete(snapshots, sn.key)
	}
	timer, free := sn.timer, sn.free
	sn.timer, sn.free = nil, nil
	snapshotsMu.Unlock()
	if timer != nil {
		timer.Stop()
	}
	if free != nil {
		free()
	}
}

var errDownloadBusy = errors.New("verified download preparation busy")

// slotHoldMax is how long a verified snapshot may hold its slots before it is
// closed, unless its readers are still making progress (see holdCheck).
// Default: 2 hours.
var slotHoldMax = 2 * time.Hour

// downloadSlotsPerShare caps concurrent snapshots of a single share (requests
// of one client for the same files share one snapshot). Default: 2 of the 3
// global slots, so one share cannot take every slot of the instance.
var downloadSlotsPerShare = 2

var (
	downloadSharesMu sync.Mutex
	downloadShares   = map[int64]int{}
)

func acquireDownloadShare(ctx context.Context, shareID int64) bool {
	deadline := time.Now().Add(5 * time.Second)
	for {
		downloadSharesMu.Lock()
		if downloadShares[shareID] < downloadSlotsPerShare {
			downloadShares[shareID]++
			downloadSharesMu.Unlock()
			return true
		}
		downloadSharesMu.Unlock()
		if time.Now().After(deadline) || ctx.Err() != nil {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func releaseDownloadShare(shareID int64) {
	downloadSharesMu.Lock()
	if downloadShares[shareID] <= 1 {
		delete(downloadShares, shareID)
	} else {
		downloadShares[shareID]--
	}
	downloadSharesMu.Unlock()
}

// Free-space guard: refuse a snapshot unless the data directory has room for it
// plus a margin (ZIP framing, other temporary files). freeSpaceFn is injectable.
const snapshotSpaceMargin = 64 << 20

var freeSpaceFn = freeDiskSpace
var errInsufficientSpace = errors.New("not enough free disk space to prepare a verified download")

var errSnapshotLimit = errors.New("verified download exceeds preparation limit")

func validSHA256(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && s == strings.ToLower(s)
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

type boundedWriter struct {
	w         io.Writer
	remaining int64
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, errSnapshotLimit
	}
	n, err := w.w.Write(p)
	w.remaining -= int64(n)
	return n, err
}

func snapshotLimit() int64 {
	// A single ZIP may need slightly more disk than the total source size.
	if n, err := strconv.ParseInt(os.Getenv("SENDORA_VERIFIED_DOWNLOAD_MAX_BYTES"), 10, 64); err == nil && n > 0 {
		return n
	}
	return 16 << 30
}

// copyVerifiedSource verifies the bytes actually copied, eliminating the gap
// between hashing a mutable source and streaming it. Legacy files get a first
// baseline only; that cannot establish what their original uploader sent.
func (s *Server) copyVerifiedSource(ctx context.Context, dst io.Writer, f FileInfo) error {
	in, _, err := s.openStoredFile(ctx, f)
	if err != nil {
		return err
	}
	defer in.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, h), contextReader{ctx, io.LimitReader(in, f.Size+1)})
	if err != nil {
		// A chunk that fails authentication is a modified file, not a passing
		// server problem: answer 409 and record it like a header failure.
		if errors.Is(err, filecrypt.ErrCorrupt) {
			s.noteDecryptFailure(f.ID)
			return errIntegrity
		}
		return err
	}
	checksum := hex.EncodeToString(h.Sum(nil))
	if n != f.Size || (f.SHA256 != "" && checksum != f.SHA256) {
		return errIntegrity
	}
	if f.SHA256 == "" {
		if err = s.St.Repos().Shares().BaselineFileChecksum(context.Background(), f.ID, checksum); err != nil {
			return err
		}
		var baseline string
		if baseline, err = s.St.Repos().Shares().FileChecksum(context.Background(), f.ID); err != nil {
			return err
		}
		if baseline != checksum {
			return errIntegrity
		}
	}
	return nil
}

// prepareDownload returns a complete, verified, private snapshot. Nothing is
// served or counted until all sources (and ZIP finalization) have succeeded.
func (s *Server) prepareDownload(ctx context.Context, files []FileInfo) (*os.File, string, error) {
	wait := time.NewTimer(5 * time.Second)
	defer wait.Stop()
	select {
	case integritySlots <- struct{}{}:
	case <-ctx.Done():
		return nil, "", ctx.Err()
	case <-wait.C:
		return nil, "", errDownloadBusy
	}
	retained := false
	defer func() {
		if !retained {
			<-integritySlots
		}
	}()
	limit := snapshotLimit()
	var total int64
	for _, f := range files {
		if f.Size < 0 || f.Size > limit-total {
			return nil, "", errSnapshotLimit
		}
		total += f.Size
	}
	if free, ferr := freeSpaceFn(s.St.DataDir); ferr == nil {
		if uint64(total)+snapshotSpaceMargin > free {
			return nil, "", errInsufficientSpace
		}
	}
	out, err := os.CreateTemp(s.St.DataDir, ".verified-download-*")
	if err != nil {
		return nil, "", err
	}
	ok := false
	defer func() {
		if !ok {
			out.Close()
			os.Remove(out.Name())
		}
	}()
	h := sha256.New()
	writer := &boundedWriter{w: io.MultiWriter(out, h), remaining: limit}
	if len(files) == 1 {
		err = s.copyVerifiedSource(ctx, writer, files[0])
	} else {
		zw := zip.NewWriter(writer)
		for _, f := range files {
			if err = validateArchivePath(f.FullPath); err != nil {
				break
			}
			// Stable metadata; digest covers the exact archive, not only its members.
			hdr := &zip.FileHeader{Name: f.FullPath, Method: zip.Store}
			hdr.Modified = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
			var entry io.Writer
			entry, err = zw.CreateHeader(hdr)
			if err == nil {
				err = s.copyVerifiedSource(ctx, entry, f)
			}
			if err != nil {
				break
			}
		}
		if err == nil {
			err = zw.Close()
		}
	}
	if err != nil {
		return nil, "", err
	}
	if _, err = out.Seek(0, io.SeekStart); err != nil {
		return nil, "", err
	}
	ok = true
	retained = true
	return out, hex.EncodeToString(h.Sum(nil)), nil
}

func setDownloadChecksum(w http.ResponseWriter, checksum string) {
	b, _ := hex.DecodeString(checksum)
	// Representation digest remains a full-file digest even for native Range requests.
	w.Header().Set("Repr-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(b)+":")
	w.Header().Set("X-Checksum-SHA256", checksum)
	w.Header().Set("Cache-Control", "no-store")
}

func integrityError(w http.ResponseWriter, err error) {
	if os.IsNotExist(err) {
		jerr(w, 404, "file missing")
		return
	}
	if errors.Is(err, errIntegrity) {
		jerr(w, http.StatusConflict, "file integrity check failed; download blocked")
		return
	}
	if errors.Is(err, store.ErrLegacyFile) || errors.Is(err, keyring.ErrKeyRetired) {
		// Not corruption: the file is under a key the application will not
		// open (old platform key, retired version). The administrator converts it.
		jerr(w, http.StatusServiceUnavailable, "this file is under an old encryption key and is unavailable until an administrator re-encrypts the stored files")
		return
	}
	if errors.Is(err, errInsufficientSpace) {
		w.Header().Set("Retry-After", "300")
		jerr(w, http.StatusInsufficientStorage, "not enough free disk space on the server to prepare this download; try again later")
		return
	}
	if errors.Is(err, errDownloadBusy) {
		w.Header().Set("Retry-After", "10")
		jerr(w, http.StatusServiceUnavailable, "too many downloads are being prepared; try again shortly")
		return
	}
	if errors.Is(err, errSnapshotLimit) {
		jerr(w, http.StatusRequestEntityTooLarge, errSnapshotLimit.Error())
		return
	}
	jerr(w, http.StatusServiceUnavailable, "verified download temporarily unavailable")
}

// rangeNeverSatisfiable reports whether a Range header would be answered with
// 416 by http.ServeContent, so the request can be refused before any snapshot
// work. size < 0 means unknown (ZIP): only the syntax is checked. An If-Range
// header makes the server ignore a bad range, so it disables the shortcut.
func rangeNeverSatisfiable(r *http.Request, size int64) bool {
	h := r.Header.Get("Range")
	if h == "" || r.Header.Get("If-Range") != "" {
		return false
	}
	const prefix = "bytes="
	if !strings.HasPrefix(h, prefix) {
		return true
	}
	anyOK := false
	for _, spec := range strings.Split(h[len(prefix):], ",") {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		a, b, ok := strings.Cut(spec, "-")
		if !ok {
			return true
		}
		a, b = strings.TrimSpace(a), strings.TrimSpace(b)
		if a == "" {
			n, err := strconv.ParseInt(b, 10, 64)
			if err != nil || n < 0 {
				return true
			}
			if n > 0 || size < 0 {
				anyOK = true
			}
			continue
		}
		start, err := strconv.ParseInt(a, 10, 64)
		if err != nil || start < 0 {
			return true
		}
		if b != "" {
			end, err := strconv.ParseInt(b, 10, 64)
			if err != nil || start > end {
				return true
			}
		}
		if size >= 0 && start >= size {
			continue
		}
		anyOK = true
	}
	return !anyOK
}

func rejectRange(w http.ResponseWriter, size int64) {
	if size >= 0 {
		w.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(size, 10))
	}
	jerr(w, http.StatusRequestedRangeNotSatisfiable, "invalid range")
}
