// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/sendora-app/sendora/internal/barrier"
	"github.com/sendora-app/sendora/internal/ports"
)

// Idempotency keys (docs/cluster/DESIGN.md 4.1, D29), in every flavour.
//
// A mutating request may carry Idempotency-Key (a UUID the client creates per
// user action). Sendora's own web UI always sends one; third-party clients
// may: a request without a key runs once and is never retried automatically.
//
// The key is claimed in a transaction of its own before the handler runs;
// only a clean commit (ports.Committed) lets the handler run. A successful
// response is stored, encrypted, and replayed for a retry with the same key
// and the same request (method, path and canonical body); a different request
// with that key is refused (422). A retry while the first request still runs
// gets 409 with Retry-After. Before a replay the server commits
// MarkReplayed: only a clean outcome proves the stored row is replicated
// (a replay on a former primary could otherwise confirm a row a failover
// removes); otherwise 503 with Sendora-Outcome: unknown. Failed requests
// (status >= 400) release the key, so a retry runs again. Keys expire after
// 24 hours (jobs).
//
// Limits of this phase: the key is recorded next to, not inside, the
// handler's business transaction, so a process that dies between the
// business commit and storing the response leaves an in-progress key whose
// lease (idempotencyLease) then expires and lets a retry run again. Moving
// the key into the business transaction comes with the handlers' move to
// transaction-scoped repositories (phase 3).

const (
	idempotencyHeader   = "Idempotency-Key"
	idempotencyLease    = 2 * time.Minute
	idempotencyTTL      = 24 * time.Hour
	idempotencyMaxBody  = 1 << 20  // request bodies hashed in memory
	idempotencyMaxStore = 64 << 10 // larger responses are replayed as a marker
)

// idempotencyExempt are mutating routes that never use keys: chunk uploads
// have their own per-chunk idempotency, and their bodies are streamed.
var idempotencyExempt = map[string]bool{
	"PATCH /api/uploads/{id}/files/{idx}": true,
}

// validIdempotencyKey accepts 1-128 visible ASCII characters without spaces.
func validIdempotencyKey(k string) bool {
	if k == "" || len(k) > 128 {
		return false
	}
	for i := 0; i < len(k); i++ {
		if k[i] <= ' ' || k[i] > '~' {
			return false
		}
	}
	return true
}

func (s *Server) idempotencyKeys() (mac, enc []byte, err error) {
	if mac, err = hkdf.Key(sha256.New, s.Secret, nil, "sendora/v1/idempotency-key", 32); err != nil {
		return nil, nil, err
	}
	enc, err = hkdf.Key(sha256.New, s.Secret, nil, "sendora/v1/idempotency-response", 32)
	return mac, enc, err
}

// canonicalBody re-encodes a JSON body with sorted keys and no insignificant
// white space; other bodies are used as they are.
func canonicalBody(b []byte) []byte {
	var v any
	if len(bytes.TrimSpace(b)) == 0 || json.Unmarshal(b, &v) != nil {
		return b
	}
	out, err := json.Marshal(v)
	if err != nil {
		return b
	}
	return out
}

// storedResponse is the replayable part of a response.
type storedResponse struct {
	Status      int    `json:"s"`
	ContentType string `json:"ct,omitempty"`
	Body        []byte `json:"b,omitempty"`
	Truncated   bool   `json:"t,omitempty"`
}

func sealResponse(key []byte, aad string, r storedResponse) ([]byte, error) {
	plain, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, []byte(aad)), nil
}

func openResponse(key []byte, aad string, sealed []byte) (storedResponse, error) {
	var r storedResponse
	block, err := aes.NewCipher(key)
	if err != nil {
		return r, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return r, err
	}
	if len(sealed) < gcm.NonceSize() {
		return r, errors.New("stored response too short")
	}
	plain, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], []byte(aad))
	if err != nil {
		return r, err
	}
	return r, json.Unmarshal(plain, &r)
}

// outcomeUnknown answers a request whose commit outcome is unknown (design
// 4.1): the client retries with the same idempotency key.
func outcomeUnknown(w http.ResponseWriter) {
	w.Header().Set("Sendora-Outcome", "unknown")
	w.Header().Set("Retry-After", "5")
	jerr(w, http.StatusServiceUnavailable, "the outcome of this request is not known yet; retry it with the same Idempotency-Key")
}

// idemRecorder passes the response through and keeps a copy of its start.
type idemRecorder struct {
	http.ResponseWriter
	status   int
	buf      bytes.Buffer
	overflow bool
}

func (w *idemRecorder) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *idemRecorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if !w.overflow {
		if w.buf.Len()+len(b) > idempotencyMaxStore {
			w.overflow = true
			w.buf.Reset()
		} else {
			w.buf.Write(b)
		}
	}
	return w.ResponseWriter.Write(b)
}

func (w *idemRecorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *idemRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// idempotent applies idempotency keys to the mutating requests it wraps.
func (s *Server) idempotent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get(idempotencyHeader)
		if key == "" || !isMutating(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		pattern := ""
		if rc := chi.RouteContext(r.Context()); rc != nil {
			pattern = rc.RoutePattern()
		}
		if idempotencyExempt[r.Method+" "+pattern] {
			w.Header().Set("Sendora-Idempotency", "unsupported")
			next.ServeHTTP(w, r)
			return
		}
		if !validIdempotencyKey(key) {
			jerr(w, http.StatusBadRequest, "invalid Idempotency-Key")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, idempotencyMaxBody+1))
		if err != nil {
			jerr(w, http.StatusBadRequest, "unreadable request body")
			return
		}
		if len(body) > idempotencyMaxBody {
			// Too large to hash in memory: runs once, without a key.
			r.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(body), r.Body), r.Body}
			w.Header().Set("Sendora-Idempotency", "unsupported")
			next.ServeHTTP(w, r)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		macKey, encKey, err := s.idempotencyKeys()
		if err != nil {
			jerr(w, http.StatusInternalServerError, "internal error")
			return
		}
		scope := "a:" + r.URL.Path // anonymous routes: the share or invitation in the path
		if u := s.ctxUser(r); u != nil {
			scope = "u:" + strconv.FormatInt(u.ID, 10)
		}
		m := hmac.New(sha256.New, macKey)
		m.Write([]byte(key))
		keyHash := hex.EncodeToString(m.Sum(nil))
		h := sha256.New()
		for _, part := range [][]byte{[]byte(r.Method), []byte(r.URL.Path), []byte(r.URL.RawQuery), canonicalBody(body)} {
			h.Write(part)
			h.Write([]byte{0})
		}
		requestHash := hex.EncodeToString(h.Sum(nil))
		aad := scope + "\x00" + keyHash

		ctx := r.Context()
		now := time.Now()
		var claim ports.IdempotencyClaim
		tx, err := s.St.Repos().Begin(ctx)
		if err == nil {
			if claim, err = tx.Idempotency().Claim(ctx, scope, keyHash, requestHash, now, now.Add(idempotencyLease)); err != nil {
				tx.Rollback()
			} else {
				err = tx.Commit()
			}
		}
		if err != nil {
			if ports.OutcomeOf(err) == ports.Unknown {
				barrier.ReportUnknown("idempotency_claim", keyHash, err)
				outcomeUnknown(w)
				return
			}
			log.Printf("idempotency claim: %v", err)
			jerr(w, http.StatusInternalServerError, "internal error")
			return
		}
		switch claim.State {
		case ports.IdempotencyMismatch:
			jerr(w, http.StatusUnprocessableEntity, "this Idempotency-Key was used for a different request")
			return
		case ports.IdempotencyInProgress:
			w.Header().Set("Retry-After", "2")
			w.Header().Set("Sendora-Idempotency", "in-progress")
			jerr(w, http.StatusConflict, "a request with this Idempotency-Key is still running; retry later")
			return
		case ports.IdempotencyDone:
			s.replayIdempotent(w, r, scope, keyHash, aad, encKey, claim)
			return
		}

		rec := &idemRecorder{ResponseWriter: w}
		completed := false
		defer func() {
			if completed {
				return
			}
			// The handler failed (or panicked): let a retry run again.
			if err := s.St.Repos().Idempotency().Release(context.WithoutCancel(ctx), scope, keyHash); err != nil {
				log.Printf("idempotency release: %v", err)
			}
		}()
		next.ServeHTTP(rec, r)
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		if status >= 400 || len(rec.Header().Values("Set-Cookie")) > 0 {
			return // failed, or carries a cookie that must not be replayed
		}
		sr := storedResponse{Status: status, ContentType: rec.Header().Get("Content-Type")}
		if rec.overflow {
			sr.Truncated = true
		} else {
			sr.Body = rec.buf.Bytes()
		}
		sealed, err := sealResponse(encKey, aad, sr)
		if err == nil {
			err = s.St.Repos().Idempotency().Complete(context.WithoutCancel(ctx), scope, keyHash, status, sealed)
		}
		if err != nil {
			log.Printf("idempotency complete: %v", err)
			return
		}
		completed = true
	})
}

// replayIdempotent answers a retry of a completed request with the stored
// response, after the replay barrier.
func (s *Server) replayIdempotent(w http.ResponseWriter, r *http.Request, scope, keyHash, aad string, encKey []byte, claim ports.IdempotencyClaim) {
	ctx := r.Context()
	tx, err := s.St.Repos().Begin(ctx)
	if err == nil {
		var n int64
		if n, err = tx.Idempotency().MarkReplayed(ctx, scope, keyHash, time.Now()); err != nil || n != 1 {
			tx.Rollback()
			if err == nil {
				err = errors.New("completed key vanished")
			}
		} else {
			err = tx.Commit()
		}
	}
	if err != nil {
		if ports.OutcomeOf(err) == ports.Unknown {
			barrier.ReportUnknown("idempotency_replay", keyHash, err)
			outcomeUnknown(w)
			return
		}
		log.Printf("idempotency replay: %v", err)
		jerr(w, http.StatusInternalServerError, "internal error")
		return
	}
	sr, err := openResponse(encKey, aad, claim.Response)
	if err != nil {
		log.Printf("idempotency replay: stored response unreadable: %v", err)
		jerr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if st := auditReqFrom(ctx); st != nil {
		u := s.ctxUser(r)
		pattern := ""
		if rc := chi.RouteContext(ctx); rc != nil {
			pattern = rc.RoutePattern()
		}
		e := auditEntry{Category: routeCategory(pattern), Action: "request_replayed", Target: r.Method + " " + pattern, Outcome: "ok",
			Detail: "status=" + strconv.Itoa(sr.Status) + " (Idempotency-Key retry; the request ran once)", ActorRole: roleOfUser(u)}
		if u != nil {
			e.ActorID, e.ActorName = u.ID, u.Username
		}
		_ = s.auditWrite(e, st)
	}
	w.Header().Set("Sendora-Idempotency", "replayed")
	if sr.Truncated {
		jout(w, sr.Status, map[string]any{"idempotent_replay": true})
		return
	}
	if sr.ContentType != "" {
		w.Header().Set("Content-Type", sr.ContentType)
	}
	w.WriteHeader(sr.Status)
	w.Write(sr.Body)
}
