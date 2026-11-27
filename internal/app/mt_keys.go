// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sendora-app/sendora/internal/keyops"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/ports"
)

// Operator-forced key rotation (docs/cluster/DESIGN.md 6.4 "Forced rotation",
// D43, D46). The platform administrator asks for a rotation of a tenant's
// data keys, for one tenant or for every platform-managed tenant. Nothing new
// runs: the request is the same key job a tenant administrator creates (a row
// in the tenant's own database, executed by the controller leader through the
// existing key-job path), with the platform administrator as its actor. The
// operator never sees key material, versions' contents or tenant data, only
// the overview below.

// operatorPurposes are the purposes the operator may force: the ones that
// protect tenant content. audit-mac cannot be rotated at all and audit-enc
// only versions the audit text of new records (nothing is rewritten), so the
// screen does not offer it.
var operatorPurposes = []string{"data", "index", "secrets", "files"}

// Key states of a tenant as the operator sees them.
const (
	keyStateOK          = "ok"
	keyStateLocked      = "locked"      // tenant-managed key not (fully) unlocked on the controllers
	keyStateUnavailable = "unavailable" // suspended, not open, or the keyring does not verify
	keyStateSkipped     = "tenant_managed"
)

// KeyOutcome is the result of a forced rotation request for one purpose.
type KeyOutcome struct {
	Purpose string `json:"purpose"`
	Result  string `json:"result"` // queued, busy or failed
	JobID   int64  `json:"job_id,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// KeyOverview is the operator's short view of the tenant's keys (never key
// material).
func (s *Server) KeyOverview(ctx context.Context) (keyops.Overview, error) {
	e, release, err := s.keyEngine(ctx, false)
	if err != nil {
		return keyops.Overview{}, err
	}
	defer release()
	return e.Overview(ctx)
}

// ControllersLocked reports whether this tenant is tenant-managed and not
// unlocked on every controller (a key job runs on the leader, which may be a
// controller that never received the key).
func (s *Server) ControllersLocked(ctx context.Context) bool {
	if s.kek == nil || s.kek.svc == nil {
		return false
	}
	mode, _ := s.kek.state()
	if mode != platform.KEKTenant {
		return false
	}
	_, _, unlocked, total, err := s.kek.svc.Status(ctx, s.kek.tenantID)
	return err != nil || unlocked < total || total == 0
}

// ForceKeyJobs creates a rotation job per purpose on behalf of a platform
// administrator and tells the controller. A purpose with an unfinished job is
// reported "busy" and left alone.
func (s *Server) ForceKeyJobs(ctx context.Context, admin string, purposes []string) ([]KeyOutcome, error) {
	if !s.keysEnabled() {
		return nil, keyops.ErrNotEnabled
	}
	jobs, err := s.St.Repos().ColumnKeys().KeyJobs(ctx, keyJobLimit)
	if err != nil {
		return nil, err
	}
	var out []KeyOutcome
	queued := false
	for _, p := range purposes {
		if keyops.OpenJob(jobs, p) {
			out = append(out, KeyOutcome{Purpose: p, Result: "busy", Detail: "a key operation for this purpose is still running"})
			continue
		}
		id, err := s.St.Repos().ColumnKeys().CreateKeyJob(ctx, ports.KeyJob{Op: ports.KeyJobRotate, Purpose: p, Actor: "platform:" + admin})
		if err != nil {
			out = append(out, KeyOutcome{Purpose: p, Result: "failed", Detail: "the request could not be stored"})
			continue
		}
		out = append(out, KeyOutcome{Purpose: p, Result: "queued", JobID: id})
		queued = true
	}
	if queued {
		s.wakeKeyWorker()
	}
	return out, nil
}

// keyRow is one line of the operator's Key management table.
type keyRow struct {
	ID             string         `json:"id"`
	Slug           string         `json:"slug"`
	Name           string         `json:"name"`
	Status         string         `json:"status"`
	KEKMode        string         `json:"kek_mode"`
	KEKFingerprint string         `json:"kek_fingerprint,omitempty"`
	State          string         `json:"state"`
	Active         map[string]int `json:"active,omitempty"`
	Behind         int            `json:"versions_behind"`
	LastRotation   string         `json:"last_rotation,omitempty"`
	Running        []string       `json:"running"`
	LastFinished   string         `json:"last_finished,omitempty"`
	LastError      string         `json:"last_error,omitempty"`
	MasterVersion  int            `json:"master_version,omitempty"`
}

func rfc(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// keyRowOf reads one tenant's overview by opening it on this replica.
func (c *platformConsole) keyRowOf(ctx context.Context, t *platform.Tenant) keyRow {
	row := keyRow{ID: t.ID, Slug: t.Slug, Name: t.Name, Status: t.Status, KEKMode: t.KEKMode, KEKFingerprint: t.KEKFingerprint, State: keyStateOK, Running: []string{}, MasterVersion: t.MasterVersion}
	if t.Status != platform.StatusActive {
		row.State = keyStateUnavailable
		return row
	}
	err := c.h.withTenant(t.ID, func(s *Server) error {
		if s.ControllersLocked(ctx) {
			row.State = keyStateLocked
		}
		ov, err := s.KeyOverview(ctx)
		if err != nil {
			return err
		}
		row.Active, row.Behind, row.LastRotation = ov.Active, ov.Behind, rfc(ov.LastRotation)
		if ov.Running != nil {
			row.Running = ov.Running
		}
		row.LastFinished, row.LastError = rfc(ov.LastFinished), ov.LastFailed
		return nil
	})
	switch {
	case errors.Is(err, ports.ErrLocked):
		row.State = keyStateLocked
	case err != nil:
		if row.State == keyStateOK {
			row.State = keyStateUnavailable
		}
	}
	return row
}

// eachTenant runs fn for every tenant with a few at a time.
func eachTenant[T any](ts []*platform.Tenant, fn func(*platform.Tenant) T) []T {
	out := make([]T, len(ts))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i, t := range ts {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = fn(t)
		}()
	}
	wg.Wait()
	return out
}

func (c *platformConsole) keyTenants() ([]*platform.Tenant, error) {
	all, err := c.h.P.Tenants("")
	if err != nil {
		return nil, err
	}
	var ts []*platform.Tenant
	for _, t := range all {
		if t.Status == platform.StatusActive || t.Status == platform.StatusSuspended {
			ts = append(ts, t)
		}
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Slug < ts[j].Slug })
	return ts, nil
}

// keyListTTL is how long the listing is reused (concurrent and repeated
// requests share one build; a rotation request invalidates it).
const keyListTTL = 2 * time.Second

func (c *platformConsole) invalidateKeyList() {
	c.keyListMu.Lock()
	c.keyListAt = time.Time{}
	c.keyListMu.Unlock()
}

// listKeys: GET /api/platform/keys. Per tenant: key mode, KEK fingerprint,
// last rotation, old versions still kept, running jobs. Metadata only.
func (c *platformConsole) listKeys(w http.ResponseWriter, r *http.Request) {
	ts, err := c.keyTenants()
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	c.keyListMu.Lock()
	if time.Since(c.keyListAt) > keyListTTL || len(c.keyListRows) != len(ts) {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		c.keyListRows = eachTenant(ts, func(t *platform.Tenant) keyRow { return c.keyRowOf(ctx, t) })
		cancel()
		c.keyListAt = time.Now()
	}
	rows := slices.Clone(c.keyListRows)
	c.keyListMu.Unlock()
	running := 0
	for _, row := range rows {
		if len(row.Running) > 0 {
			running++
		}
	}
	jout(w, 200, map[string]any{"tenants": rows, "purposes": operatorPurposes, "running": running, "budget_per_hour": keyOpsPerHour()})
}

type forceBody struct {
	Purposes []string
	Reason   string
	Code     string
}

// parseForce validates the purposes and the written reason (design 6.4).
func parseForce(w http.ResponseWriter, r *http.Request) (forceBody, bool) {
	var b forceBody
	if decodeLoose(r, &b) != nil {
		jerr(w, 400, "invalid request")
		return b, false
	}
	var ps []string
	for _, p := range b.Purposes {
		p = strings.TrimSpace(p)
		if !slices.Contains(operatorPurposes, p) {
			jerr(w, 400, "purposes must be from: "+strings.Join(operatorPurposes, ", "))
			return b, false
		}
		if !slices.Contains(ps, p) {
			ps = append(ps, p)
		}
	}
	if len(ps) == 0 {
		jerr(w, 400, "choose at least one purpose")
		return b, false
	}
	b.Purposes = ps
	b.Reason = strings.TrimSpace(b.Reason)
	if len(b.Reason) < 3 || len(b.Reason) > 300 {
		jerr(w, 400, "a reason of 3 to 300 characters is required")
		return b, false
	}
	return b, true
}

// forceOne enqueues the rotation of one tenant and records it on both sides.
func (c *platformConsole) forceOne(r *http.Request, t *platform.Tenant, b forceBody, bulk bool) map[string]any {
	res := map[string]any{"id": t.ID, "slug": t.Slug, "result": "queued"}
	if t.Status != platform.StatusActive {
		res["result"], res["detail"] = keyStateUnavailable, "the organisation is "+t.Status
		return res
	}
	if bulk && t.KEKMode == platform.KEKTenant {
		res["result"], res["detail"] = keyStateSkipped, "the organisation holds its own key; only it can rotate there"
		return res
	}
	admin := consoleFrom(r).admin.Username
	var outcomes []KeyOutcome
	err := c.h.withTenant(t.ID, func(s *Server) error {
		if s.ControllersLocked(r.Context()) {
			return ports.ErrLocked
		}
		var err error
		outcomes, err = s.ForceKeyJobs(r.Context(), admin, b.Purposes)
		if err == nil {
			queued := 0
			for _, o := range outcomes {
				if o.Result == "queued" {
					queued++
				}
			}
			if queued > 0 {
				s.RecordPlatformEvent(admin, "key_rotation_forced", fmt.Sprintf("purposes=%s; reason=%s", strings.Join(b.Purposes, ","), clip(b.Reason, 300)))
			}
		}
		return err
	})
	switch {
	case errors.Is(err, ports.ErrLocked):
		res["result"], res["detail"] = keyStateLocked, "the organisation's own key is not unlocked on every controller"
	case err != nil:
		res["result"], res["detail"] = "failed", "the request could not be placed"
	default:
		res["purposes"] = outcomes
		allBusy := true
		for _, o := range outcomes {
			if o.Result == "queued" {
				allBusy = false
			}
		}
		if allBusy {
			res["result"] = "busy"
		}
	}
	detail := fmt.Sprintf("purposes=%s result=%v reason=%s", strings.Join(b.Purposes, ","), res["result"], clip(b.Reason, 300))
	c.record(r, "tenant_keys_rotation_requested", tenantTarget(t), fmt.Sprint(res["result"]), detail)
	return res
}

// forceBudget is the operator's hourly budget of forced rotations (a bulk
// request counts once): SENDORA_KEY_OPS_PER_HOUR, as for tenants.
func (c *platformConsole) forceBudget(w http.ResponseWriter, r *http.Request) bool {
	cs := consoleFrom(r)
	if !c.allow(fmt.Sprintf("keyforce:%d", cs.admin.ID), keyOpsPerHour(), time.Hour) {
		jerr(w, 429, "too many key operations; try again later")
		return false
	}
	return true
}

// rotateTenantKeys: POST /api/platform/tenants/{id}/keys/rotate {purposes,
// reason, code}. A tenant-managed tenant is allowed only while its key is
// unlocked on every controller; otherwise the answer is "locked".
func (c *platformConsole) rotateTenantKeys(w http.ResponseWriter, r *http.Request) {
	t := c.tenantParam(w, r)
	if t == nil {
		return
	}
	b, ok := parseForce(w, r)
	if !ok || !c.stepUp(w, r, b.Code) || !c.forceBudget(w, r) {
		return
	}
	res := c.forceOne(r, t, b, false)
	c.invalidateKeyList()
	status := 202
	switch res["result"] {
	case keyStateLocked:
		status = 423
	case keyStateUnavailable:
		status = 409
	case "busy":
		status = 409
	case "failed":
		status = 500
	}
	jout(w, status, res)
}

// rotateAllKeys: POST /api/platform/keys/rotate-all {purposes, reason, code}:
// every platform-managed tenant, one request per tenant, with the result of
// each; tenant-managed tenants are skipped and reported.
func (c *platformConsole) rotateAllKeys(w http.ResponseWriter, r *http.Request) {
	b, ok := parseForce(w, r)
	if !ok || !c.stepUp(w, r, b.Code) || !c.forceBudget(w, r) {
		return
	}
	ts, err := c.keyTenants()
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	results := eachTenant(ts, func(t *platform.Tenant) map[string]any { return c.forceOne(r, t, b, true) })
	c.invalidateKeyList()
	counts := map[string]int{}
	for _, res := range results {
		counts[fmt.Sprint(res["result"])]++
	}
	c.record(r, "keys_rotation_requested_all", "all platform-managed tenants", "ok", fmt.Sprintf("purposes=%s results=%v reason=%s", strings.Join(b.Purposes, ","), counts, clip(b.Reason, 300)))
	jout(w, 202, map[string]any{"ok": true, "results": results, "counts": counts})
}

// ---------- master key (D46) ----------

// masterStatus: GET /api/platform/master. The versions, how many tenants use
// each, whether a rotation runs and the controller's last note. Never a key.
func (c *platformConsole) masterStatus(w http.ResponseWriter, r *http.Request) {
	st, err := c.h.P.MasterStatus()
	if err != nil {
		jerr(w, 500, "database error")
		return
	}
	jout(w, 200, st)
}

type masterBody struct {
	Version int
	Reason  string
	Code    string
}

func parseMaster(w http.ResponseWriter, r *http.Request) (masterBody, bool) {
	var b masterBody
	if decodeLoose(r, &b) != nil || b.Version < 1 {
		jerr(w, 400, "invalid request")
		return b, false
	}
	b.Reason = strings.TrimSpace(b.Reason)
	if len(b.Reason) < 3 || len(b.Reason) > 300 {
		jerr(w, 400, "a reason of 3 to 300 characters is required")
		return b, false
	}
	return b, true
}

// masterRotate: POST /api/platform/master/rotate {version, reason, code}:
// asks the controller to move every tenant to master key version `version`
// (the active one plus one; its key file must already be mounted on the
// controllers). Step-up, written reason, audit, key-operation budget.
func (c *platformConsole) masterRotate(w http.ResponseWriter, r *http.Request) {
	b, ok := parseMaster(w, r)
	if !ok || !c.stepUp(w, r, b.Code) || !c.forceBudget(w, r) {
		return
	}
	err := c.h.P.StartMasterRotation(b.Version)
	outcome := "ok"
	if err != nil {
		outcome = "refused"
	}
	c.record(r, "master_rotation_requested", "master key", outcome, fmt.Sprintf("version=%d reason=%s", b.Version, clip(b.Reason, 300)))
	switch {
	case errors.Is(err, platform.ErrMasterBusy), errors.Is(err, platform.ErrMasterStep):
		jerr(w, 409, err.Error())
	case err != nil:
		jerr(w, 500, "the request could not be stored")
	default:
		jout(w, 202, map[string]any{"ok": true})
	}
}

// masterRetire: POST /api/platform/master/retire {version, reason, code}.
// Refused while a tenant still needs the version.
func (c *platformConsole) masterRetire(w http.ResponseWriter, r *http.Request) {
	b, ok := parseMaster(w, r)
	if !ok || !c.stepUp(w, r, b.Code) || !c.forceBudget(w, r) {
		return
	}
	err := c.h.P.RetireMasterVersion(b.Version)
	outcome := "ok"
	if err != nil {
		outcome = "refused"
	}
	c.record(r, "master_version_retired", "master key", outcome, fmt.Sprintf("version=%d reason=%s", b.Version, clip(b.Reason, 300)))
	if err != nil {
		jerr(w, 409, err.Error())
		return
	}
	jout(w, 200, map[string]any{"ok": true})
}
