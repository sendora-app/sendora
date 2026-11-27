// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sendora-app/sendora/internal/adapters/k8s"
	"github.com/sendora-app/sendora/internal/adapters/postgres"
	"github.com/sendora-app/sendora/internal/app"
	"github.com/sendora-app/sendora/internal/flavour"
	"github.com/sendora-app/sendora/internal/keyclient"
	"github.com/sendora-app/sendora/internal/keyring"
	"github.com/sendora-app/sendora/internal/keyserver"
	"github.com/sendora-app/sendora/internal/masterkey"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/ports"
	"github.com/sendora-app/sendora/internal/store"
)

// Cluster flavour (SENDORA_FLAVOUR=cluster, docs/cluster/DESIGN.md 2.2; preview).
//
//   - SENDORA_ROLE=web serves tenants and the platform console. It reaches
//     PostgreSQL only through the pooler, as the platform's and the tenants'
//     app roles; it never holds provisioner credentials and never migrates.
//   - SENDORA_ROLE=controller campaigns for the controller Lease. The leader
//     creates and migrates the platform database, provisions, migrates and
//     drops tenant databases, and runs every background job (maintenance,
//     outbox workers) for all tenants; the others wait.
//
// The master key (SENDORA_DB_KEY_FILE) exists only in controller pods (D42).
// The controller derives the tenants' keys and the app roles' database
// passwords from it and serves them on the key endpoint (internal/keyserver);
// web replicas fetch what they need with internal/keyclient.

func derivedHex(master []byte, label string) string {
	h, err := keyserver.DerivedHex(master, label)
	if err != nil {
		log.Fatal(err)
	}
	return h
}

// unhex decodes a key received from the key source.
func unhex(what, h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		log.Fatalf("cluster: key source returned an invalid %s", what)
	}
	return b
}

func runCluster(sel flavour.Selection) {
	cfg, err := flavour.ClusterFromEnv(sel.Role, os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	for _, name := range []string{"JWT_SECRET", "JWT_SECRET_FILE", "APP_URL", "SENDORA_STORAGE_BACKEND"} {
		if os.Getenv(name) != "" {
			log.Printf("WARNING: %s is ignored by the Cluster flavour", name)
		}
	}
	pooler, err := pgx.ParseConfig(cfg.DSN(cfg.PoolerAddr))
	if err != nil {
		log.Fatal("SENDORA_PG_POOLER: ", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Key material: the controller derives it from the master key (only it
	// reads the key file); a web replica asks the controller's key endpoint.
	var keys ports.ClusterKeys
	var local *keyserver.Local
	var master []byte
	var masters *masterkey.Set
	if sel.Role == flavour.RoleController {
		// The master key file is one key (version 1) or a directory of
		// master-<n> files (D46). The platform's own material and the
		// database role passwords derive from masterkey.InfraVersion; a
		// tenant's keys from the version its record names.
		if masters, err = masterkey.Load(cfg.KeyFile); err != nil {
			log.Fatal(err)
		}
		defer masters.Close()
		if master, err = masters.Key(masterkey.InfraVersion); err != nil {
			log.Fatal(err)
		}
		defer clear(master)
		local = &keyserver.Local{Master: master}
		keys = local
	} else {
		kc, err := keyclient.New(keyclient.Config{URL: cfg.KeyURL, CAFile: cfg.KeyCA, TokenFile: cfg.KeyTokenFile, TTL: cfg.KeyTTL})
		if err != nil {
			log.Fatal("key endpoint: ", err)
		}
		defer kc.Close()
		keys = kc
	}
	var pk ports.PlatformKeys
	retry(ctx, "fetching the platform keys", func() (err error) {
		pk, err = keys.Platform(ctx)
		return err
	})
	platformPassword := pk.DBPassword
	platKey := unhex("platform key", pk.DBKey)
	defer clear(platKey)
	var prov *postgres.Provisioner
	if sel.Role == flavour.RoleController {
		user, password, err := readCredentialDir(cfg.ProvisionerDir)
		if err != nil {
			log.Fatal("SENDORA_PG_PROVISIONER_DIR: ", err)
		}
		direct, err := pgx.ParseConfig(cfg.DSN(cfg.DirectAddr))
		if err != nil {
			log.Fatal("SENDORA_PG_DIRECT: ", err)
		}
		direct.User, direct.Password = user, password
		prov = postgres.NewProvisioner(direct)
		defer prov.Close()
		// Idempotent; on a new cluster this is the platform database's only
		// CREATE DATABASE. Every controller does it: the migration runs under
		// an advisory lock, so concurrent starts wait for each other.
		retry(ctx, "creating and migrating the platform database", func() error {
			// The platform's column keys are created with the database (as
			// the owner: the app role cannot write the control log).
			return prov.EnsurePlatform(ctx, cfg.PlatformDatabase, platformPassword, 0, func(ctx context.Context, db *sql.DB) (ports.ColumnCodec, error) {
				a := postgres.New(db)
				return store.InitColumnCodec(ctx, a.ControlLog(), a.Keyring(), platKey)
			})
		})
	}
	platDB, err := postgres.OpenPlatformApp(pooler, cfg.PlatformDatabase, platformPassword)
	if err != nil {
		log.Fatal(err)
	}
	platDB.SetMaxOpenConns(8)
	platDB.SetConnMaxIdleTime(time.Minute)
	// A web replica can start before the controller created the database.
	retry(ctx, "waiting for the platform database (created by the controller)", func() error {
		vs, err := postgres.AppliedVersions(ctx, platDB)
		if err == nil && len(vs) < len(postgres.Migrations(postgres.PlatformSchema)) {
			err = fmt.Errorf("platform schema at version %v, controller has not migrated it yet", vs)
		}
		return err
	})
	// A web replica can also start before the controller gave the database
	// its column keys; opening verifies them.
	var pst *store.Store
	retry(ctx, "opening the platform database (column keys)", func() (err error) {
		pst, err = store.OpenRemote(postgres.New(platDB), cfg.DataDir, platKey, platDB.Close, store.WithColumnEncryption())
		return err
	})
	platRepo := postgres.NewPlatform(platDB)
	platRepo.SetCodec(pst.ColumnCodec())
	p, err := platform.OpenOn(pst, platRepo, cfg.DataDir, master) // master is nil on web replicas
	if err != nil {
		log.Fatal("platform database: ", err)
	}
	defer p.Close()
	var kek *keyserver.KEKManager
	var rot *keyserver.MasterRotator
	if local != nil {
		p.UseMasters(masters)
		local.P = p
		// Tenant-supplied KEKs (D44): held in this controller's memory only.
		kek = keyserver.NewKEKManager(p, func(ctx context.Context, id string) (ports.ControlLogRepository, ports.KeyringRepository, func(), error) {
			db, err := prov.OwnerDB(id)
			if err != nil {
				return nil, nil, nil, err
			}
			a := postgres.New(db)
			return a.ControlLog(), a.Keyring(), func() { db.Close() }, nil
		}, master, log.Printf)
		local.KEK = kek
		rot = &keyserver.MasterRotator{P: p, Masters: masters, KEK: kek, Logf: log.Printf, Ring: func(ctx context.Context, id string) (ports.ControlLogRepository, ports.KeyringRepository, func(), error) {
			db, err := prov.OwnerDB(id)
			if err != nil {
				return nil, nil, nil, err
			}
			a := postgres.New(db)
			return a.ControlLog(), a.Keyring(), func() { db.Close() }, nil
		}, Audit: func(action, tenantID, detail string) {
			target := "all tenants"
			if tenantID != "" {
				target = tenantID
			}
			if err := p.Audit(0, "master key rotation", action, target, "ok", detail, ""); err != nil {
				log.Printf("cluster: platform audit: %v", err)
			}
		}}
	} else {
		p.UseKeyProvider(platform.RemoteKeys{Src: keys})
	}
	managed, err := p.ApplyEnv()
	if err != nil {
		log.Fatal(err)
	}
	if def := p.PlatformStorage(); def.Validate() != nil {
		log.Fatal("platform storage: ", def.Validate())
	}
	if sel.Role == flavour.RoleWeb && p.AdminCount() == 0 && strings.TrimSpace(os.Getenv("SENDORA_PLATFORM_SETUP_CODE")) == "" {
		log.Fatal("SENDORA_PLATFORM_SETUP_CODE is required until the first platform administrator exists: every web replica must accept the same setup code")
	}

	var elector postgres.Elector = postgres.StaticElector{}
	var lease *k8s.LeaseElector
	var listen *pgx.ConnConfig
	if sel.Role == flavour.RoleController {
		lease, err = k8s.NewLeaseElector(k8s.LeaseConfig{Name: cfg.LeaseName, Identity: cfg.PodName,
			LeaseDuration: cfg.LeaseDuration, RenewDeadline: cfg.LeaseDuration * 2 / 3, RetryPeriod: max(cfg.LeaseDuration/7, time.Second),
			APIServer: os.Getenv("SENDORA_K8S_API")})
		if err != nil {
			log.Fatal(err)
		}
		go lease.Run(ctx)
		elector = lease
		listen = prov.DirectConfig(cfg.PlatformDatabase)
	}
	coord, err := postgres.NewCoordinator(ctx, postgres.CoordinatorConfig{DB: platDB, Listen: listen, Elector: elector, PollInterval: cfg.PollInterval})
	if err != nil {
		log.Fatal("coordinator: ", err)
	}
	defer coord.Close()
	rateKey := unhex("rate-limit key", pk.RateKey)
	defer clear(rateKey)
	rt := &app.ClusterRuntime{
		Coordinator: coord,
		Lock:        postgres.NewLock(platDB, cfg.PodName, 30*time.Second),
		Limiter:     postgres.NewRateLimiter(platDB, rateKey, nil),
		OpenStore: func(t *platform.Tenant, dir string, root []byte) (*store.Store, error) {
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			tk, err := keys.Tenant(ctx, t.ID) // cached by the key client
			if err != nil {
				return nil, err
			}
			db, err := postgres.OpenTenantApp(pooler, t.ID, tk.DBPassword)
			if err != nil {
				return nil, err
			}
			db.SetMaxOpenConns(8)
			db.SetConnMaxIdleTime(time.Minute)
			opts := []store.RemoteOpt{store.WithColumnEncryption()}
			if tk.KEK != "" { // tenant-managed and unlocked: the controller handed out its wrapping key
				w, err := hex.DecodeString(tk.KEK)
				if err != nil || len(w) != 32 {
					db.Close()
					return nil, errors.New("key source returned an invalid tenant KEK")
				}
				defer clear(w)
				opts = append(opts, store.WithTenantWrapKey(w))
			}
			st, err := store.OpenRemote(postgres.New(db), dir, root, db.Close, opts...)
			if err != nil {
				db.Close()
			}
			return st, err
		},
		ForgetKeys: func(id string) {
			if kc, ok := keys.(*keyclient.Client); ok {
				kc.ForgetTenant(id)
			}
		},
		Fresh: func(t *platform.Tenant) {
			// After a master key rotation the cached material of a tenant is
			// derived from its old version: drop it so the store opens with the new.
			kc, ok := keys.(*keyclient.Client)
			if !ok {
				return
			}
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if tk, err := keys.Tenant(ctx, t.ID); err == nil && tk.MasterVersion != t.MasterVersion {
				kc.ForgetTenant(t.ID)
			}
		},
		KeyCheck: func(ctx context.Context, id string) error {
			_, err := keys.Tenant(ctx, id)
			return err
		},
	}
	static, err := fs.Sub(distFS, "web/dist")
	if err != nil {
		log.Fatal(err)
	}
	proxies, err := app.ParseTrustedProxies(os.Getenv("SENDORA_TRUSTED_PROXIES"))
	if err != nil {
		log.Fatal(err)
	}
	mt := app.MultiTenantConfig{Platform: p, BaseDomain: cfg.BaseDomain, Static: static, Version: version, TrustedProxies: proxies,
		ForceLocalLogin: os.Getenv("SENDORA_FORCE_LOCAL_LOGIN") == "true", Managed: managed, Cluster: rt}
	if kc, ok := keys.(*keyclient.Client); ok {
		mt.KEK = kc // web replicas forward tenant keys to the controllers
	}
	if sel.Role == flavour.RoleWeb {
		rt.Provision = func(ctx context.Context, t *platform.Tenant) error { return awaitProvisioned(ctx, coord, p, t.ID) }
		rt.Drop = func(ctx context.Context, id string) error { return coord.Signal(ctx, app.WorkDrop, id) }
		runClusterWeb(ctx, mt, cfg)
		return
	}
	c := &controller{cfg: cfg, master: master, local: local, kek: kek, rot: rot, p: p, prov: prov, coord: coord, lease: lease, mt: mt}
	rt.Provision = func(ctx context.Context, t *platform.Tenant) error { return c.provision(ctx, t.ID) }
	rt.Drop = func(ctx context.Context, id string) error { return c.drop(ctx, id) }
	rt.RunJobs = true
	rt.KeyWriter = c.keyWriter
	c.run(ctx)
}

// retry runs fn until it succeeds or ctx ends (then the process exits),
// logging each failure with a growing delay: PostgreSQL may be failing over
// or the controller may not have created the database yet.
func retry(ctx context.Context, what string, fn func() error) {
	wait := time.Second
	for {
		err := fn()
		if err == nil {
			return
		}
		log.Printf("cluster: %s: %v; retrying in %s", what, err, wait)
		select {
		case <-ctx.Done():
			log.Fatal("stopped while ", what)
		case <-time.After(wait):
		}
		wait = min(wait*2, 30*time.Second)
	}
}

// readCredentialDir reads the files username and password of a mounted
// basic-auth Secret (as CloudNativePG creates them for managed roles).
func readCredentialDir(dir string) (user, password string, err error) {
	u, err := os.ReadFile(filepath.Join(dir, "username"))
	if err != nil {
		return "", "", err
	}
	pw, err := os.ReadFile(filepath.Join(dir, "password"))
	if err != nil {
		return "", "", err
	}
	user, password = strings.TrimSpace(string(u)), strings.TrimRight(string(pw), "\r\n")
	if user == "" || password == "" {
		return "", "", errors.New("username or password is empty")
	}
	return user, password, nil
}

// awaitProvisioned asks the controller to provision tenant id (work signal)
// and waits until it is active.
func awaitProvisioned(ctx context.Context, coord ports.Coordinator, p *platform.Platform, id string) error {
	if err := coord.Signal(ctx, app.WorkProvision, id); err != nil {
		return err
	}
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		if cur, err := p.Tenant(id); err == nil && cur.Status == platform.StatusActive {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("the controller did not provision the database in time (is a sendora-controller running and leading?)")
		case <-t.C:
		}
	}
}

func listenAddr() string { return net.JoinHostPort(env("HOST", "127.0.0.1"), env("PORT", "8080")) }

// runClusterWeb serves HTTP until ctx ends.
func runClusterWeb(ctx context.Context, mt app.MultiTenantConfig, cfg flavour.ClusterConfig) {
	h, err := app.NewTenantHost(mt)
	if err != nil {
		log.Fatal(err)
	}
	jobsCtx, cancelJobs := context.WithCancel(ctx)
	defer cancelJobs()
	h.Start(jobsCtx)
	hs := &http.Server{Addr: listenAddr(), Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
	stopped := make(chan struct{})
	go func() {
		<-ctx.Done()
		cancelJobs()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := hs.Shutdown(sctx); err != nil {
			hs.Close()
		}
		cancel()
		h.Shutdown(5 * time.Second)
		close(stopped)
	}()
	log.Printf("sendora %s cluster web replica %s listening on %s (console %s)", version, cfg.PodName, hs.Addr, h.ConsoleURL())
	if err := hs.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
	<-stopped
}

// controller is a controller replica.
type controller struct {
	cfg    flavour.ClusterConfig
	master []byte
	local  *keyserver.Local
	kek    *keyserver.KEKManager
	rot    *keyserver.MasterRotator
	p      *platform.Platform
	prov   *postgres.Provisioner
	coord  *postgres.Coordinator
	lease  *k8s.LeaseElector
	mt     app.MultiTenantConfig
}

// run serves the health endpoint and follows the Lease: while leading, a
// tenant host runs every tenant's jobs and the workers below.
func (c *controller) run(ctx context.Context) {
	mux := http.NewServeMux()
	status := func(w http.ResponseWriter, r *http.Request) {
		leader, epoch := c.lease.Leader()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "role": "controller", "pod": c.cfg.PodName, "leader": leader, "epoch": epoch, "holder": c.lease.Holder()})
	}
	mux.HandleFunc("GET /api/health", status)
	mux.HandleFunc("GET /api/cluster/status", status)
	hs := &http.Server{Addr: listenAddr(), Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := hs.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	ks := c.keyServer()
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ks.Shutdown(sctx)
		cancel()
	}()
	log.Printf("sendora %s cluster controller %s (Lease %s) listening on %s", version, c.cfg.PodName, c.cfg.LeaseName, hs.Addr)
	var stopLeading func()
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		leader, epoch := c.lease.Leader()
		switch {
		case leader && stopLeading == nil:
			stopLeading = c.lead(ctx, epoch)
		case !leader && stopLeading != nil:
			log.Printf("cluster controller %s: no longer the leader; stopping the jobs", c.cfg.PodName)
			stopLeading()
			stopLeading = nil
		}
		select {
		case <-ctx.Done():
			if stopLeading != nil {
				stopLeading()
			}
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			hs.Shutdown(sctx)
			cancel()
			return
		case <-t.C:
		}
	}
}

// keyServer starts the key endpoint (TLS 1.3, TokenReview-authenticated). Every
// controller replica serves it: all hold the master key and no state.
func (c *controller) keyServer() *http.Server {
	tlsCfg, err := keyserver.TLSConfig(c.cfg.KeyTLSCert, c.cfg.KeyTLSKey)
	if err != nil {
		log.Fatal("key endpoint certificate: ", err)
	}
	rev, err := k8s.NewTokenReviewer(k8s.TokenReviewConfig{APIServer: os.Getenv("SENDORA_K8S_API")})
	if err != nil {
		log.Fatal(err)
	}
	user := c.cfg.KeyUser
	if user == "" {
		ns, err := k8s.PodNamespace()
		if err != nil {
			log.Fatal("key endpoint: ", err)
		}
		user = "system:serviceaccount:" + ns + ":sendora-web"
	}
	h := keyserver.Handler(keyserver.Config{Source: c.local, Review: rev, AllowedUser: user, KEK: c.kek, Status: func(id string) (string, error) {
		t, err := c.p.Tenant(id)
		if err != nil {
			return "", err
		}
		return t.Status, nil
	}})
	ks := &http.Server{Addr: c.cfg.KeyAddr, Handler: h, TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		if err := ks.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	log.Printf("sendora cluster controller %s: key endpoint on %s (allowed caller %s)", c.cfg.PodName, ks.Addr, user)
	return ks
}

// lead migrates every tenant, then starts a tenant host with the jobs and
// the workers. The returned function stops them.
func (c *controller) lead(ctx context.Context, epoch int64) func() {
	log.Printf("cluster controller %s: leading (epoch %d)", c.cfg.PodName, epoch)
	lctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	var host *app.TenantHost
	go func() {
		defer close(done)
		if ts, err := c.p.Tenants(""); err == nil {
			var ids []string
			for _, t := range ts {
				if t.Status != platform.StatusImporting {
					ids = append(ids, t.ID)
				}
			}
			for _, r := range c.prov.MigrateTenants(lctx, ids) {
				if r.Err != nil {
					log.Printf("cluster: migrating tenant %s: %v", r.ID, r.Err)
				}
			}
		}
		if lctx.Err() != nil {
			return
		}
		h, err := app.NewTenantHost(c.mt)
		if err != nil {
			log.Printf("cluster: tenant host: %v", err)
			return
		}
		host = h
		host.Start(lctx)
		c.workers(lctx, host)
	}()
	return func() {
		cancel()
		<-done
		if host != nil {
			host.Shutdown(5 * time.Second)
		}
	}
}

// workers drains the work signals until ctx ends: provisioning of pending
// tenants, dropping deleted tenants' databases and waking the outbox
// workers of tenants with work, and enforcing suspensions in PostgreSQL
// (reconcileLogins; on every routing change and every 5 s). A sweep every 5
// minutes catches signals lost between a commit and its signal (design 4.3,
// M8).
func (c *controller) workers(ctx context.Context, host *app.TenantHost) {
	sub := func(kind string) (<-chan struct{}, func()) { return c.coord.Subscribe(ports.WorkTopic(kind)) }
	provCh, c1 := sub(app.WorkProvision)
	defer c1()
	dropCh, c2 := sub(app.WorkDrop)
	defer c2()
	mailCh, c3 := sub(app.WorkDownloadMail)
	defer c3()
	keysCh, c5 := sub(app.WorkKeyJob)
	defer c5()
	routesCh, c4 := c.coord.Subscribe(app.TopicRoutes)
	defer c4()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	sweep := time.NewTicker(5 * time.Minute)
	defer sweep.Stop()

	take := func(kind string, limit int) []string {
		ids, err := c.coord.TakeSignals(ctx, kind, limit)
		if err != nil && ctx.Err() == nil {
			log.Printf("cluster: taking %s signals: %v", kind, err)
		}
		return ids
	}
	provision := func() {
		for _, id := range take(app.WorkProvision, 20) {
			if err := c.provision(ctx, id); err != nil {
				log.Printf("cluster: provisioning tenant %s: %v (retried by the sweep)", id, err)
			}
		}
	}
	drop := func() {
		for _, id := range take(app.WorkDrop, 5) {
			if err := c.drop(ctx, id); err != nil {
				log.Printf("cluster: dropping tenant %s: %v", id, err)
			}
		}
	}
	mail := func() {
		for _, id := range take(app.WorkDownloadMail, 50) {
			if err := host.WakeDownloadMail(id); err != nil {
				log.Printf("cluster: download notifications of tenant %s: %v", id, err)
			}
		}
	}
	keyJobs := func() {
		for _, id := range take(app.WorkKeyJob, 50) {
			if err := host.WakeKeyJobs(id); err != nil {
				log.Printf("cluster: key jobs of tenant %s: %v", id, err)
			}
		}
	}
	// The master key rotation (D46) runs in its own goroutine: a pass visits
	// every tenant and may take long; a pass in progress makes a new one return.
	masterPass := func() {
		if c.rot == nil || c.p.MasterState().Target == 0 {
			return
		}
		go func() {
			if _, err := c.rot.Pass(ctx); err != nil && !errors.Is(err, keyserver.ErrRotationBusy) && ctx.Err() == nil {
				log.Printf("cluster: master key rotation: %v", err)
			}
		}()
	}
	sweepAll := func() {
		ts, err := c.p.Tenants("")
		if err != nil {
			return
		}
		for _, t := range ts {
			switch t.Status {
			case platform.StatusImporting:
				if err := c.provision(ctx, t.ID); err != nil {
					log.Printf("cluster: provisioning tenant %s: %v", t.ID, err)
				}
			case platform.StatusActive:
				host.WakeDownloadMail(t.ID)
				host.WakeKeyJobs(t.ID)
			}
		}
	}
	sweepAll()
	c.reconcileLogins(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-routesCh:
			c.reconcileLogins(ctx)
		case <-provCh:
			provision()
		case <-dropCh:
			drop()
		case <-mailCh:
			mail()
		case <-keysCh:
			keyJobs()
		case <-tick.C:
			provision()
			drop()
			mail()
			keyJobs()
			c.reconcileLogins(ctx)
			masterPass()
		case <-sweep.C:
			sweepAll()
		}
	}
}

// reconcileLogins makes every tenant app role's LOGIN match the tenant's
// status (design 4.6, M11): a suspended tenant's role is NOLOGIN and its
// backends are terminated, so no replica can use its database even before
// its routing cache has caught up; an active tenant's role may log in.
// Pending tenants are left to provisioning.
func (c *controller) reconcileLogins(ctx context.Context) {
	logins, err := c.prov.TenantLogins(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("cluster: reading tenant logins: %v", err)
		}
		return
	}
	ts, err := c.p.Tenants("")
	if err != nil {
		return
	}
	for _, t := range ts {
		var want bool
		switch t.Status {
		case platform.StatusActive:
			want = true
		case platform.StatusSuspended:
			want = false
		default:
			continue
		}
		have, ok := logins[t.ID]
		if !ok || have == want {
			continue
		}
		if err := c.prov.SetTenantLogin(ctx, t.ID, want); err != nil {
			log.Printf("cluster: tenant %s: setting LOGIN=%t: %v", t.Slug, want, err)
			continue
		}
		if want {
			log.Printf("cluster: tenant %s resumed: database login enabled", t.Slug)
		} else {
			log.Printf("cluster: tenant %s suspended: database login disabled, connections terminated", t.Slug)
		}
	}
}

// provision creates tenant id's database (roles, schema, migrations, core
// seed with the tenant's signing secret, grants) and sets the tenant active.
// Only a tenant still pending (status importing) is provisioned.
func (c *controller) provision(ctx context.Context, id string) error {
	t, err := c.p.Tenant(id)
	if errors.Is(err, platform.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if t.Status != platform.StatusImporting {
		return nil
	}
	seed := store.DefaultSeed()
	// The signing secret exists before any replica opens the tenant, so
	// replicas never race to create different ones.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	seed.Settings = append(seed.Settings, ports.Setting{Key: "jwt_secret", Value: hex.EncodeToString(secret), Group: "system"})
	dbKey, root, err := c.p.TenantKeys(t)
	if err != nil {
		return err
	}
	defer clear(dbKey)
	defer clear(root)
	if root == nil {
		root = append([]byte(nil), dbKey...) // as TenantHost.open does
	}
	initKeys := func(ctx context.Context, db *sql.DB) (ports.ColumnCodec, error) {
		a := postgres.New(db)
		return store.InitColumnCodec(ctx, a.ControlLog(), a.Keyring(), root)
	}
	spec := postgres.TenantSpec{ID: id, InitKeys: initKeys, AppPassword: derivedHex(c.master, keyserver.LabelTenantPassword+id), ConnectionLimit: postgres.ConnectionLimit(c.cfg.Poolers), Seed: &seed}
	if err := c.prov.CreateTenant(ctx, spec); err != nil {
		return err
	}
	if err := c.p.ActivatePending(id); err != nil {
		return err
	}
	log.Printf("cluster: provisioned tenant %s (%s)", t.Slug, id)
	return nil
}

// keyWriter is the keyring service of tenant id on the owner connection, the
// only one that may write the control log and the keyring (tenant key
// rotation, D43). release closes the connection and clears the key.
func (c *controller) keyWriter(ctx context.Context, id string) (*keyring.Service, func(), error) {
	t, err := c.p.Tenant(id)
	if err != nil {
		return nil, nil, err
	}
	dbKey, root, err := c.p.TenantKeys(t)
	if err != nil {
		return nil, nil, err
	}
	if root == nil {
		root = append([]byte(nil), dbKey...) // as TenantHost.open does
	}
	var wrap []byte
	if t.KEKMode == platform.KEKTenant { // new wraps must go under the tenant's KEK: needs it unlocked here
		var ok bool
		if wrap, ok = c.kek.Wrap(id, t.KEKFingerprint); !ok {
			clear(dbKey)
			clear(root)
			return nil, nil, ports.ErrLocked
		}
	}
	db, err := c.prov.OwnerDB(id)
	if err != nil {
		clear(dbKey)
		clear(root)
		clear(wrap)
		return nil, nil, err
	}
	a := postgres.New(db)
	svc, err := store.RemoteKeyringWithTenantKEK(a.ControlLog(), a.Keyring(), root, wrap)
	clear(wrap)
	if err != nil {
		db.Close()
		clear(dbKey)
		clear(root)
		return nil, nil, err
	}
	return svc, func() { db.Close(); clear(dbKey); clear(root) }, nil
}

// drop removes the database of a deleted tenant. Drops are spaced out: every
// DROP DATABASE forces a checkpoint (design 3.4a).
func (c *controller) drop(ctx context.Context, id string) error {
	if _, err := c.p.Tenant(id); !errors.Is(err, platform.ErrNotFound) {
		return err // still registered (or unknown state): keep the database
	}
	if err := c.prov.DropTenant(ctx, id); err != nil {
		return err
	}
	log.Printf("cluster: dropped the database of deleted tenant %s", id)
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
	}
	return nil
}
