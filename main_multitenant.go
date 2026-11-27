// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sendora-app/sendora/internal/app"
	"github.com/sendora-app/sendora/internal/platform"
	"github.com/sendora-app/sendora/internal/store"
)

// runMultiTenant serves all tenants and the platform console from one process
// (SENDORA_MULTI_TENANT=true, docs/MULTI-TENANT.md).
func runMultiTenant(dataDir string, key []byte, baseDomain string) {
	for _, name := range []string{"JWT_SECRET", "JWT_SECRET_FILE", "APP_URL"} {
		if os.Getenv(name) != "" {
			log.Printf("WARNING: %s is ignored in multi-tenant mode (every tenant has its own signing secret and URL)", name)
		}
	}
	if _, err := os.Stat(filepath.Join(dataDir, store.DBFile)); err == nil {
		log.Fatal("a single-tenant database (" + store.DBFile + ") is in the data directory: convert it first with 'sendora-db tenant-import' (docs/MULTI-TENANT.md) or use another DATA_DIR")
	}
	p, err := platform.Open(dataDir, key, os.Getenv("SENDORA_DB_INITIALIZE") == "true")
	clear(key)
	if err != nil {
		log.Fatal("platform database: ", err)
	}
	managed, err := p.ApplyEnv()
	if err != nil {
		log.Fatal(err)
	}
	// The platform default object storage (SENDORA_PLATFORM_STORAGE_* or the
	// console); an invalid configuration stops the start, like single-tenant mode.
	def := p.PlatformStorage()
	if err := def.Validate(); err != nil {
		log.Fatal("platform storage: ", err)
	}
	if def.Backend != "local" {
		log.Printf("platform storage: tenants' new files go to %s (prefix tenants/<tenant id>/)", def.Describe())
	}
	if os.Getenv("SENDORA_STORAGE_BACKEND") != "" {
		log.Printf("WARNING: SENDORA_STORAGE_* is ignored in multi-tenant mode; use SENDORA_PLATFORM_STORAGE_* for the platform default storage")
	}
	if err := p.CheckOffer(p.NewTenantOffer()); err != nil {
		log.Fatal("SENDORA_NEW_TENANT_STORAGE_OFFER / new_tenant_storage_offer: ", err)
	}
	if !p.MFARequired() {
		log.Printf("WARNING: platform_mfa_required is off: platform administrators sign in with a password only")
	}
	static, err := fs.Sub(distFS, "web/dist")
	if err != nil {
		log.Fatal(err)
	}
	proxies, err := app.ParseTrustedProxies(os.Getenv("SENDORA_TRUSTED_PROXIES"))
	if err != nil {
		log.Fatal(err)
	}
	h, err := app.NewTenantHost(app.MultiTenantConfig{
		Platform: p, BaseDomain: baseDomain, Static: static, Version: version,
		TrustedProxies: proxies, ForceLocalLogin: os.Getenv("SENDORA_FORCE_LOCAL_LOGIN") == "true", Managed: managed,
	})
	if err != nil {
		log.Fatal(err)
	}
	ts, _ := p.Tenants("")
	log.Printf("multi-tenant mode: %d tenant(s), platform console at %s, sqlcipher=%s", len(ts), h.ConsoleURL(), p.St.CipherVersion())
	p.Audit(0, "system", "system_start", "platform", "ok", "version "+version, "")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	jobsCtx, cancelJobs := context.WithCancel(ctx)
	defer cancelJobs()
	h.Start(jobsCtx)
	// "Restart" (Platform settings): orderly stop, then restart (restart.go).
	restartRequested := make(chan struct{}, 1)
	h.SetRestarter(func() {
		restartRequested <- struct{}{}
		stop()
	})
	hs := &http.Server{
		Addr:              net.JoinHostPort(env("HOST", "127.0.0.1"), env("PORT", "8080")),
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
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
	log.Printf("sendora %s listening on %s", version, hs.Addr)
	if err := hs.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
	<-stopped
	p.Audit(0, "system", "system_stop", "platform", "ok", "", "")
	if err := p.Close(); err != nil {
		log.Printf("closing the platform database: %v", err)
	}
	select {
	case <-restartRequested:
		restartProcess()
	default:
	}
}
