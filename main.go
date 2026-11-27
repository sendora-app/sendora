// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"embed"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/sendora-app/sendora/internal/app"
	"github.com/sendora-app/sendora/internal/dbcli"
	"github.com/sendora-app/sendora/internal/flavour"
	"github.com/sendora-app/sendora/internal/store"
)

//go:embed all:web/dist
var distFS embed.FS

// Set at build time with -ldflags "-X main.version=… -X main.revision=…
// -X main.sourceURL=…". sourceURL (and SENDORA_SOURCE_URL, which wins) is the
// "Source code" link in the footer required by AGPL-3.0 section 13; forks
// point it at their own repository. See internal/app/source.go.
var (
	version   = "dev"
	revision  = ""
	sourceURL = ""
)

// buildRevision is the commit of this build: -X main.revision, else the VCS
// stamp Go records when building from a git checkout.
func buildRevision() string {
	if revision != "" && revision != "unknown" {
		return revision
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				return s.Value
			}
		}
	}
	return ""
}

// configureSourceURL fixes the footer's source link for this process.
func configureSourceURL() {
	u, ok := app.ResolveSourceURL(version, buildRevision(), sourceURL, os.Getenv("SENDORA_SOURCE_URL"))
	if !ok {
		log.Printf("WARNING: the configured source URL (SENDORA_SOURCE_URL or build setting) is not a valid http(s) URL; using %s", u)
	}
	app.SetSourceURL(u)
}

// dispatchDBTool runs the database tool when the program was started as
// sendora-db (argv[0]) or as "sendora db ...".
func dispatchDBTool(args []string) (int, bool) {
	if len(args) == 0 {
		return 0, false
	}
	name := strings.TrimSuffix(filepath.Base(args[0]), ".exe")
	if name == "sendora-db" {
		return dbTool(args[1:]), true
	}
	if len(args) >= 2 && args[1] == "db" {
		return dbTool(args[2:]), true
	}
	return 0, false
}

// dbTool is replaced in tests.
var dbTool = dbcli.Main

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	// The offline database tool is part of this binary: "sendora db <command>",
	// or "sendora-db <command>" through a link of that name (the image installs
	// /usr/local/bin/sendora-db -> /sendora).
	if code, ok := dispatchDBTool(os.Args); ok {
		os.Exit(code)
	}
	// "sendora healthcheck": container HEALTHCHECK probe against the running server.
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	// SENDORA_FLAVOUR first, so an invalid flavour is reported before anything
	// else is checked (single, multi or cluster), with its consistency with
	// SENDORA_MULTI_TENANT and SENDORA_ROLE.
	sel, err := flavour.FromEnv(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	if err := app.DisableCoreDumps(); err != nil {
		log.Printf("WARNING: could not disable core dumps: %v", err)
	}
	// A readable or foreign-owned secret file stops the start, like the database key file.
	if err := app.CheckSecretFiles(); err != nil {
		log.Fatal(err)
	}
	app.WarnPlainSecrets()
	configureSourceURL()
	if sel.Flavour == flavour.Cluster {
		runCluster(sel) // main_cluster.go
		return
	}
	dataDir := env("DATA_DIR", "./data")
	// SENDORA_FLAVOUR / SENDORA_MULTI_TENANT (true/false) > the mode persisted by
	// a conversion > single-tenant.
	multiTenant, baseDomain := app.ResolveMode(sel.MultiTenantEnv, os.Getenv("SENDORA_BASE_DOMAIN"), dataDir)
	convert := !multiTenant && sel.MultiTenantEnv != "false" && app.ConversionPending(dataDir)
	// A short signing secret could be guessed offline from any captured token.
	// (Multi-tenant mode ignores JWT_SECRET: every tenant has its own secret.)
	if sec, err := app.JWTSecretFromEnv(); err != nil {
		log.Fatal(err)
	} else if err := app.ValidateJWTSecret(sec); err != nil && !multiTenant && !convert {
		log.Fatal(err)
	}
	key, err := store.ReadDatabaseKey(os.Getenv("SENDORA_DB_KEY_FILE"))
	if err != nil {
		log.Fatal(err)
	}
	if convert {
		// A conversion scheduled in Admin -> Multi-tenant (internal/app/mt_convert.go).
		// On failure everything is put back and the server starts single-tenant.
		if base, err := app.ConvertPending(dataDir, key, log.Printf); err == nil {
			multiTenant, baseDomain = true, base
			if b := os.Getenv("SENDORA_BASE_DOMAIN"); b != "" {
				baseDomain = b
			}
		}
	}
	if multiTenant {
		runMultiTenant(dataDir, key, baseDomain)
		return
	}
	// A converted (multi-tenant) data directory must not be opened as a fresh
	// single-tenant instance by mistake.
	if _, err := os.Stat(filepath.Join(dataDir, store.PlatformDBFile)); err == nil {
		log.Fatal("this data directory belongs to a multi-tenant installation (platform.db exists); set SENDORA_FLAVOUR=multi (or SENDORA_MULTI_TENANT=true)")
	}
	st, err := store.OpenEncryptedRecovering(dataDir, key, os.Getenv("SENDORA_DB_INITIALIZE") == "true", log.Printf)
	// The store keeps its own copies; do not leave this one lying around.
	clear(key)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("file encryption active fp=%s format=2 sqlcipher=%s", st.KeyFingerprint(), st.CipherVersion())
	static, err := fs.Sub(distFS, "web/dist")
	if err != nil {
		log.Fatal(err)
	}
	srv := app.New(st, static, version)
	proxies, err := app.ParseTrustedProxies(os.Getenv("SENDORA_TRUSTED_PROXIES"))
	if err != nil {
		log.Fatal(err)
	}
	srv.SetTrustedProxies(proxies)
	if len(proxies) > 0 {
		log.Printf("trusting X-Forwarded-For/-Proto from %d configured proxy range(s)", len(proxies))
	}
	srv.SetForceLocalLogin(os.Getenv("SENDORA_FORCE_LOCAL_LOGIN") == "true")
	srv.LogLocalLoginState()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	jobsCtx, cancelJobs := context.WithCancel(ctx)
	defer cancelJobs()
	srv.RunJobs(jobsCtx)

	hs := &http.Server{
		Addr:              net.JoinHostPort(env("HOST", "127.0.0.1"), env("PORT", "8080")),
		Handler:           srv.Router(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// Explicit header cap (the net/http default is 1 MiB). Body timeouts are
		// per request in the security middleware, so large transfers are unaffected.
		MaxHeaderBytes: 64 << 10,
	}
	// An orderly stop: jobs end, requests in flight finish (at most 10 seconds),
	// then system_stop is written synchronously. A confirmed database import uses
	// the same stop before it carries the audit log, swaps and re-execs.
	gracefulStop := func() { srv.GracefulStop(10*time.Second, cancelJobs, hs.Shutdown, hs.Close) }
	srv.SetImportStopper(gracefulStop)
	// "Restart now" (Admin -> Multi-tenant): stop in order, then restart the
	// process (restart.go), which runs the scheduled conversion.
	restartRequested := make(chan struct{}, 1)
	srv.SetRestarter(func() {
		restartRequested <- struct{}{}
		stop()
	})
	stopped := make(chan struct{})
	go func() {
		<-ctx.Done()
		gracefulStop()
		close(stopped)
	}()
	log.Printf("sendora %s listening on %s", version, hs.Addr)
	if err := hs.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
	// ListenAndServe returns as soon as the shutdown begins. During an applied
	// import the swap/re-exec runs in a goroutine and owns the store; do not exit.
	if srv.AwaitImport() {
		return
	}
	<-stopped
	if err := st.Close(); err != nil {
		log.Printf("closing the database: %v", err)
	}
	select {
	case <-restartRequested:
		restartProcess()
	default:
	}
}
