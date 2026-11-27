// SPDX-License-Identifier: AGPL-3.0-or-later

package dbcli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sendora-app/sendora/internal/adapters/postgres"
)

// clusterCheck runs the CloudNativePG checklist self-test (design 3.2,
// 5.2a) against one cluster: "sendora db cluster-check -direct-host ...
// -pooler-host ... -ca-file ... -provisioner-secret DIR [-monitor-secret DIR]".
// Secret directories are mounted Kubernetes Secrets with the files username
// and password (design 3.3); passwords are never taken from flags.
func clusterCheck(args []string) error {
	fs := flag.NewFlagSet("cluster-check", flag.ContinueOnError)
	directHost := fs.String("direct-host", "", "read-write service of the cluster (e.g. sendora-pg-rw.<ns>.svc)")
	poolerHost := fs.String("pooler-host", "", "read-write pooler service (e.g. sendora-pg-pooler-rw.<ns>.svc)")
	poolerROHost := fs.String("pooler-ro-host", "", "read-only pooler service (optional)")
	port := fs.Int("port", 5432, "PostgreSQL and PgBouncer port")
	caFile := fs.String("ca-file", "", "CA certificate of the cluster (sslmode=verify-full)")
	provisioner := fs.String("provisioner-secret", "", "directory with username and password of sendora_provisioner")
	monitor := fs.String("monitor-secret", "", "directory with username and password of sendora_monitor (optional)")
	poolers := fs.Int("poolers", 2, "PgBouncer instances per pooler (P in design 9.3)")
	tenants := fs.Int("tenants", 100, "tenants planned on this cluster (T in design 9.3)")
	allow := fs.String("allow-login-role", "", "comma-separated extra LOGIN roles reported as WARN instead of FAIL")
	asJSON := fs.Bool("json", false, "machine-readable output")
	timeout := fs.Duration("timeout", 3*time.Minute, "overall time limit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if *directHost == "" || *poolerHost == "" || *caFile == "" || *provisioner == "" {
		return errors.New("cluster-check: -direct-host, -pooler-host, -ca-file and -provisioner-secret are required")
	}
	conf := func(host, db, secretDir string) (*pgx.ConnConfig, error) {
		dsn := fmt.Sprintf("host=%s port=%d dbname=%s sslmode=verify-full sslrootcert=%s connect_timeout=10", dsnValue(host), *port, db, dsnValue(*caFile))
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			return nil, err
		}
		if secretDir != "" {
			if cfg.User, cfg.Password, err = readSecretDir(secretDir); err != nil {
				return nil, err
			}
		}
		return cfg, nil
	}
	var cc postgres.CheckConfig
	var err error
	if cc.Direct, err = conf(*directHost, "postgres", *provisioner); err != nil {
		return err
	}
	if cc.Pooler, err = conf(*poolerHost, "postgres", ""); err != nil {
		return err
	}
	if *poolerROHost != "" {
		if cc.PoolerRO, err = conf(*poolerROHost, "postgres", ""); err != nil {
			return err
		}
	}
	if *monitor != "" {
		if cc.Monitor, err = conf(*directHost, "postgres", *monitor); err != nil {
			return err
		}
	}
	cc.Poolers, cc.Tenants = *poolers, *tenants
	for _, r := range strings.Split(*allow, ",") {
		if r = strings.TrimSpace(r); r != "" {
			cc.AllowLoginRoles = append(cc.AllowLoginRoles, r)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	results := postgres.ClusterCheck(ctx, cc)
	if *asJSON {
		if err := json.NewEncoder(stdout).Encode(results); err != nil {
			return err
		}
	} else {
		w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "#\tSTATUS\tCHECK\tDETAIL")
		for _, r := range results {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.ID, r.Status, r.Name, r.Detail)
		}
		w.Flush()
	}
	counts := map[string]int{}
	for _, r := range results {
		counts[r.Status]++
	}
	summary := "cluster-check: " + strconv.Itoa(counts[postgres.CheckPass]) + " pass, " + strconv.Itoa(counts[postgres.CheckWarn]) + " warn, " + strconv.Itoa(counts[postgres.CheckFail]) + " fail, " + strconv.Itoa(counts[postgres.CheckSkip]) + " skipped"
	fmt.Fprintln(stderr, summary)
	if postgres.Failed(results) {
		return errors.New("cluster-check failed")
	}
	return nil
}

// readSecretDir reads username and password from a mounted Secret.
func readSecretDir(dir string) (user, password string, err error) {
	read := func(name string) (string, error) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	if user, err = read("username"); err != nil {
		return "", "", err
	}
	if password, err = read("password"); err != nil {
		return "", "", err
	}
	if user == "" || password == "" {
		return "", "", fmt.Errorf("%s: empty username or password", dir)
	}
	return user, password, nil
}

// dsnValue quotes a keyword/value connection string value.
func dsnValue(v string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v) + "'"
}
