// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dbcli is the offline database tool, "sendora db ..." (also started
// as "sendora-db ..." through a link named sendora-db to the sendora binary).
// It performs explicit offline exports and checks; it never replaces a live DB.
package dbcli

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sendora-app/sendora/internal/store"
)

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sendora-db keygen|shamir-split|shamir-combine|kek-generate|tenant-unlock|migrate|backup|upgrade-encryption|rotate-key|retire-key|files-reencrypt|snapshot-plaintext|verify|verify-files|audit-verify|mfa-reset|tenant-import|storage-migrate|platform-admin-reset|cluster-check [flags]")
	}
	if args[0] == "cluster-check" {
		return clusterCheck(args[1:])
	}
	if args[0] == "shamir-split" {
		return shamirSplitCmd(args[1:])
	}
	if args[0] == "kek-generate" {
		return kekGenerateCmd(args[1:])
	}
	if args[0] == "tenant-unlock" {
		return tenantUnlockCmd(args[1:])
	}
	if args[0] == "shamir-combine" {
		return shamirCombineCmd(args[1:])
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	source := flags.String("source", "", "database source path; stop the app before offline operations")
	destination := flags.String("destination", "", "new output path (must not exist)")
	keyFile := flags.String("key-file", os.Getenv("SENDORA_DB_KEY_FILE"), "external 32-byte key file")
	plaintext := flags.Bool("plaintext", false, "explicit legacy plaintext verification")
	user := flags.String("user", "", "username for mfa-reset and platform-admin-reset")
	resetMFA := flags.Bool("mfa", false, "platform-admin-reset: remove the administrator's authenticator")
	resetPassword := flags.Bool("password", false, "platform-admin-reset: set a temporary password that must be changed at the next sign-in")
	dataDir := flags.String("data-dir", "", "data directory holding shares/ (verify-files; default: directory of -source)")
	asJSON := flags.Bool("json", false, "verify-files and audit-verify: machine-readable output")
	names := flags.Bool("names", false, "verify-files: also print share and file names (sensitive)")
	all := flags.Bool("all", false, "verify-files: list every row, not only problems")
	progress := flags.Bool("progress", false, "verify-files: report progress on stderr (default: only when stderr is a terminal)")
	slug := flags.String("slug", "", "tenant-import: subdomain of the new tenant")
	name := flags.String("name", "", "tenant-import: display name of the new tenant (default: the subdomain)")
	sourceKeyFile := flags.String("source-key-file", "", "tenant-import: key of the single-tenant database when it differs from -key-file (the master key)")
	from := flags.String("from", "", "tenant-import: copy the single-tenant DATA_DIR at this path into -data-dir (another host; the source is only read)")
	customDomain := flags.String("custom-domain", "", "tenant-import: the old host name, added as a verified custom domain of the new tenant (existing links keep working)")
	abort := flags.Bool("abort", false, "tenant-import: undo an unfinished conversion")
	tenant := flags.String("tenant", "", "multi-tenant: operate on this tenant's database (the key is derived from -key-file, the master key)")
	legacyRoot := flags.Bool("legacy-root", false, "multi-tenant: the tenant was imported from a single-tenant installation; its files and audit chain use the master key (verify-files, audit-verify)")
	purpose := flags.String("purpose", "", "rotate-key and retire-key: the key to rotate or retire (data, files, index, secrets, audit-enc)")
	keyVersion := flags.Int("version", 0, "retire-key: the decrypt-only key version to retire")
	platformDB := flags.Bool("platform", false, "upgrade-encryption: convert the platform database of the multi-tenant installation in -data-dir (with the master key)")
	dryRun := flags.Bool("dry-run", false, "storage-migrate: only report how many files would be copied")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if args[0] == "keygen" {
		if *keyFile == "" {
			return errors.New("key-file is required; use a path outside the data volume and source tree")
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		f, err := os.OpenFile(*keyFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = f.Write(key)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			os.Remove(*keyFile)
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		fmt.Println("Key created. Keep a separate protected recovery copy; losing the key makes the database unrecoverable.")
		return nil
	}
	if args[0] == "tenant-import" {
		return tenantImport(*dataDir, *keyFile, *sourceKeyFile, *slug, *name, *abort, *from, *customDomain)
	}
	if args[0] == "platform-admin-reset" {
		return platformAdminReset(*dataDir, *keyFile, *user, *resetMFA, *resetPassword)
	}
	if args[0] == "upgrade-encryption" && *platformDB {
		return upgradePlatformEncryption(*dataDir, *keyFile)
	}
	if *source == "" {
		return errors.New("source is required")
	}
	if args[0] == "snapshot-plaintext" {
		if *destination == "" {
			return errors.New("destination is required")
		}
		if err := store.SnapshotPlaintext(*source, *destination); err != nil {
			return err
		}
		fmt.Println("Verified standalone plaintext rollback snapshot created; protect it as sensitive data.")
		return nil
	}
	var key []byte
	if !(args[0] == "verify" && *plaintext) {
		var err error
		key, err = store.ReadDatabaseKey(*keyFile)
		if err != nil {
			return err
		}
	}
	// root: what the file and audit keys derive from (= the database key, except
	// for a tenant imported from a single-tenant installation).
	root := key
	var master []byte
	if *tenant != "" {
		master = key
		var err error
		if key, err = store.TenantDBKey(master, *tenant); err != nil {
			return err
		}
		root = key
		if *legacyRoot {
			root = master
			// A tenant copied from another installation (tenant-import -from)
			// keeps that installation's key as its root: pass it as -source-key-file.
			if *sourceKeyFile != "" {
				old, err := store.ReadDatabaseKey(*sourceKeyFile)
				if err != nil {
					return fmt.Errorf("source key: %w", err)
				}
				root = old
			}
		}
	}
	switch args[0] {
	case "migrate":
		if *destination == "" {
			return errors.New("destination is required")
		}
		if err := store.ExportDatabase(*source, *destination, nil, key); err != nil {
			return err
		}
		fmt.Println("Encrypted export verified. Source unchanged; no replacement or restart performed.")
	case "upgrade-encryption":
		dir := *dataDir
		if dir == "" {
			dir = filepath.Dir(*source)
		}
		stamp := time.Now().UTC().Format("20060102-150405")
		safety := *source + ".pre-column-encryption-" + stamp
		if err := store.ExportDatabase(*source, safety, key, key); err != nil {
			return fmt.Errorf("safety copy: %w", err)
		}
		n, err := store.UpgradeColumnEncryption(dir, key, root)
		if err != nil {
			return fmt.Errorf("%w (the database was not changed by a failed conversion; safety copy: %s)", err, safety)
		}
		fmt.Printf("Column encryption: %d values encrypted. Safety copy of the database before the conversion: %s (remove it once you have checked the installation).\n", n, safety)
	case "rotate-key", "retire-key", "files-reencrypt":
		dir := *dataDir
		if dir == "" {
			dir = filepath.Dir(*source)
		}
		return rotateKey(*source, dir, key, *purpose, *keyVersion, args[0] == "retire-key", args[0] == "files-reencrypt", tenantContext{id: *tenant, master: master, root: root})
	case "backup":
		if *destination == "" {
			return errors.New("destination is required")
		}
		if err := store.ExportDatabase(*source, *destination, key, key); err != nil {
			return err
		}
		fmt.Println("Encrypted backup verified. Preserve the external key separately.")
	case "mfa-reset":
		if *user == "" {
			return errors.New("user is required")
		}
		if err := store.ResetUserMFA(*source, key, *user); err != nil {
			return err
		}
		fmt.Println("All multi-factor factors and sessions of the user were removed. Stop the application before running this offline step.")
	case "storage-migrate":
		dir := *dataDir
		if dir == "" {
			dir = filepath.Dir(*source)
		}
		return storageMigrate(*source, dir, key, *dryRun, tenantContext{id: *tenant, master: master, root: root})
	case "verify-files":
		dir := *dataDir
		if dir == "" {
			dir = filepath.Dir(*source)
		}
		return verifyFiles(*source, dir, key, verifyFlags{json: *asJSON, names: *names, all: *all, progress: *progress, root: root})
	case "verify":
		counts, err := store.VerifyDatabase(*source, key)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(counts)
	case "audit-verify":
		st, err := store.VerifyAuditDatabaseRoot(*source, key, root)
		if err != nil {
			return err
		}
		if *asJSON {
			if err := json.NewEncoder(os.Stdout).Encode(st); err != nil {
				return err
			}
		} else if st.OK {
			fmt.Printf("Audit chain verified: %d records, last seq %d, checkpoint seq %d.\n", st.Count, st.LastSeq, st.CheckpointSeq)
		} else {
			fmt.Printf("Audit chain BROKEN at seq %d (%s). %d records examined.\n", st.FirstBroken, st.Reason, st.Count)
		}
		if !st.OK {
			return fmt.Errorf("audit chain broken at seq %d", st.FirstBroken)
		}
	default:
		return errors.New("unknown command")
	}
	return nil
}

// Output of verify-files; replaced in tests.
var (
	stdout           io.Writer = os.Stdout
	stderr           io.Writer = os.Stderr
	stderrIsTerminal           = func() bool {
		st, err := os.Stderr.Stat()
		return err == nil && st.Mode()&os.ModeCharDevice != 0
	}
)

// progressEvery is how many files verify-files checks between progress lines.
var progressEvery = 1000

type verifyFlags struct {
	json, names, all, progress bool
	root                       []byte
}

// verifyFiles streams the verify-files report: by default only rows with a
// problem and orphans, with -all every row, then a summary. With -json the
// output is JSON Lines: one object per reported row ("type":"file") and
// orphan ("type":"orphan"), then one "type":"summary" object. Rows appear in
// row id order. Names appear only with -names; keys, plaintext and crypto
// error text never do. Any problem makes the command fail.
func verifyFiles(source, dataDir string, key []byte, f verifyFlags) error {
	out := bufio.NewWriter(stdout)
	enc := json.NewEncoder(out)
	var writeErr error
	emit := func(v any, line string) {
		if writeErr != nil {
			return
		}
		if f.json {
			writeErr = enc.Encode(v)
		} else {
			_, writeErr = fmt.Fprintln(out, line)
		}
	}
	opt := store.VerifyOptions{Names: f.names, Root: f.root}
	opt.File = func(c store.FileCheck) {
		if !f.all && !c.Problem() {
			return
		}
		line := fmt.Sprintf("file id=%d path=%s %s", c.ID, c.PathHash, c.Status)
		if f.names {
			line += fmt.Sprintf(" share=%q file=%q", c.Share, c.Name)
		}
		emit(struct {
			Type string `json:"type"`
			store.FileCheck
		}{"file", c}, line)
		if c.Problem() {
			// Problems are visible at once, not only when the buffer fills.
			if err := out.Flush(); err != nil && writeErr == nil {
				writeErr = err
			}
		}
	}
	opt.Orphan = func(o store.OrphanFile) {
		line := fmt.Sprintf("orphan path=%s", o.PathHash)
		if f.names {
			line += fmt.Sprintf(" file=%q", o.Name)
		}
		emit(struct {
			Type string `json:"type"`
			store.OrphanFile
		}{"orphan", o}, line)
	}
	terminal := stderrIsTerminal()
	if f.progress || terminal {
		opt.Progress = func(done, total int) {
			if done%progressEvery != 0 && done != total {
				return
			}
			if terminal {
				fmt.Fprintf(stderr, "\rverify-files: %d/%d files checked", done, total)
				if done == total {
					fmt.Fprintln(stderr)
				}
			} else {
				fmt.Fprintf(stderr, "verify-files: %d/%d files checked\n", done, total)
			}
		}
	}
	s, err := store.VerifyFilesStream(source, dataDir, key, opt)
	if err != nil {
		out.Flush()
		return err
	}
	emit(struct {
		Type string `json:"type"`
		store.FilesSummary
	}{"summary", s}, fmt.Sprintf("summary rows=%d encrypted=%d plain=%d ok=%d plain-legacy=%d legacy-key=%d failed=%d orphans=%d",
		s.Rows, s.Encrypted, s.Plain, s.OK, s.Legacy, s.LegacyKey, s.Failed, s.Orphans))
	if err := out.Flush(); err != nil && writeErr == nil {
		writeErr = err
	}
	if writeErr != nil {
		return writeErr
	}
	if n := s.Failed + s.Orphans; n != 0 {
		return fmt.Errorf("verify-files: %d problem(s) found", n)
	}
	return nil
}

// Main runs one sendora-db command (args without the program name) and
// returns the process exit code.
func Main(args []string) int {
	if err := run(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
