// SPDX-License-Identifier: AGPL-3.0-or-later

package dbcli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sendora-app/sendora/internal/colenc"
	"github.com/sendora-app/sendora/internal/keyclient"
	"github.com/sendora-app/sendora/internal/keyserver"
	"github.com/sendora-app/sendora/internal/store"
)

// Tenant-supplied key (KEK) tools of the Cluster flavour (docs/cluster/DESIGN.md
// D41, D44): kek-generate makes a key for a tenant to keep, tenant-unlock
// presents it to the controllers on the tenant's behalf.

func kekGenerateCmd(args []string) error {
	flags := flag.NewFlagSet("kek-generate", flag.ContinueOnError)
	shares := flags.String("shares", "", `also split the key with Shamir's scheme, "3-of-5" (threshold-of-shares)`)
	if err := flags.Parse(args); err != nil {
		return err
	}
	k, n := 0, 0
	if *shares != "" {
		var err error
		if k, n, err = parseShares(*shares); err != nil {
			return err
		}
	}
	key := make([]byte, store.TenantKEKBytes)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	defer clear(key)
	fmt.Fprintf(stdout, "# Tenant key (KEK). Store it where only your organisation can reach it.\n")
	fmt.Fprintf(stdout, "# If you lose this key and its shares, your data cannot be recovered by anyone, backups included.\n\n")
	fmt.Fprintf(stdout, "Key: %s\n", base64.StdEncoding.EncodeToString(key))
	fmt.Fprintf(stdout, "Fingerprint: %s\n", store.TenantKEKFingerprint(key))
	if n > 0 {
		sh, err := colenc.Split(key, k, n)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "\n# Shamir shares: any %d of %d rebuild the key. Give them to different people and keep them in different places.\n", k, n)
		for i, s := range sh {
			fmt.Fprintf(stdout, "Share %d: %s\n", i+1, s)
		}
	}
	return nil
}

func parseShares(s string) (k, n int, err error) {
	a, b, ok := strings.Cut(strings.ToLower(strings.TrimSpace(s)), "-of-")
	if ok {
		k, err = strconv.Atoi(a)
		if err == nil {
			n, err = strconv.Atoi(b)
		}
	}
	if !ok || err != nil || k < 2 || k > n || n > 255 {
		return 0, 0, errors.New(`-shares must look like "3-of-5" (2 <= threshold <= shares <= 255)`)
	}
	return k, n, nil
}

// kekUnlocker presents a tenant's KEK to the controllers (keyclient.Client).
type kekUnlocker interface {
	Unlock(ctx context.Context, tenant, kek string) (keyserver.Response, error)
	Close() error
}

// newKEKClient builds the key-endpoint client; tests replace it.
var newKEKClient = func(cfg keyclient.Config) (kekUnlocker, error) { return keyclient.New(cfg) }

func tenantUnlockCmd(args []string) error {
	flags := flag.NewFlagSet("tenant-unlock", flag.ContinueOnError)
	tenant := flags.String("tenant", "", "tenant id (as shown in the platform console)")
	kekFile := flags.String("kek-file", "", "file holding the key: base64 text, or 32 raw bytes ('-' reads stdin)")
	sharesStr := flags.String("shares", "", "comma-separated Shamir shares of the key (instead of -kek-file)")
	url := flags.String("url", os.Getenv("SENDORA_KEY_URL"), "key endpoint URL (default SENDORA_KEY_URL)")
	ca := flags.String("ca", os.Getenv("SENDORA_KEY_CA"), "CA bundle of the key endpoint (default SENDORA_KEY_CA)")
	token := flags.String("token-file", os.Getenv("SENDORA_KEY_TOKEN_FILE"), "projected ServiceAccount token (default SENDORA_KEY_TOKEN_FILE)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *tenant == "" || !store.TenantIDPattern.MatchString(*tenant) {
		return errors.New("-tenant (the tenant id) is required")
	}
	kek, err := loadKEKInput(*kekFile, *sharesStr)
	if err != nil {
		return err
	}
	if *url == "" || *token == "" {
		return errors.New("the key endpoint is needed: run this inside a web pod (it has SENDORA_KEY_URL, SENDORA_KEY_CA and SENDORA_KEY_TOKEN_FILE) or pass -url, -ca and -token-file")
	}
	c, err := newKEKClient(keyclient.Config{URL: *url, CAFile: *ca, TokenFile: *token})
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	res, err := c.Unlock(ctx, *tenant, kek)
	if err != nil {
		return fmt.Errorf("unlock: %w", err)
	}
	fmt.Fprintf(stdout, "Tenant %s unlocked on every controller replica (key fingerprint %s).\n", *tenant, res.Fingerprint)
	return nil
}

// loadKEKInput returns the key as base64 text, from a key file or from shares.
func loadKEKInput(file, shares string) (string, error) {
	switch {
	case file != "" && shares != "":
		return "", errors.New("use -kek-file or -shares, not both")
	case shares != "":
		var list []string
		for _, s := range strings.Split(shares, ",") {
			if s = strings.TrimSpace(s); s != "" {
				list = append(list, s)
			}
		}
		raw, err := colenc.Combine(list)
		if err != nil {
			return "", fmt.Errorf("combining the shares: %w", err)
		}
		defer clear(raw)
		if len(raw) != store.TenantKEKBytes {
			return "", errors.New("the shares do not rebuild a tenant key (wrong shares?)")
		}
		return base64.StdEncoding.EncodeToString(raw), nil
	case file != "":
		var data []byte
		var err error
		if file == "-" {
			data, err = io.ReadAll(io.LimitReader(os.Stdin, 4<<10))
		} else {
			data, err = os.ReadFile(file)
		}
		if err != nil {
			return "", err
		}
		defer clear(data)
		if len(data) == store.TenantKEKBytes { // raw bytes (shamir-combine's output)
			return base64.StdEncoding.EncodeToString(data), nil
		}
		s := strings.TrimSpace(string(data))
		if _, err := store.ParseTenantKEK(s); err != nil {
			return "", err
		}
		return s, nil
	}
	return "", errors.New("give the key with -kek-file or -shares")
}
