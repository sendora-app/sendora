// SPDX-License-Identifier: AGPL-3.0-or-later

package dbcli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/sendora-app/sendora/internal/colenc"
	"github.com/sendora-app/sendora/internal/store"
)

func shamirSplitCmd(args []string) error {
	flags := flag.NewFlagSet("shamir-split", flag.ContinueOnError)
	keyFile := flags.String("key-file", os.Getenv("SENDORA_DB_KEY_FILE"), "path to 32-byte master key file")
	k := flags.Int("threshold", colenc.DefaultThreshold, "threshold shares required to reconstruct (default 3)")
	n := flags.Int("shares", colenc.DefaultShares, "total number of shares to generate (default 5)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" {
		return errors.New("key-file is required")
	}

	key, err := store.ReadDatabaseKey(*keyFile)
	if err != nil {
		return fmt.Errorf("reading key file: %w", err)
	}
	defer clear(key)

	shares, err := colenc.Split(key, *k, *n)
	if err != nil {
		return fmt.Errorf("splitting key: %w", err)
	}

	fmt.Fprintf(stdout, "# Shamir secret sharing: threshold %d of %d\n", *k, *n)
	fmt.Fprintf(stdout, "# Keep these shares in separate, secure locations.\n\n")
	for i, s := range shares {
		fmt.Fprintf(stdout, "Share %d: %s\n", i+1, s)
	}
	return nil
}

func shamirCombineCmd(args []string) error {
	flags := flag.NewFlagSet("shamir-combine", flag.ContinueOnError)
	destination := flags.String("destination", "", "path to write reconstructed 32-byte key file (must not exist)")
	sharesStr := flags.String("shares", "", "comma-separated list of shares")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *destination == "" {
		return errors.New("destination is required")
	}

	var shares []string
	if *sharesStr != "" {
		for _, s := range strings.Split(*sharesStr, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				shares = append(shares, s)
			}
		}
	} else if flags.NArg() > 0 {
		shares = flags.Args()
	}

	if len(shares) == 0 {
		return errors.New("no shares provided (provide via -shares or as positional arguments)")
	}

	secret, err := colenc.Combine(shares)
	if err != nil {
		return fmt.Errorf("reconstructing secret: %w", err)
	}
	defer clear(secret)

	if _, err := os.Stat(*destination); err == nil {
		return fmt.Errorf("destination %q already exists", *destination)
	}

	if err := os.WriteFile(*destination, secret, 0o600); err != nil {
		return fmt.Errorf("writing reconstructed key: %w", err)
	}

	fmt.Fprintf(stdout, "Successfully reconstructed 32-byte key file at %s\n", *destination)
	return nil
}
