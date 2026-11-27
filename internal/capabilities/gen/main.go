// SPDX-License-Identifier: AGPL-3.0-or-later

// Command gen writes the capability matrix (docs/CAPABILITIES.md):
// go generate ./internal/capabilities
package main

import (
	"flag"
	"log"
	"os"

	"github.com/sendora-app/sendora/internal/capabilities"
)

func main() {
	out := flag.String("o", "docs/CAPABILITIES.md", "output file")
	flag.Parse()
	if err := os.WriteFile(*out, []byte(capabilities.Matrix()), 0o644); err != nil {
		log.Fatal(err)
	}
}
