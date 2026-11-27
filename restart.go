// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"log"
	"os"
	"syscall"

	"github.com/sendora-app/sendora/internal/app"
)

// restartProcess runs after an orderly stop (requests finished, jobs ended,
// databases closed) when "Restart now" was used: the process replaces itself
// with the same executable, arguments and environment (app.RestartMode
// "exec", Unix), or exits with app.ExitRestart for a supervisor ("exit":
// SENDORA_RESTART_MODE=exit, Windows, or when exec fails).
func restartProcess() {
	if app.RestartMode() == "exec" {
		exe, err := os.Executable()
		if err == nil {
			log.Printf("restarting: exec %s", exe)
			err = execSelf(exe, os.Args, os.Environ())
		}
		log.Printf("restart by exec failed (%v); exiting with code %d for a supervisor", err, app.ExitRestart)
	} else {
		log.Printf("restarting: exit code %d for the supervisor", app.ExitRestart)
	}
	os.Exit(app.ExitRestart)
}

// execSelf is syscall.Exec (replaced in tests).
var execSelf = syscall.Exec
