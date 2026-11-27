// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// The helper process restarts itself once through restartProcess: the second
// incarnation sees the marker and prints that it runs after the restart.
func TestRestartHelperProcess(t *testing.T) {
	switch os.Getenv("SENDORA_TEST_RESTART") {
	case "":
		t.Skip("helper for TestRestartReplacesTheProcess")
	case "before":
		os.Setenv("SENDORA_TEST_RESTART", "after")
		fmt.Println("before-restart pid", os.Getpid())
		restartProcess()
	case "after":
		fmt.Println("after-restart pid", os.Getpid(), "args", strings.Join(os.Args[1:], " "))
		os.Exit(0)
	}
}

func TestRestartReplacesTheProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("exec restart is Unix only")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRestartHelperProcess$", "-test.v")
	cmd.Env = append(os.Environ(), "SENDORA_TEST_RESTART=before", "SENDORA_RESTART_MODE=")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	s := string(out)
	if !strings.Contains(s, "before-restart pid") || !strings.Contains(s, "after-restart pid") || !strings.Contains(s, "-test.run=^TestRestartHelperProcess$") {
		t.Fatalf("no restart with the same arguments:\n%s", s)
	}
	// exec keeps the process ID (the process replaces itself).
	var before, after int
	for _, l := range strings.Split(s, "\n") {
		fmt.Sscanf(strings.TrimSpace(l), "before-restart pid %d", &before)
		fmt.Sscanf(strings.TrimSpace(l), "after-restart pid %d", &after)
	}
	if before == 0 || before != after {
		t.Fatalf("pid before %d after %d", before, after)
	}
}

func TestRestartExitModeForSupervisors(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestRestartHelperProcess$")
	cmd.Env = append(os.Environ(), "SENDORA_TEST_RESTART=before", "SENDORA_RESTART_MODE=exit")
	err := cmd.Run()
	ee, ok := err.(*exec.ExitError)
	if !ok || ee.ExitCode() != 75 {
		t.Fatalf("want exit code 75, got %v", err)
	}
}
