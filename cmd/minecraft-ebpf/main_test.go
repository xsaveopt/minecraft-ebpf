package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const helperEnv = "MINECRAFT_EBPF_HELPER_PROCESS"

var dispatchedCommands = []string{"run", "info", "stats", "top", "inspect", "dump", "health", "clear"}

func TestHelperProcess(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		t.Skip("only runs as a re-executed CLI")
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	os.Args = append([]string{"minecraft-ebpf"}, args...)
	main()
	os.Exit(0)
}

type cliResult struct {
	code   int
	stdout string
	stderr string
}

func runCLI(t *testing.T, args ...string) cliResult {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0], append([]string{"-test.run=^TestHelperProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	return cliResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func TestUsageListsEveryCommandAndMapName(t *testing.T) {
	stdout, stderr := captureOutput(t, usage)
	if stdout != "" {
		t.Errorf("usage wrote %q to stdout, want stderr only", stdout)
	}
	for _, cmd := range dispatchedCommands {
		if !strings.Contains(stderr, "minecraft-ebpf "+cmd+" ") {
			t.Errorf("usage does not list %s:\n%s", cmd, stderr)
		}
	}
	for _, name := range []string{
		"whitelist", "established", "syn-seen", "open-count",
		"status-ratelimit", "login-ratelimit", "health", "drop-history", "all",
	} {
		if !strings.Contains(stderr, name) {
			t.Errorf("usage does not name map %s", name)
		}
	}
}

func TestMainHelpPrintsUsageAndReturns(t *testing.T) {
	orig := os.Args
	t.Cleanup(func() { os.Args = orig })
	for _, flag := range []string{"-h", "--help", "help"} {
		t.Run(flag, func(t *testing.T) {
			os.Args = []string{"minecraft-ebpf", flag}
			stdout, stderr := captureOutput(t, main)
			if stdout != "" {
				t.Errorf("stdout = %q, want nothing", stdout)
			}
			if !strings.Contains(stderr, "Usage:") {
				t.Errorf("stderr does not carry usage:\n%s", stderr)
			}
		})
	}
}

func TestMainExitsTwoWithUsageOnMissingOrUnknownCommand(t *testing.T) {
	cases := map[string][]string{
		"no command":      nil,
		"unknown command": {"banana"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			res := runCLI(t, args...)
			if res.code != 2 {
				t.Errorf("exit code %d, want 2", res.code)
			}
			if !strings.Contains(res.stderr, "Usage:") {
				t.Errorf("stderr does not carry usage:\n%s", res.stderr)
			}
		})
	}
}

func TestMainDispatchesEachCommandToItsOwnFlagSet(t *testing.T) {
	marker := map[string]string{
		"run":     "-metrics-addr",
		"info":    "-pin-path",
		"stats":   "-json",
		"top":     "-map",
		"inspect": "-watch",
		"dump":    "-map",
		"health":  "-all",
		"clear":   "-ip",
	}
	for _, cmd := range dispatchedCommands {
		t.Run(cmd, func(t *testing.T) {
			res := runCLI(t, cmd, "-h")
			if res.code != 0 {
				t.Fatalf("exit code %d, want 0; stderr:\n%s", res.code, res.stderr)
			}
			if !strings.Contains(res.stderr, "Usage of "+cmd+":") {
				t.Errorf("stderr is not the %s flag usage:\n%s", cmd, res.stderr)
			}
			if !strings.Contains(res.stderr, marker[cmd]) {
				t.Errorf("stderr does not list %s:\n%s", marker[cmd], res.stderr)
			}
		})
	}
}
