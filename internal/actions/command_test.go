package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nem1989/hookbox/internal/config"
)

func TestMain(m *testing.M) {
	if len(os.Args) >= 3 && os.Args[1] == "hookbox-test-child" {
		os.Exit(helper(os.Args[2:]))
	}
	os.Exit(m.Run())
}

func helper(args []string) int {
	switch args[0] {
	case "echo":
		b, _ := io.ReadAll(os.Stdin)
		d, _ := os.Getwd()
		json.NewEncoder(os.Stdout).Encode([]string{string(b), d, os.Getenv("HB_INHERIT"), os.Getenv("HB_VALUE"), args[1]})
	case "output":
		n, _ := strconv.Atoi(args[1])
		fmt.Fprint(os.Stdout, strings.Repeat("x", n))
		fmt.Fprint(os.Stderr, strings.Repeat("y", n))
	case "bytes":
		os.Stdout.Write([]byte{0xff})
	case "fail":
		fmt.Fprint(os.Stderr, "private diagnostic")
		return 7
	case "sleep":
		time.Sleep(time.Minute)
	case "descendant":
		os.WriteFile(args[1], []byte("ready"), 0600)
		for {
			if _, err := os.Stat(args[1]+".release"); err == nil {
				os.WriteFile(args[1]+".survived", nil, 0600)
				return 0
			}
			time.Sleep(10 * time.Millisecond)
		}
	case "spawn":
		child := exec.Command(os.Args[0], "hookbox-test-child", "descendant", args[2])
		if args[1] != "detached-stdio" {
			child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
		}
		if err := child.Start(); err != nil {
			return 8
		}
		for {
			if _, err := os.Stat(args[2]); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if args[1] == "live-parent" {
			time.Sleep(time.Minute)
		}
	default:
		return 9
	}
	return 0
}

func action(t *testing.T, args ...string) config.Action {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return config.Action{Type: "command", Command: append([]string{exe, "hookbox-test-child"}, args...),
		Cwd: t.TempDir(), Stdin: true, MaxOutput: 65536, Timeout: 10,
		Env: map[string]string{"GORACE": "atexit_sleep_ms=0"}}
}

func TestCommandInput(t *testing.T) {
	t.Setenv("HB_INHERIT", "inherited")
	t.Setenv("HB_VALUE", "old")
	const literal = "spaces & echo \"Привет\" > marker"
	a := action(t, "echo", literal)
	a.Env["HB_VALUE"] = "configured"
	for _, tc := range []struct {
		send bool
		body, want string
	}{{true, `{"msg":"мир"}`, `{"msg":"мир"}`}, {true, "", "null"}, {false, `"private"`, ""}} {
		a.Stdin = tc.send
		got, err := RunCommand(t.Context(), a, json.RawMessage(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		if err := json.Unmarshal([]byte(got.Stdout), &out); err != nil || len(out) != 5 {
			t.Fatalf("invalid output %q", got.Stdout)
		}
		if out[0] != tc.want || out[1] != a.Cwd || out[2] != "inherited" || out[3] != "configured" || out[4] != literal ||
			got.Type != "command" || got.ExitCode != 0 || got.Stderr != "" || got.Truncated {
			t.Fatalf("unexpected result: %#v", got)
		}
	}
}

func TestCommandStreams(t *testing.T) {
	for _, n := range []int{4, 5, 200000} {
		a := action(t, "output", strconv.Itoa(n))
		a.MaxOutput = 4
		got, err := RunCommand(t.Context(), a, json.RawMessage(strings.Repeat(" ", 1<<20)+"null"))
		if err != nil || got.Stdout != "xxxx" || got.Stderr != "yyyy" || got.Truncated != (n > 4) {
			t.Fatalf("%d bytes: %#v, %v", n, got, err)
		}
	}
	got, err := RunCommand(t.Context(), action(t, "bytes"), nil)
	if err != nil || got.Stdout != "�" {
		t.Fatalf("bad UTF-8: %#v, %v", got, err)
	}
}

func TestCommandFailures(t *testing.T) {
	a := action(t, "fail")
	if _, err := RunCommand(t.Context(), a, nil); err != commandFailed || strings.Contains(err.Error(), "private") {
		t.Fatal(err)
	}
	a.Command[0] = filepath.Join(t.TempDir(), "missing")
	if _, err := RunCommand(t.Context(), a, nil); err != startFailed {
		t.Fatal(err)
	}
	a = action(t, "sleep")
	a.Timeout = .15
	if _, err := RunCommand(t.Context(), a, json.RawMessage(strings.Repeat(" ", 1<<20)+"null")); err != timedOut {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := RunCommand(ctx, a, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestCaptureUTF8(t *testing.T) {
	for input, want := range map[string]string{
		"мир": "мир", "\xff\xff": "��", "\xe2\x82": "�", "\xe2\x82X": "�X",
		"\xe0\x80\x80": "���", "\xf0\x9f\x98\x80": "😀",
	} {
		if got := outputText([]byte(input)); got != want {
			t.Errorf("%x: got %q, want %q", input, got, want)
		}
	}
}

func TestCommandFromConfig(t *testing.T) {
	original := action(t, "output", "4")
	path := original.Command[0]
	t.Setenv("HB_TEST_BIN", filepath.Base(path))
	t.Setenv("HB_TEST_DIR", filepath.Dir(path))
	cfg, err := config.Load([]byte(`webhook:
  sample:
    actions:
      - type: command
        command: ['${HB_TEST_BIN}', hookbox-test-child, output, '4']
        env:
          PATH: '${HB_TEST_DIR}'
security: {}
`), original.Cwd)
	if err != nil {
		t.Fatal(err)
	}
	got, err := RunCommand(t.Context(), cfg.Hooks["sample"].Actions[0], nil)
	if err != nil || got.Stdout != "xxxx" || got.Stderr != "yyyy" {
		t.Fatalf("configured executable: %#v, %v", got, err)
	}
}

func TestCommandTree(t *testing.T) {
	for _, mode := range []string{"live-parent", "exited-parent", "detached-stdio"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			ready := filepath.Join(t.TempDir(), "child")
			a := action(t, "spawn", mode, ready)
			a.Timeout = 3
			_, err := RunCommand(t.Context(), a, nil)
			if mode == "detached-stdio" && err != nil || mode != "detached-stdio" && err != timedOut {
				t.Fatalf("unexpected action status: %v", err)
			}
			if _, err := os.Stat(ready); err != nil {
				t.Fatal("descendant never started", err)
			}
			if err := os.WriteFile(ready+".release", nil, 0600); err != nil {
				t.Fatal(err)
			}
			time.Sleep(300 * time.Millisecond)
			if _, err := os.Stat(ready+".survived"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("descendant survived cleanup", err)
			}
		})
	}
}
