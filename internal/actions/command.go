package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/nem1989/hookbox/internal/config"
)

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"-"`
}

func (e *Error) Error() string { return e.Message }

type CommandResult struct {
	Type      string `json:"type"`
	ExitCode  int    `json:"exit_code"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Truncated bool   `json:"output_truncated"`
}

var (
	startFailed   = &Error{"command_failed", "Command could not be started.", 502}
	commandFailed = &Error{"command_failed", "Command returned a nonzero exit code.", 502}
	timedOut      = &Error{"action_timeout", "Action exceeded its timeout.", 504}
	ioFailed      = &Error{"command_failed", "Command input or output could not be processed.", 502}
)

// Keep draining after reaching the limit, even while the other pipe is busy.
type capture struct {
	data      bytes.Buffer
	limit     int64
	truncated bool
}

func (c *capture) Write(p []byte) (int, error) {
	n := min(int64(len(p)), c.limit-int64(c.data.Len()))
	c.data.Write(p[:n])
	c.truncated = c.truncated || n < int64(len(p))
	return len(p), nil
}

// Replace each malformed UTF-8 subsequence once, including an incomplete
// multibyte character at the capture boundary (Python errors="replace").
func outputText(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var text strings.Builder
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		if r == utf8.RuneError && n == 1 {
			for n < len(b) && n < utf8.UTFMax && !utf8.FullRune(b[:n+1]) {
				n++
			}
		}
		text.WriteRune(r)
		b = b[n:]
	}
	return text.String()
}

type processTree interface {
	waitRoot() error // Observe exit while retaining the identity of the root.
	stop() error
	reap() (int, error)
}

// RunCommand accepts a validated action and the JSON body received by the hook.
func RunCommand(parent context.Context, a config.Action, payload json.RawMessage) (CommandResult, error) {
	var result CommandResult
	ctx, cancel := context.WithTimeout(parent, config.Timeout(a.Timeout))
	defer cancel()
	if ctx.Err() != nil {
		return result, contextError(ctx)
	}
	if len(a.Command) == 0 || a.MaxOutput < 0 {
		return result, startFailed
	}
	if !a.Stdin {
		payload = nil
	} else if len(payload) == 0 {
		payload = json.RawMessage("null")
	}

	// Child ends are closed in the parent immediately after starting the process.
	var child, host [3]*os.File
	for i := range child {
		r, w, err := os.Pipe()
		if err != nil {
			return result, startFailed
		}
		defer r.Close()
		defer w.Close()
		child[i], host[i] = w, r
		if i == 0 {
			child[i], host[i] = r, w
		}
	}
	env := exec.Command(a.Command[0])
	env.Dir = a.Cwd
	vars := env.Environ()
	for k, v := range a.Env {
		vars = append(vars, k+"="+v)
	}
	env.Env = vars
	vars = env.Environ() // Deduplicate using the OS's environment key rules.
	path, err := executable(a.Command[0], a.Cwd, vars)
	if err != nil {
		return result, startFailed
	}
	tree, err := startTree(path, a.Command, a.Cwd, vars, child)
	if err != nil {
		return result, startFailed
	}
	for _, f := range child {
		f.Close()
	}

	stdout, stderr := capture{limit: a.MaxOutput}, capture{limit: a.MaxOutput}
	var streams sync.WaitGroup
	var readErr [2]error
	for i, dest := range []*capture{&stdout, &stderr} {
		streams.Add(1)
		go func() {
			defer streams.Done()
			_, readErr[i] = io.Copy(dest, host[i+1])
		}()
	}
	streams.Add(1)
	go func() {
		defer streams.Done()
		defer host[0].Close()
		// Closing stdin early is valid. Only the process exit code determines success.
		_, _ = io.Copy(host[0], bytes.NewReader(payload))
	}()
	done := make(chan error, 1)
	go func() {
		err := tree.waitRoot()
		if err == nil {
			streams.Wait()
		}
		done <- err
	}()

	var waitErr, deadlineErr error
	select {
	case waitErr = <-done:
	case <-ctx.Done():
		deadlineErr = contextError(ctx)
	}
	stopErr := tree.stop()
	if deadlineErr != nil || waitErr != nil {
		for _, f := range host {
			f.Close()
		}
		if deadlineErr != nil {
			waitErr = <-done
		}
		streams.Wait()
	}
	exitCode, reapErr := tree.reap()
	if deadlineErr != nil {
		return result, deadlineErr
	}
	if errors.Join(waitErr, stopErr, reapErr, readErr[0], readErr[1]) != nil {
		return result, ioFailed
	}
	if exitCode != 0 {
		return result, commandFailed
	}
	return CommandResult{"command", exitCode, outputText(stdout.data.Bytes()),
		outputText(stderr.data.Bytes()), stdout.truncated || stderr.truncated}, nil
}

func contextError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return timedOut
	}
	return ctx.Err()
}

func executable(name, dir string, env []string) (string, error) {
	if !filepath.IsLocal(name) || strings.ContainsAny(name, string(filepath.Separator)+"/") {
		if !filepath.IsAbs(name) {
			name = filepath.Join(dir, name)
		}
		name, err := filepath.Abs(name)
		if err != nil {
			return "", err
		}
		return exec.LookPath(name)
	}
	for _, entry := range env {
		key, value, _ := strings.Cut(entry, "=")
		if key != "PATH" && !(runtime.GOOS == "windows" && strings.EqualFold(key, "PATH")) {
			continue
		}
		for _, folder := range filepath.SplitList(value) {
			if !filepath.IsAbs(folder) {
				folder = filepath.Join(dir, folder)
			}
			candidate, err := filepath.Abs(filepath.Join(folder, name))
			if err == nil {
				if path, err := exec.LookPath(candidate); err == nil {
					return path, nil
				}
			}
		}
	}
	return "", exec.ErrNotFound
}
