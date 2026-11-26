package actions

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type linuxTree struct{ root *os.Process }

func startTree(path string, argv []string, dir string, env []string, files [3]*os.File) (processTree, error) {
	root, err := os.StartProcess(path, argv, &os.ProcAttr{
		Dir: dir, Env: env, Files: files[:], Sys: &syscall.SysProcAttr{Setsid: true},
	})
	if err != nil {
		return nil, err
	}
	return linuxTree{root}, nil
}

func (t linuxTree) waitRoot() error {
	// Do not reap the group leader until after killpg. Its PID cannot be reused.
	var status unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, t.root.Pid, &status, unix.WEXITED|unix.WNOWAIT, nil)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

func (t linuxTree) stop() error {
	err := unix.Kill(-t.root.Pid, unix.SIGKILL)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func (t linuxTree) reap() (int, error) {
	state, err := t.root.Wait()
	if err != nil {
		return -1, err
	}
	return state.ExitCode(), nil
}
