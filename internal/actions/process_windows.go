package actions

import (
	"os"
	"runtime"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsTree struct{ root, job windows.Handle }

// PROC_THREAD_ATTRIBUTE_JOB_LIST assigns the job during CreateProcessW, before
// the first user instruction. Only the three named pipe handles are inherited.
const procThreadAttributeJobList = 0x0002000d

func startTree(path string, argv []string, dir string, env []string, files [3]*os.File) (processTree, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	root, err := launchInJob(job, path, argv, dir, env, files)
	if err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	return windowsTree{root, job}, nil
}

func launchInJob(job windows.Handle, path string, argv []string, dir string, env []string, files [3]*os.File) (windows.Handle, error) {
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)))
	if err != nil {
		return 0, err
	}
	attrs, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return 0, err
	}
	defer attrs.Delete()
	if err := attrs.Update(procThreadAttributeJobList, unsafe.Pointer(&job), unsafe.Sizeof(job)); err != nil {
		return 0, err
	}
	var pipes [3]windows.Handle
	for i, file := range files {
		err := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(file.Fd()),
			windows.CurrentProcess(), &pipes[i], 0, true, windows.DUPLICATE_SAME_ACCESS)
		if err != nil {
			return 0, err
		}
		defer windows.CloseHandle(pipes[i])
	}
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&pipes[0]), unsafe.Sizeof(pipes)); err != nil {
		return 0, err
	}
	var startup windows.StartupInfoEx
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.Flags = windows.STARTF_USESTDHANDLES
	startup.StdInput, startup.StdOutput, startup.StdErr = pipes[0], pipes[1], pipes[2]
	startup.ProcThreadAttributeList = attrs.List()
	app, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	args, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(argv))
	if err != nil {
		return 0, err
	}
	var cwd *uint16
	if dir != "" {
		cwd, err = windows.UTF16PtrFromString(dir)
		if err != nil {
			return 0, err
		}
	}
	slices.SortFunc(env, func(a, b string) int { return strings.Compare(strings.ToUpper(a), strings.ToUpper(b)) })
	var block []uint16
	for _, item := range env {
		encoded, err := windows.UTF16FromString(item)
		if err != nil {
			return 0, err
		}
		block = append(block, encoded...)
	}
	block = append(block, 0, 0)
	var pi windows.ProcessInformation
	err = windows.CreateProcess(app, args, nil, nil, true,
		windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW,
		&block[0], cwd, &startup.StartupInfo, &pi)
	runtime.KeepAlive(files)
	if err != nil {
		return 0, err
	}
	windows.CloseHandle(pi.Thread)
	return pi.Process, nil
}

func (t windowsTree) waitRoot() error {
	_, err := windows.WaitForSingleObject(t.root, windows.INFINITE)
	return err
}

func (t windowsTree) stop() error {
	// Closing our only job handle kills remaining descendants, including any
	// still holding stdio after the root exited.
	return windows.CloseHandle(t.job)
}

func (t windowsTree) reap() (int, error) {
	defer windows.CloseHandle(t.root)
	var code uint32
	err := windows.GetExitCodeProcess(t.root, &code)
	return int(code), err
}
