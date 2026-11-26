package admin

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var replaceFile = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReplaceFileW")

// ReplaceFileW retains the existing file's DACL when replacing its contents.
func installConfig(temp, dest string) error {
	dst, err := windows.UTF16PtrFromString(dest)
	if err != nil { return err }
	src, err := windows.UTF16PtrFromString(temp)
	if err != nil { return err }
	ok, _, callErr := replaceFile.Call(uintptr(unsafe.Pointer(dst)), uintptr(unsafe.Pointer(src)), 0, 0, 0, 0)
	if ok == 0 { return callErr }
	return nil
}
