//go:build windows

package app

import (
	"os"
	"syscall"
	"unsafe"
)

var getConsoleMode = syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleMode")

func isTerminal(file *os.File) bool {
	var mode uint32
	result, _, _ := getConsoleMode.Call(file.Fd(), uintptr(unsafe.Pointer(&mode)))
	return result != 0
}
