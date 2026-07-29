//go:build darwin

package app

import (
	"os"
	"syscall"
	"unsafe"
)

func isTerminal(file *os.File) bool {
	var state syscall.Termios
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		file.Fd(),
		uintptr(syscall.TIOCGETA),
		uintptr(unsafe.Pointer(&state)),
		0,
		0,
		0,
	)
	return errno == 0
}
