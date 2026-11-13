//go:build windows

package main

import (
	"os/exec"
	"syscall"
	"unsafe"
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleCP   = kernel32.NewProc("SetConsoleOutputCP")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

// initConsole: 控制台切到 UTF-8（避免中文乱码），并尝试开启 ANSI 颜色。
// 返回 false 表示该控制台不支持 ANSI，调用方应关闭颜色。
func initConsole() bool {
	// 65001 = UTF-8
	procSetConsoleCP.Call(uintptr(65001))

	h, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	if err != nil {
		return false
	}
	var mode uint32
	r, _, _ := procGetConsoleMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return false
	}
	const enableVirtualTerminalProcessing = 0x0004
	r, _, _ = procSetConsoleMode.Call(uintptr(h), uintptr(mode|enableVirtualTerminalProcessing))
	return r != 0
}

// hideWindow: 调用 route/ping/wmic 时不弹出控制台黑框
func hideWindow(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
}
