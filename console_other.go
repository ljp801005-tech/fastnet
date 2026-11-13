//go:build !windows

package main

import "os/exec"

// 非 Windows 平台终端默认支持 ANSI
func initConsole() bool { return true }

// 非 Windows 平台无需隐藏窗口
func hideWindow(cmd *exec.Cmd) { _ = cmd }
