package main

// 把移动版页面共享到局域网：手机浏览器打开 http://<电脑IP>:8899 即可使用，
// 可「添加到主屏幕」当 App 用，比传 HTML 文件到手机更省事。

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const mobileHTMLName = "FastNet-Android.html"

func findMobileHTML() ([]byte, string) {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		dirs = append(dirs, wd)
	}
	for _, d := range dirs {
		for _, rel := range []string{mobileHTMLName, filepath.Join("mobile", mobileHTMLName)} {
			p := filepath.Join(d, rel)
			if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
				return b, p
			}
		}
	}
	return nil, ""
}

func runWeb(port string) {
	data, path := findMobileHTML()
	if data == nil {
		title("手机版页面共享")
		bad("没找到 " + mobileHTMLName)
		info("请把 " + mobileHTMLName + " 与 fastnet 放在同一目录后重试")
		return
	}
	addr := ":" + defStr(strings.TrimSpace(port), "8899")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		bad("端口被占用或无法监听: " + err.Error())
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(data)
	})

	title("手机版页面已共享到局域网")
	ok(fmt.Sprintf("页面文件: %s（%d KB）", path, len(data)/1024))
	fmt.Println()
	p := portOf(ln.Addr().String())
	shown := 0
	if v4, _, _ := localAddrs(); len(v4) > 0 {
		for _, s := range v4 {
			ip := strings.Fields(s)[0]
			info("手机浏览器打开: http://" + net.JoinHostPort(ip, p))
			shown++
		}
	}
	if shown == 0 {
		info("未找到局域网地址，请确认已连接 Wi-Fi/网线")
	}
	fmt.Println()
	info("手机与电脑需在同一 Wi-Fi / 局域网")
	info("打开后可用浏览器菜单「添加到主屏幕」，下次一点即用")
	info("按 Ctrl+C 停止共享")
	fmt.Println()
	if err := http.Serve(ln, mux); err != nil {
		bad("服务异常退出: " + err.Error())
	}
}
