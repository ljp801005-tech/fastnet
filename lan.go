package main

// 内网带宽测速：测「运行本程序的电脑 ↔ 路由器/内网设备」这段链路。
// 不经过公网，不消耗任何外部测速服务额度。

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- 结果结构 ----------

type lanResult struct {
	Gateway   string  `json:"gateway"`
	LocalIP   string  `json:"localIp"`
	LinkSpeed string  `json:"linkSpeed,omitempty"`
	LatencyMs float64 `json:"latencyMs"`
	JitterMs  float64 `json:"jitterMs"`
	LossPct   float64 `json:"lossPct"`
	Endpoint  string  `json:"endpoint,omitempty"`
	DownMbps  float64 `json:"downMbps"`
	UpMbps    float64 `json:"upMbps"`
	Conns     int     `json:"conns,omitempty"`
	UtilPct   float64 `json:"utilPct,omitempty"`
	Verdict   string  `json:"verdict,omitempty"`
	Err       string  `json:"error,omitempty"`
}

// ---------- 执行外部命令（不弹黑框） ----------

func runCmd(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	hideWindow(cmd)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return ""
	}
	return string(out)
}

func firstMatch(s, pattern string) string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}
	if m := re.FindStringSubmatch(s); len(m) > 1 {
		return m[1]
	}
	return ""
}

// ---------- 网关与本地地址 ----------

const reIPv4 = `(\d{1,3}(?:\.\d{1,3}){3})`

// 通过一次「不发包的 UDP 连接」拿到默认路由所用的本机地址
func localIPForRoute() string {
	c, err := net.Dial("udp4", "223.5.5.5:53")
	if err != nil {
		return ""
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
}

func guessGateways(local string) []string {
	parts := strings.Split(local, ".")
	if len(parts) != 4 {
		return nil
	}
	base := parts[0] + "." + parts[1] + "." + parts[2] + "."
	return []string{base + "1", base + "254"}
}

// 找出「与网关同网段」的本机地址。代理/TUN 开启时，按默认路由取到的是
// 198.18.x.x 这类假地址，对内网测速没有意义，必须换成真实网卡地址。
func lanLocalIP(gw string) string {
	ifaces, err := net.Interfaces()
	if err == nil {
		var gwnet net.IP
		if gw != "" {
			gwnet = net.ParseIP(gw)
		}
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				ipn, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				ip4 := ipn.IP.To4()
				if ip4 == nil || isFakeIPv4(ip4) {
					continue
				}
				if gwnet != nil && ipn.Contains(gwnet) {
					return ip4.String()
				}
			}
		}
	}
	if local := localIPForRoute(); local != "" && !isFakeIPv4(net.ParseIP(local)) {
		return local
	}
	if v4, _, _ := localAddrs(); len(v4) > 0 {
		return strings.Fields(v4[0])[0]
	}
	return ""
}

func detectGateway() (gw, local string) {
	local = localIPForRoute()
	if local != "" && isFakeIPv4(net.ParseIP(local)) {
		// 代理 TUN 会返回 198.18.x.x，换成真实网卡地址
		if v4, _, _ := localAddrs(); len(v4) > 0 {
			local = strings.Fields(v4[0])[0]
		}
	}
	var out string
	switch runtime.GOOS {
	case "windows":
		out = runCmd("route", "print", "-4")
		if out == "" {
			out = runCmd("route", "print")
		}
		gw = firstMatch(out, `(?m)^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+`+reIPv4)
	case "darwin":
		out = runCmd("route", "-n", "get", "default")
		gw = firstMatch(out, `(?m)^\s*gateway:\s*`+reIPv4)
	default:
		out = runCmd("ip", "route", "show", "default")
		gw = firstMatch(out, `(?m)\bvia\s+`+reIPv4)
	}
	if gw == "" && local != "" {
		// 系统路由表不可用时，退回同网段 .1 / .254 猜测，并用 TCP 探测确认
		for _, cand := range guessGateways(local) {
			if n := openPorts(cand, []int{80, 443, 3200, 3300, 8080, 53, 22}, 400*time.Millisecond); len(n) > 0 {
				return cand, local
			}
		}
		gw = guessGateways(local)[0]
	}
	return
}

func openPorts(host string, ports []int, timeout time.Duration) []int {
	ch := make(chan int, len(ports))
	for _, p := range ports {
		go func(p int) {
			if _, err := tcpRTT(net.JoinHostPort(host, strconv.Itoa(p)), timeout); err == nil {
				ch <- p
				return
			}
			ch <- 0
		}(p)
	}
	var got []int
	for range ports {
		if p := <-ch; p != 0 {
			got = append(got, p)
		}
	}
	return got
}

func firstOpenPort(host string, ports []int, timeout time.Duration) int {
	best, bestD := 0, time.Duration(1<<62)
	for _, p := range openPorts(host, ports, timeout) {
		if d, err := tcpRTT(net.JoinHostPort(host, strconv.Itoa(p)), timeout); err == nil && d < bestD {
			best, bestD = p, d
		}
	}
	return best
}

// ---------- 网卡协商速率（判断「本地带宽」的物理上限） ----------

func nicLinkSpeed(local string) (label string, bps int64) {
	if local == "" {
		return "", 0
	}
	var ifName string
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.String() == local {
					ifName = ifc.Name
				}
			}
		}
	}
	switch runtime.GOOS {
	case "windows":
		out := runCmd("wmic", "nic", "where", "NetEnabled=true", "get", "Speed", "/format:list")
		for _, m := range regexp.MustCompile(`Speed=(\d+)`).FindAllStringSubmatch(out, -1) {
			n, _ := strconv.ParseInt(m[1], 10, 64)
			if n > bps {
				bps = n
			}
		}
	case "darwin":
		if ifName != "" {
			out := runCmd("ifconfig", ifName)
			if m := regexp.MustCompile(`media:\s*([^\s<]+)`).FindStringSubmatch(out); len(m) > 1 {
				// Wi-Fi / 部分网卡只报 autoselect，没有可用速率，直接跳过
				if regexp.MustCompile(`\d`).MatchString(m[1]) {
					label = m[1]
				}
			}
		}
	default:
		if ifName != "" {
			if b, err := os.ReadFile("/sys/class/net/" + ifName + "/speed"); err == nil {
				n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
				if n > 0 {
					bps = n * 1000000
				}
			}
		}
	}
	if bps > 0 {
		label = rate(float64(bps))
	}
	if label != "" && bps > 0 {
		label = fmt.Sprintf("%s（网卡协商速率）", label)
	}
	return
}

// ---------- 到网关的延迟（先 ICMP，再 TCP 兜底） ----------

func parsePingTimes(out string) []float64 {
	// 不依赖语言：Windows「时间=1ms」/ 英文「time=1ms」/ *nix「time=0.876 ms」都能命中
	re := regexp.MustCompile(`[=<＜]?\s*(\d+(?:\.\d+)?)\s*ms`)
	var vals []float64
	for _, m := range re.FindAllStringSubmatch(out, -1) {
		v, err := strconv.ParseFloat(m[1], 64)
		if err == nil {
			vals = append(vals, v)
		}
		if len(vals) >= 6 {
			break
		}
	}
	return vals
}

func pingGateway(gw string) []float64 {
	var out string
	switch runtime.GOOS {
	case "windows":
		out = runCmd("ping", "-4", "-n", "6", "-w", "800", gw)
	case "darwin":
		out = runCmd("ping", "-c", "6", "-W", "800", gw)
	default:
		out = runCmd("ping", "-c", "6", "-W", "1", gw)
	}
	return parsePingTimes(out)
}

func tcpLatency(addr string, rounds int) []float64 {
	var vals []float64
	for i := 0; i < rounds; i++ {
		d, err := tcpRTT(addr, 900*time.Millisecond)
		if err != nil {
			continue
		}
		if i == 0 {
			continue // 首包可能含 ARP 解析，丢弃
		}
		vals = append(vals, float64(d.Microseconds())/1000.0)
	}
	return vals
}

func statLatency(vals []float64) (avg, jitter float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	avg = sum / float64(len(vals))
	if len(vals) > 1 {
		var j float64
		for i := 1; i < len(vals); i++ {
			d := vals[i] - vals[i-1]
			if d < 0 {
				d = -d
			}
			j += d
		}
		jitter = j / float64(len(vals)-1)
	}
	return
}

// ---------- 测速端点探测 ----------

type lanEndpoint struct {
	Host     string
	Port     int
	Base     string
	DownPath string // 含一个 %d 占位（字节数）
	UpPath   string
}

func (e *lanEndpoint) downURL(size int) string {
	return e.Base + fmt.Sprintf(e.DownPath, size)
}

func lanClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               nil, // 内网一律直连
			DialContext:         (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConnsPerHost: 32,
			DisableCompression:  true, // 避免 gzip 让字节统计失真
		},
	}
}

var (
	downTemplates = []string{
		"/download?bytes=%d",
		"/download?size=%d&count=1",
		"/download?size=%d",
		"/__down?bytes=%d",
		"/speedtest/download?size=%d",
	}
	upPaths = []string{"/upload", "/__up", "/speedtest/upload"}
)

func probeSpeedEndpoint(host string, port int) *lanEndpoint {
	base := "http://" + net.JoinHostPort(host, strconv.Itoa(port))
	cli := lanClient(1500 * time.Millisecond)
	defer cli.CloseIdleConnections()
	const want = 2 << 20
	for _, tpl := range downTemplates {
		u := base + fmt.Sprintf(tpl, want)
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := cli.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			continue
		}
		n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, want))
		resp.Body.Close()
		if n < 1<<20 { // 普通网页不会返回 1MB 以上
			continue
		}
		ep := &lanEndpoint{Host: host, Port: port, Base: base, DownPath: tpl}
		for _, up := range upPaths {
			if probeUpload(cli, base+up) {
				ep.UpPath = up
				break
			}
		}
		return ep
	}
	return nil
}

func probeUpload(cli *http.Client, u string) bool {
	payload := make([]byte, 256<<10)
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return false
	}
	req.ContentLength = int64(len(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := cli.Do(req)
	if err != nil {
		return false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode < 400
}

func findEndpoint(host string, forcePort int) *lanEndpoint {
	ports := []int{3300, 3200, 8080, 8000, 80}
	if forcePort > 0 {
		ports = []int{forcePort}
	}
	type r struct{ ep *lanEndpoint }
	ch := make(chan r, len(ports))
	for _, p := range ports {
		go func(p int) { ch <- r{probeSpeedEndpoint(host, p)} }(p)
	}
	for range ports {
		if v := <-ch; v.ep != nil {
			return v.ep
		}
	}
	return nil
}

// ---------- 吞吐量测试 ----------

func clearProgressLine() {
	fmt.Print("\r" + strings.Repeat(" ", 80) + "\r")
}

func lanDownloadTest(ep *lanEndpoint, seconds, conns int) (float64, int64) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
	defer cancel()
	var total int64
	start := time.Now()
	done := make(chan struct{})
	go speedProgress("下行", &total, start, done)

	var wg sync.WaitGroup
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cli := lanClient(30 * time.Second)
			defer cli.CloseIdleConnections()
			for ctx.Err() == nil {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.downURL(16<<20), nil)
				if err != nil {
					return
				}
				resp, err := cli.Do(req)
				if err != nil {
					return
				}
				if resp.StatusCode != http.StatusOK {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					return
				}
				n, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				atomic.AddInt64(&total, n)
				if n == 0 {
					return
				}
			}
		}()
	}
	wg.Wait()
	close(done)
	clearProgressLine()

	el := time.Since(start).Seconds()
	b := atomic.LoadInt64(&total)
	if el <= 0 || b == 0 {
		return 0, b
	}
	return float64(b) * 8 / el / 1e6, b
}

func lanUploadTest(ep *lanEndpoint, seconds, conns int) (float64, int64) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
	defer cancel()
	payload := make([]byte, 4<<20)
	var total int64
	start := time.Now()
	done := make(chan struct{})
	go speedProgress("上行", &total, start, done)

	var wg sync.WaitGroup
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cli := lanClient(30 * time.Second)
			defer cli.CloseIdleConnections()
			for ctx.Err() == nil {
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.Base+ep.UpPath, bytes.NewReader(payload))
				if err != nil {
					return
				}
				req.ContentLength = int64(len(payload))
				req.Header.Set("Content-Type", "application/octet-stream")
				resp, err := cli.Do(req)
				if err != nil {
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode >= 400 {
					return
				}
				atomic.AddInt64(&total, int64(len(payload)))
			}
		}()
	}
	wg.Wait()
	close(done)
	clearProgressLine()

	el := time.Since(start).Seconds()
	b := atomic.LoadInt64(&total)
	if el <= 0 || b == 0 {
		return 0, b
	}
	return float64(b) * 8 / el / 1e6, b
}

// ---------- 主流程 ----------

var lanProbePorts = []int{80, 443, 3200, 3300, 8080, 8000, 5000, 22, 53}

func parseHostPort(s string) (string, int) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "http://"), "https://")
	s = strings.TrimSuffix(s, "/")
	if s == "" {
		return "", 0
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, _ := strconv.Atoi(p)
		return h, n
	}
	return s, 0
}

func defStr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func runLAN(target string, interactive bool) *lanResult {
	title("内网带宽测速（电脑 ↔ 路由器 / 内网设备）")
	r := &lanResult{}

	gw, _ := detectGateway()
	local := defStr(lanLocalIP(gw), "未知")
	r.LocalIP = local
	r.Gateway = gw

	line("本机地址", local)
	if gw == "" {
		bad("未识别到默认网关（可能使用的是移动网络 / VPN 全局代理）")
	} else {
		line("默认网关", gw)
	}
	linkLabel, linkBps := nicLinkSpeed(local)
	if linkLabel != "" {
		r.LinkSpeed = linkLabel
		line("网卡链路", linkLabel)
	}

	if interactive {
		fmt.Printf("  目标（回车=网关 %s；也可填内网其它设备 IP:Port）: ", defStr(gw, "未识别"))
		if v := strings.TrimSpace(readLine()); v != "" {
			target = v
		}
	}

	host, port := parseHostPort(target)
	if host == "" {
		host = gw
	}
	if host == "" {
		r.Err = "无可用目标"
		return r
	}

	// ---- 1) 到目标的时延 ----
	fmt.Println()
	vals := pingGateway(host)
	method := "ICMP"
	if len(vals) == 0 {
		p := port
		if p == 0 {
			p = firstOpenPort(host, lanProbePorts, 500*time.Millisecond)
		}
		if p > 0 {
			vals = tcpLatency(net.JoinHostPort(host, strconv.Itoa(p)), 8)
			method = fmt.Sprintf("TCP %d 端口", p)
			if port == 0 {
				port = p
			}
		}
	}
	if len(vals) == 0 {
		warn("时延测量失败（ICMP 与 TCP 均无响应）")
	} else {
		r.LatencyMs, r.JitterMs = statLatency(vals)
		r.LossPct = float64(5-len(vals)) / 5 * 100
		if r.LossPct < 0 {
			r.LossPct = 0
		}
		msg := fmt.Sprintf("%.2f ms   抖动 %.2f ms   丢包 %.0f%%   （%s）", r.LatencyMs, r.JitterMs, r.LossPct, method)
		if r.LatencyMs > 10 {
			warn(msg)
		} else {
			ok(msg)
		}
	}

	// ---- 2) 找测速端点 ----
	fmt.Println()
	info("正在探测目标设备上的测速端点（需设备提供 /download /upload）…")
	ep := findEndpoint(host, portIfForced(target))
	if ep == nil {
		warn("未找到可用的测速端点，无法测吞吐")
		fmt.Println()
		info("三种可用做法：")
		info("  ① 目标设备是 OpenWrt/FastNet 类固件 → 确认 3200/3300 端口服务已启动")
		info("  ② 同网段另一台电脑运行：fastnet.exe serve，然后用菜单 8 填它的 IP:5201")
		info("  ③ 有 NAS/内网服务器 → 菜单 7 输入它的 IP:Port 测 HTTP 下载")
		if linkBps > 0 {
			fmt.Println()
			info(fmt.Sprintf("链路物理上限约 %s，仅凭网卡协商速率无法得知真实吞吐", rate(float64(linkBps))))
		}
		r.Verdict = "未找到测速端点"
		return r
	}
	r.Endpoint = ep.Base
	ok(fmt.Sprintf("测速端点: %s  下载 %s", ep.Base, strings.Split(ep.DownPath, "?")[0]))
	if ep.UpPath != "" {
		info("上传端点: " + ep.Base + ep.UpPath)
	} else {
		warn("该端点不支持上传，只测下行")
	}

	// ---- 3) 双向吞吐 ----
	const seconds = 5
	conns := 4
	if cfg.SpeedConns > 4 {
		conns = cfg.SpeedConns
	}
	r.Conns = conns
	fmt.Println()
	info(fmt.Sprintf("开始测速，时长 %d 秒 / %d 连接（期间请勿同时下载大文件）", seconds, conns))
	fmt.Println()
	r.DownMbps, _ = lanDownloadTest(ep, seconds, conns)
	if r.DownMbps > 0 {
		ok(fmt.Sprintf("下行（设备 → 本机）  %s", rate(r.DownMbps*1e6)))
	} else {
		warn("下行测速未取得有效数据")
	}
	if ep.UpPath != "" {
		r.UpMbps, _ = lanUploadTest(ep, seconds, conns)
		if r.UpMbps > 0 {
			ok(fmt.Sprintf("上行（本机 → 设备）  %s", rate(r.UpMbps*1e6)))
		} else {
			warn("上行测速未取得有效数据")
		}
	} else {
		info("该设备未提供上传端点，跳过上行")
	}

	// ---- 4) 结论 ----
	if linkBps > 0 && r.DownMbps > 0 {
		r.UtilPct = r.DownMbps * 1e6 / float64(linkBps) * 100
	}
	fmt.Println()
	switch {
	case r.DownMbps == 0:
		r.Verdict = "测速失败"
	case r.UtilPct >= 85:
		r.Verdict = "链路已跑满"
		ok(r.Verdict + "，这段网线/交换机没有问题")
	case r.DownMbps > 88 && r.DownMbps < 100 && linkBps > 500000000:
		r.Verdict = "疑似百兆瓶颈"
		warn("链路协商在千兆，但实测只有百兆水平 → 大概率是网线只通了 4 芯、水晶头氧化或网线质量差，换根 Cat5e/Cat6 网线即可")
	case r.UtilPct > 0 && r.UtilPct < 50:
		r.Verdict = "吞吐偏低"
		warn("实测吞吐不足链路的一半，可能是设备端服务性能限制、CPU 占用，或网线/端口降速")
	default:
		r.Verdict = "正常"
		ok("吞吐正常")
	}
	if r.UtilPct > 0 {
		info(fmt.Sprintf("链路利用率 %.0f%%（按网卡协商速率计算）", r.UtilPct))
	}
	return r
}

// 只有用户显式写了端口，才锁定该端口探测
func portIfForced(target string) int {
	if strings.Count(strings.TrimSpace(target), ":") == 1 && !strings.Contains(target, "//") {
		_, p := parseHostPort(target)
		return p
	}
	return 0
}

// ---------- 服务端模式：让另一台电脑也能被本工具测 ----------

func runServe(addr string) {
	addr = strings.TrimSpace(addr)
	switch {
	case addr == "":
		addr = ":5201"
	case !strings.Contains(addr, ":"):
		// 只给了端口号 或 只给了网卡地址
		if _, err := strconv.Atoi(addr); err == nil {
			addr = ":" + addr
		} else {
			addr += ":5201"
		}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		bad("监听失败: " + err.Error())
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("pong"))
	})
	mux.HandleFunc("/download", func(w http.ResponseWriter, req *http.Request) {
		size := int64(16 << 20)
		for _, k := range []string{"bytes", "size", "len"} {
			if v := req.URL.Query().Get(k); v != "" {
				if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
					size = n
				}
			}
		}
		if size > 512<<20 {
			size = 512 << 20
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.Header().Set("Cache-Control", "no-store")
		buf := make([]byte, 256<<10)
		for sent := int64(0); sent < size; {
			n := int64(len(buf))
			if size-sent < n {
				n = size - sent
			}
			if _, err := w.Write(buf[:n]); err != nil {
				return
			}
			sent += n
		}
	})
	mux.HandleFunc("/upload", func(w http.ResponseWriter, req *http.Request) {
		n, _ := io.Copy(io.Discard, req.Body)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "ok %d", n)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "FastNet 内网测速服务端\n用法: /download?bytes=16777216  /upload  /ping\n")
	})

	title("内网测速服务端已启动")
	ok("监听 " + ln.Addr().String())
	fmt.Println()
	v4, _, _ := localAddrs()
	for _, s := range v4 {
		ip := strings.Fields(s)[0] // localAddrs 形如 "192.168.1.5 (en0)"
		info("在另一台电脑上填: " + net.JoinHostPort(ip, portOf(ln.Addr().String())))
	}
	fmt.Println()
	info("按 Ctrl+C 停止")
	fmt.Println()
	if err := http.Serve(ln, mux); err != nil {
		bad("服务异常退出: " + err.Error())
	}
}

func portOf(addr string) string {
	if _, p, err := net.SplitHostPort(addr); err == nil {
		return p
	}
	return "5201"
}
