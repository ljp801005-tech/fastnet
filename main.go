package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ================= 全局配置 =================

type Config struct {
	SpeedSeconds int
	SpeedConns   int
	Timeout      time.Duration
	SaveDir      string
}

var cfg = Config{
	SpeedSeconds: 10,
	SpeedConns:   4,
	Timeout:      6 * time.Second,
}

var (
	useColor bool
	useProxy bool
)

// ================= 终端输出 =================

const (
	cReset  = "\033[0m"
	cGray   = "\033[90m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cCyan   = "\033[36m"
	cBold   = "\033[1m"
)

func col(c, s string) string {
	if !useColor {
		return s
	}
	return c + s + cReset
}

func title(s string) {
	fmt.Println()
	fmt.Println(col(cCyan, strings.Repeat("=", 64)))
	fmt.Println(col(cCyan, "  "+s))
	fmt.Println(col(cCyan, strings.Repeat("=", 64)))
}

// 中文字符占 2 列，按显示宽度对齐
func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		if r < 128 {
			w++
		} else {
			w += 2
		}
	}
	return w
}

func pad(s string, width int) string {
	d := width - displayWidth(s)
	if d <= 0 {
		return s
	}
	return s + strings.Repeat(" ", d)
}

func line(k, v string) {
	fmt.Printf("  %s  %s\n", pad(k, 18), v)
}

func ok(s string)   { fmt.Println("  " + col(cGreen, "[OK]  ") + s) }
func bad(s string)  { fmt.Println("  " + col(cRed, "[!!]  ") + s) }
func warn(s string) { fmt.Println("  " + col(cYellow, "[!]   ") + s) }
func info(s string) { fmt.Println("  " + col(cGray, "      ") + s) }

func rate(bps float64) string {
	if bps < 1000 {
		return fmt.Sprintf("%.0f bps", bps)
	} else if bps < 1000*1000 {
		return fmt.Sprintf("%.1f Kbps", bps/1000)
	} else if bps < 1000*1000*1000 {
		return fmt.Sprintf("%.2f Mbps", bps/1e6)
	}
	return fmt.Sprintf("%.2f Gbps", bps/1e9)
}

// ================= HTTP =================

func proxyFunc() func(*http.Request) (*url.URL, error) {
	if useProxy {
		return http.ProxyFromEnvironment
	}
	return nil
}

func newClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy: proxyFunc(),
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       45 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

func getBody(rawurl string, timeout time.Duration) (string, error) {
	c := newClient(timeout)
	defer c.CloseIdleConnections()
	resp, err := c.Get(rawurl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return string(b), nil
}

var ipv4Re = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)

// ================= 1. 环境概览 =================

type EnvInfo struct {
	LocalIPv4  []string `json:"localIPv4"`
	LocalIPv6  []string `json:"localIPv6"`
	PublicIPv4 string   `json:"publicIPv4"`
	PublicIPv6 string   `json:"publicIPv6"`
	Location   string   `json:"location"`
	ISP        string   `json:"isp"`
	ASN        string   `json:"asn"`
	ProxyEnv   string   `json:"proxyEnv"`
	Time       string   `json:"time"`
}

// 过滤代理软件常见的虚拟网段（Clash TUN 等），避免把假地址当成真实网卡
func isFakeIPv4(ip net.IP) bool {
	return len(ip) == 4 && ip[0] == 198 && (ip[1] == 18 || ip[1] == 19)
}

func isFakeIPv6(ip net.IP) bool {
	s := ip.String()
	return strings.HasPrefix(s, "fdfe:dcba:9876") || strings.HasPrefix(s, "fdf4:ec3f:f2a:")
}

func localAddrs() (v4 []string, v6 []string, hasFake bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		gotV4, gotV6 := false, false
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				if isFakeIPv4(ip4) {
					hasFake = true
					continue
				}
				if !gotV4 {
					v4 = append(v4, fmt.Sprintf("%s (%s)", ip4.String(), ifc.Name))
					gotV4 = true
				}
			} else {
				if isFakeIPv6(ip) {
					hasFake = true
					continue
				}
				if !gotV6 {
					v6 = append(v6, fmt.Sprintf("%s (%s)", ip.String(), ifc.Name))
					gotV6 = true
				}
			}
		}
	}
	return
}

func proxyEnvValue() string {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func getPublicIPv4() (ip, loc, isp, asn string) {
	// 1) ipip.net：国内运营商信息最准
	if body, err := getBody("https://myip.ipip.net", cfg.Timeout); err == nil {
		if m := ipv4Re.FindStringSubmatch(body); len(m) > 1 {
			ip = m[1]
			if i := strings.Index(body, "来自于"); i >= 0 {
				loc = strings.TrimSpace(body[i+len("来自于"):])
				loc = strings.TrimPrefix(loc, "：")
				loc = strings.TrimPrefix(loc, ":")
				loc = strings.Join(strings.Fields(loc), " ")
			}
			return
		}
	}
	// 2) ip.sb：JSON，含 ASN
	if body, err := getBody("https://api.ip.sb/geoip", cfg.Timeout); err == nil {
		var r struct {
			IP      string `json:"ip"`
			City    string `json:"city"`
			Region  string `json:"region"`
			ISP     string `json:"isp"`
			ASN     string `json:"asn"`
			ASNOrg  string `json:"asn_organization"`
			Country string `json:"country"`
		}
		if json.Unmarshal([]byte(body), &r) == nil && r.IP != "" {
			ip = r.IP
			loc = strings.TrimSpace(r.Country + " " + r.Region + " " + r.City)
			isp = r.ISP
			asn = "AS" + r.ASN + " " + r.ASNOrg
			return
		}
	}
	// 3) Cloudflare trace
	if body, err := getBody("https://www.cloudflare.com/cdn-cgi/trace", cfg.Timeout); err == nil {
		for _, l := range strings.Split(body, "\n") {
			if strings.HasPrefix(l, "ip=") {
				ip = strings.TrimPrefix(l, "ip=")
			} else if strings.HasPrefix(l, "loc=") {
				loc = "地区代码 " + strings.TrimPrefix(l, "loc=")
			}
		}
	}
	return
}

func getPublicIPv6() string {
	for _, u := range []string{"https://api6.ipify.org", "https://v6.ident.me", "https://ipv6.ip.sb"} {
		if body, err := getBody(u, cfg.Timeout); err == nil {
			body = strings.TrimSpace(body)
			if ip := net.ParseIP(body); ip != nil && ip.To4() == nil {
				return body
			}
		}
	}
	return ""
}

func runEnv() *EnvInfo {
	title("环境概览")
	e := &EnvInfo{Time: time.Now().Format("2006-01-02 15:04:05")}
	v4list, v6list, hasFake := localAddrs()
	e.LocalIPv4, e.LocalIPv6 = v4list, v6list
	e.ProxyEnv = proxyEnvValue()

	fmt.Println("  " + col(cBold, "本机地址"))
	if len(e.LocalIPv4) == 0 {
		info("IPv4: 无")
	}
	for _, a := range e.LocalIPv4 {
		info("IPv4: " + a)
	}
	if len(e.LocalIPv6) == 0 {
		info("IPv6: 无全局地址")
	}
	for _, a := range e.LocalIPv6 {
		info("IPv6: " + a)
	}

	fmt.Println("  " + col(cBold, "公网出口"))
	ip, loc, isp, asn := getPublicIPv4()
	e.PublicIPv4, e.Location, e.ISP, e.ASN = ip, loc, isp, asn
	if ip != "" {
		ok("IPv4: " + ip)
		if loc != "" {
			info("位置: " + loc)
		}
		if isp != "" {
			info("运营商: " + isp)
		}
		if asn != "" {
			info("ASN: " + asn)
		}
	} else {
		bad("无法获取公网 IPv4（可能被代理/防火墙拦截，或网络不通）")
	}

	e.PublicIPv6 = getPublicIPv6()
	if e.PublicIPv6 != "" {
		ok("IPv6: " + e.PublicIPv6)
	} else {
		warn("未获取到公网 IPv6")
	}

	if e.ProxyEnv != "" {
		warn("检测到代理环境变量: " + e.ProxyEnv)
		info("公网测速强制直连；无法确认直连时会自动跳过，不会给出代理链路的带宽")
	}
	if v := systemProxyValue(); v != "" {
		warn("检测到 Windows 系统代理: " + v)
		info("系统代理与 TUN 会在系统层接管流量，测速前会做出口体检")
	}
	if hasFake {
		warn("检测到 TUN/透明代理虚拟网卡（198.18.x.x），公网测速可能被跳过")
		info("关闭 Clash/V2Ray 的 TUN 模式后重测，或用菜单 8 测内网带宽")
	}
	return e
}

// ================= 2. 延迟与抖动 =================

type latencyResult struct {
	Name    string  `json:"name"`
	Addr    string  `json:"addr"`
	AvgMs   float64 `json:"avgMs"`
	Jitter  float64 `json:"jitterMs"`
	Loss    float64 `json:"lossPct"`
	Samples int     `json:"samples"`
	Err     string  `json:"error,omitempty"`
}

var latencyTargets = []struct{ Name, Addr string }{
	{"阿里 DNS", "223.5.5.5:443"},
	{"腾讯 DNS", "119.29.29.29:443"},
	{"百度 DNS", "180.76.76.76:443"},
	{"114 DNS", "114.114.114.114:53"},
	{"Cloudflare", "1.1.1.1:443"},
}

func tcpRTT(addr string, timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return 0, err
	}
	elapsed := time.Since(start)
	conn.Close()
	return elapsed, nil
}

func runLatency() []latencyResult {
	title("延迟与抖动 (TCP 握手)")
	results := make([]latencyResult, 0, len(latencyTargets))
	for _, t := range latencyTargets {
		r := latencyResult{Name: t.Name, Addr: t.Addr}
		var samples []float64
		attempts := 6
		for i := 0; i < attempts; i++ {
			d, err := tcpRTT(t.Addr, 3*time.Second)
			if err != nil {
				continue
			}
			if i > 0 { // 丢弃首次（DNS/ARP 影响）
				samples = append(samples, float64(d.Microseconds())/1000.0)
			}
		}
		r.Samples = len(samples)
		if len(samples) == 0 {
			r.Err = "不可达"
			bad(fmt.Sprintf("%s %s 不可达", pad(r.Name, 10), pad(r.Addr, 22)))
			results = append(results, r)
			continue
		}
		var sum float64
		for _, s := range samples {
			sum += s
		}
		r.AvgMs = sum / float64(len(samples))
		if len(samples) > 1 {
			var j float64
			for i := 1; i < len(samples); i++ {
				d := samples[i] - samples[i-1]
				if d < 0 {
					d = -d
				}
				j += d
			}
			r.Jitter = j / float64(len(samples)-1)
		}
		r.Loss = float64(attempts-1-len(samples)) / float64(attempts-1) * 100
		ok(fmt.Sprintf("%s %s 平均 %6.2f ms   抖动 %5.2f ms", pad(r.Name, 10), pad(r.Addr, 22), r.AvgMs, r.Jitter))
		results = append(results, r)
	}
	return results
}

// ================= 3/4. 上下行测速 =================

const (
	downURL = "https://speed.cloudflare.com/__down?bytes=10485760"
	upURL   = "https://speed.cloudflare.com/__up"
)

type speedResult struct {
	Direction string  `json:"direction"`
	Bps       float64 `json:"bps"`
	Mbps      float64 `json:"mbps"`
	Bytes     int64   `json:"bytes"`
	Seconds   float64 `json:"seconds"`
	Conns     int     `json:"conns"`
	Server    string  `json:"server"`
	Skipped   bool    `json:"skipped,omitempty"`
	Reason    string  `json:"reason,omitempty"`
	Egress    string  `json:"egress,omitempty"`
}

func speedProgress(label string, total *int64, start time.Time, done <-chan struct{}) {
	tk := time.NewTicker(300 * time.Millisecond)
	defer tk.Stop()
	for {
		select {
		case <-done:
			return
		case <-tk.C:
			el := time.Since(start).Seconds()
			if el <= 0 {
				continue
			}
			b := atomic.LoadInt64(total)
			fmt.Printf("\r  %s %6.2f Mbps  (已传输 %.1f MB / %.1fs)   ",
				label, float64(b)*8/el/1e6, float64(b)/1048576, el)
		}
	}
}

func runSpeed(up bool) speedResult {
	name := "下载测速"
	target := downURL
	if up {
		name = "上传测速"
		target = upURL
	}
	title(name + " (Cloudflare)")
	info(fmt.Sprintf("时长 %d 秒 / 并发 %d / 数据源 speed.cloudflare.com", cfg.SpeedSeconds, cfg.SpeedConns))

	direction := map[bool]string{true: "upload", false: "download"}[up]

	// 测速前先确认「测速流量」走的是本机宽带直连，而不是代理 / TUN 出口。
	// 绕不过代理就跳过，绝不给一个看似正常、实际失真的带宽数字。
	path := checkSpeedPath()
	if !path.DirectOK && !forceSpeed {
		warn("检测到代理/TUN，已跳过公网测速（不把代理链路速率当成本机带宽）")
		for _, why := range path.Reasons {
			info("· " + why)
		}
		if path.SpeedIP != "" {
			info(fmt.Sprintf("测速目标实际出口: %s (%s)", path.SpeedIP, path.SpeedRegion))
		}
		if path.Note != "" {
			info(path.Note)
		}
		info("请关闭系统代理 / Clash TUN 模式，或把 speed.cloudflare.com 加入直连规则后重测")
		info("只想验证内网瓶颈可用菜单 8（内网带宽），它不走公网、不受代理影响")
		return speedResult{
			Direction: direction,
			Conns:     cfg.SpeedConns,
			Server:    "speed.cloudflare.com",
			Skipped:   true,
			Reason:    strings.Join(path.Reasons, "; "),
			Egress:    path.SpeedIP,
		}
	}
	if path.BindPhysical {
		info("已绑定物理网卡直连，测速流量绕过代理")
	}
	if forceSpeed && !path.DirectOK {
		warn("强制测速：结果只代表当前代理链路，不代表宽带带宽")
	}

	var total int64
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.SpeedSeconds)*time.Second)
	defer cancel()

	client := directClient(path.BindPhysical, 60*time.Second)
	defer client.CloseIdleConnections()

	payload := make([]byte, 8<<20)
	if up {
		_, _ = rand.Read(payload)
	}

	var wg sync.WaitGroup
	var errOnce sync.Once
	var firstErr error
	start := time.Now()
	done := make(chan struct{})
	go speedProgress("测速中", &total, start, done)

	for i := 0; i < cfg.SpeedConns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				var req *http.Request
				var err error
				if up {
					req, err = http.NewRequestWithContext(ctx, "POST", target, bytes.NewReader(payload))
					if err != nil {
						return
					}
					req.ContentLength = int64(len(payload))
					req.Header.Set("Content-Type", "application/octet-stream")
				} else {
					req, err = http.NewRequestWithContext(ctx, "GET", target, nil)
					if err != nil {
						return
					}
				}
				resp, err := client.Do(req)
				if err != nil {
					if ctx.Err() == nil {
						errOnce.Do(func() { firstErr = err })
					}
					return
				}
				if resp.StatusCode != http.StatusOK {
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
					resp.Body.Close()
					msg := strings.TrimSpace(string(body))
					if msg == "" {
						msg = resp.Status
					}
					errOnce.Do(func() {
						firstErr = fmt.Errorf("HTTP %d %s", resp.StatusCode, msg)
					})
					return
				}
				n, copyErr := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if up && n == 0 {
					n = int64(len(payload))
				}
				// 过小的响应多半是错误页/CDN 提示，不能计入带宽
				if n < 65536 {
					return
				}
				if copyErr != nil && n == 0 {
					return
				}
				atomic.AddInt64(&total, n)
			}
		}()
	}

	// 等测速时间到，或所有连接都失败
	for {
		select {
		case <-time.After(200 * time.Millisecond):
			if ctx.Err() != nil {
				goto finish
			}
			if atomic.LoadInt64(&total) == 0 && firstErr != nil {
				goto finish
			}
		}
	}

finish:
	wg.Wait()
	close(done)
	elapsed := time.Since(start).Seconds()
	fmt.Printf("\r%60s\r", "")

	res := speedResult{
		Direction: direction,
		Bytes:     atomic.LoadInt64(&total),
		Seconds:   elapsed,
		Conns:     cfg.SpeedConns,
		Server:    "speed.cloudflare.com",
	}
	if elapsed > 0 {
		res.Bps = float64(res.Bytes) * 8 / elapsed
		res.Mbps = res.Bps / 1e6
	}
	const minValid = int64(1 << 20)
	if res.Bytes < minValid {
		bad(name + " 数据不足，未得到有效结果")
		if firstErr != nil {
			info("原因: " + firstErr.Error())
			if strings.Contains(firstErr.Error(), "429") {
				warn("测速端点限流（429），请等 1-2 分钟再测，或减少并发连接数")
			}
		}
		res.Bps, res.Mbps = 0, 0
		return res
	}
	ok(fmt.Sprintf("%s  %s  (%.1f MB / %.1f 秒)", name, rate(res.Bps), float64(res.Bytes)/1048576, elapsed))
	return res
}

// ================= 5. NAT 类型 =================

const (
	stunMagicCookie = 0x2112A442
	attrMapped      = 0x0001
	attrXorMapped   = 0x0020
	attrChangeReq   = 0x0003
	attrOtherAddr   = 0x802C
)

type stunResp struct {
	MappedIP   string
	MappedPort int
	OtherIP    string
	OtherPort  int
	FromIP     string
	FromPort   int
}

type stunServer struct{ Name, Addr string }

var stunServers = []stunServer{
	{"小米", "stun.miwifi.com:3478"},
	{"B站", "stun.chat.bilibili.com:3478"},
	{"Google", "stun.l.google.com:19302"},
}

func buildStun(changeReq uint32) ([]byte, [12]byte) {
	var attrs []byte
	if changeReq != 0 {
		attrs = make([]byte, 8)
		binary.BigEndian.PutUint16(attrs[0:2], attrChangeReq)
		binary.BigEndian.PutUint16(attrs[2:4], 4)
		binary.BigEndian.PutUint32(attrs[4:8], changeReq)
	}
	buf := make([]byte, 20+len(attrs))
	binary.BigEndian.PutUint16(buf[0:2], 0x0001)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(attrs)))
	binary.BigEndian.PutUint32(buf[4:8], stunMagicCookie)
	var tid [12]byte
	_, _ = rand.Read(tid[:])
	copy(buf[8:20], tid[:])
	copy(buf[20:], attrs)
	return buf, tid
}

func parseStun(data []byte, tid [12]byte) (*stunResp, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("STUN 包过短")
	}
	// 必须校验事务 ID，否则会把上一条请求的迟到响应当成结果
	for k := 0; k < 12; k++ {
		if data[8+k] != tid[k] {
			return nil, fmt.Errorf("transaction id mismatch")
		}
	}
	r := &stunResp{}
	i := 20
	for i+4 <= len(data) {
		t := binary.BigEndian.Uint16(data[i : i+2])
		l := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
		if i+4+l > len(data) {
			break
		}
		v := data[i+4 : i+4+l]
		switch t {
		case attrXorMapped:
			if len(v) >= 8 {
				fam := v[1]
				port := binary.BigEndian.Uint16(v[2:4]) ^ 0x2112
				if fam == 0x01 {
					ip := make(net.IP, 4)
					cookie := uint32(stunMagicCookie)
					for k := 0; k < 4; k++ {
						ip[k] = v[4+k] ^ byte(cookie>>(24-8*uint(k)))
					}
					r.MappedIP = ip.String()
					r.MappedPort = int(port)
				}
			}
		case attrMapped:
			if len(v) >= 8 && r.MappedIP == "" {
				port := binary.BigEndian.Uint16(v[2:4])
				r.MappedIP = net.IP(v[4:8]).String()
				r.MappedPort = int(port)
			}
		case attrOtherAddr:
			if len(v) >= 8 {
				fam := v[1]
				port := binary.BigEndian.Uint16(v[2:4])
				if fam == 0x01 {
					r.OtherIP = net.IP(v[4:8]).String()
					r.OtherPort = int(port)
				}
			}
		}
		i += 4 + ((l + 3) / 4 * 4)
	}
	return r, nil
}

func stunQuery(conn *net.UDPConn, server string, changeReq uint32, timeout time.Duration) (*stunResp, error) {
	raddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 2048)
	// 先清空缓冲区里的迟到包，避免误读成本次结果
	_ = conn.SetReadDeadline(time.Now().Add(-time.Second))
	for {
		if _, _, err := conn.ReadFromUDP(buf); err != nil {
			break
		}
	}
	pkt, tid := buildStun(changeReq)
	if _, err := conn.WriteToUDP(pkt, raddr); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		_ = conn.SetReadDeadline(deadline)
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, err
		}
		r, err := parseStun(buf[:n], tid)
		if err != nil {
			continue // 事务 ID 不匹配，不是本次响应
		}
		r.FromIP = from.IP.String()
		r.FromPort = from.Port
		return r, nil
	}
}

type natResult struct {
	Type       string `json:"type"`
	Code       string `json:"code"`
	MappedIP   string `json:"mappedIp"`
	MappedPort int    `json:"mappedPort"`
	LocalIP    string `json:"localIp"`
	LocalPort  int    `json:"localPort"`
	Server     string `json:"server"`
	Detail     string `json:"detail"`
	P2PHint    string `json:"p2pHint"`
}

func runNAT() *natResult {
	title("NAT 类型检测 (STUN)")
	res := &natResult{}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		bad("无法创建 UDP 套接字: " + err.Error())
		return res
	}
	defer conn.Close()
	res.LocalPort = conn.LocalAddr().(*net.UDPAddr).Port

	// 找到可用服务器
	var primary stunServer
	var r1 *stunResp
	for _, s := range stunServers {
		info("尝试 " + s.Name + " (" + s.Addr + ") ...")
		r, err := stunQuery(conn, s.Addr, 0, 2500*time.Millisecond)
		if err == nil && r.MappedIP != "" {
			primary, r1 = s, r
			break
		}
	}
	if r1 == nil {
		bad("所有 STUN 服务器均无响应（UDP 可能被阻断）")
		res.Type, res.Code, res.Detail = "检测失败", "?", "STUN 无响应"
		return res
	}
	res.Server = primary.Addr
	res.MappedIP = r1.MappedIP
	res.MappedPort = r1.MappedPort
	res.LocalIP = "本机"
	ok(fmt.Sprintf("公网映射: %s:%d  (本地端口 %d)", r1.MappedIP, r1.MappedPort, res.LocalPort))

	// 本地内网地址，用于判断是否在 NAT 后
	v4, _, _ := localAddrs()
	if len(v4) > 0 {
		res.LocalIP = strings.Fields(v4[0])[0]
	}

	// 第二个服务器，同一本地端口，比对映射端口是否一致
	var r2 *stunResp
	for _, s := range stunServers {
		if s.Addr == primary.Addr {
			continue
		}
		r, err := stunQuery(conn, s.Addr, 0, 2500*time.Millisecond)
		if err == nil && r.MappedIP != "" {
			r2 = r
			info(fmt.Sprintf("对比 %s 映射: %s:%d", s.Name, r.MappedIP, r.MappedPort))
			break
		}
	}

	if res.MappedIP == res.LocalIP {
		res.Code = "OPEN"
		res.Type = "公网直连（无 NAT）"
		res.Detail = "映射地址与本机地址一致"
		ok(res.Type)
		return res
	}

	if r2 != nil && r2.MappedPort != r1.MappedPort {
		res.Code = "NAT4"
		res.Type = "对称型 NAT (Symmetric)"
		res.Detail = fmt.Sprintf("不同目标映射端口不同：%d vs %d", r1.MappedPort, r2.MappedPort)
		res.P2PHint = "P2P 穿透困难，需要中继"
		warn(res.Type)
		info(res.Detail)
		return res
	}

	// 锥形：用 change-request 细分
	if r1.OtherIP != "" && r1.OtherPort > 0 {
		info(fmt.Sprintf("服务器其它地址: %s:%d", r1.OtherIP, r1.OtherPort))
		// 1) 请求服务器从「其它 IP + 其它端口」回包
		rc, err := stunQuery(conn, primary.Addr, 0x06, 2500*time.Millisecond)
		if err == nil {
			info(fmt.Sprintf("换IP+端口 请求的响应来源: %s:%d", rc.FromIP, rc.FromPort))
		}
		if err == nil && rc.FromIP == r1.OtherIP && rc.FromPort == r1.OtherPort {
			res.Code = "NAT1"
			res.Type = "完全锥形 NAT (Full Cone)"
			res.Detail = "任意外部主机均可主动发包进来"
			res.P2PHint = "P2P 穿透容易"
			ok(res.Type)
			return res
		}
		// 2) 只换端口
		rp, err := stunQuery(conn, primary.Addr, 0x04, 2500*time.Millisecond)
		if err == nil && rp.FromPort == r1.OtherPort {
			res.Code = "NAT2"
			res.Type = "受限锥形 NAT (Restricted Cone)"
			res.Detail = "仅允许已通信过的 IP 主动连入"
			res.P2PHint = "P2P 穿透一般，需要端口预测"
			ok(res.Type)
			return res
		}
		res.Code = "NAT3"
		res.Type = "端口受限锥形 NAT (Port Restricted)"
		res.Detail = "仅允许已通信过的 IP+端口 主动连入"
		res.P2PHint = "P2P 穿透较难"
		warn(res.Type)
		return res
	}

	res.Code = "NAT?"
	res.Type = "锥形 NAT（无法细分）"
	res.Detail = "STUN 服务器未返回其它地址，无法做变更请求测试"
	warn(res.Type)
	return res
}

// ================= 6. IPv6 就绪度 =================

type v6Result struct {
	LocalV6   []string `json:"localV6"`
	PublicV6  string   `json:"publicV6"`
	DNSAAAA   bool     `json:"dnsAAAA"`
	Reachable bool     `json:"reachable"`
	Score     int      `json:"score"`
	Verdict   string   `json:"verdict"`
}

func runIPv6() *v6Result {
	title("IPv6 就绪度")
	r := &v6Result{}
	_, v6list, hasFake := localAddrs()
	r.LocalV6 = v6list
	if hasFake {
		warn("检测到 TUN/透明代理，IPv6 结果可能代表代理出口而非本机宽带")
	}

	if len(r.LocalV6) == 0 {
		bad("本机没有全局 IPv6 地址")
	} else {
		for _, a := range r.LocalV6 {
			ok("本机 IPv6: " + a)
		}
		r.Score += 3
	}

	// DNS AAAA 解析能力
	if ips, err := net.LookupIP("ipv6.baidu.com"); err == nil {
		for _, ip := range ips {
			if ip.To4() == nil {
				r.DNSAAAA = true
				break
			}
		}
	}
	if r.DNSAAAA {
		ok("DNS 可解析 AAAA 记录")
		r.Score += 2
	} else {
		warn("DNS 未返回 AAAA 记录")
	}

	// 能否真正访问 IPv6-only 站点
	r.PublicV6 = getPublicIPv6()
	if r.PublicV6 != "" {
		ok("可访问 IPv6 网络，出口: " + r.PublicV6)
		r.Reachable = true
		r.Score += 5
	} else {
		warn("无法访问 IPv6-only 站点")
	}

	switch {
	case r.Score >= 10:
		r.Verdict = "IPv6 全链路可用"
		ok(r.Verdict)
	case r.Score >= 8:
		r.Verdict = "IPv6 基本可用，但部分环节不完整"
		ok(r.Verdict)
	case r.Score >= 5:
		r.Verdict = "有 IPv6 地址但无法真正访问 IPv6 网站"
		warn(r.Verdict)
	case r.Score > 0:
		r.Verdict = "IPv6 配置不完整，建议检查路由器 IPv6 设置"
		warn(r.Verdict)
	default:
		r.Verdict = "未接入 IPv6（仅 IPv4）"
		info(r.Verdict)
	}
	return r
}

// ================= 7. 上游节点测速 =================

type upstreamResult struct {
	Target    string  `json:"target"`
	Reachable bool    `json:"reachable"`
	AvgMs     float64 `json:"avgMs"`
	JitterMs  float64 `json:"jitterMs"`
	HTTPCode  int     `json:"httpCode"`
	DownMbps  float64 `json:"downMbps"`
	Err       string  `json:"error,omitempty"`
}

func runUpstream(target string) *upstreamResult {
	title("上游节点测速")
	target = strings.TrimSpace(target)
	if target == "" {
		fmt.Print("  请输入目标 IP:Port（例如 192.168.11.1:3300）：")
		target = strings.TrimSpace(readLine())
	}
	r := &upstreamResult{Target: target}
	if target == "" {
		warn("已取消")
		return r
	}
	if !strings.Contains(target, ":") {
		target += ":80"
	}

	var samples []float64
	for i := 0; i < 6; i++ {
		d, err := tcpRTT(target, 3*time.Second)
		if err == nil && i > 0 {
			samples = append(samples, float64(d.Microseconds())/1000.0)
		}
	}
	if len(samples) == 0 {
		r.Err = "TCP 不可达"
		bad("TCP 连接失败: " + target)
		return r
	}
	r.Reachable = true
	var sum float64
	for _, s := range samples {
		sum += s
	}
	r.AvgMs = sum / float64(len(samples))
	for i := 1; i < len(samples); i++ {
		d := samples[i] - samples[i-1]
		if d < 0 {
			d = -d
		}
		r.JitterMs += d
	}
	if len(samples) > 1 {
		r.JitterMs /= float64(len(samples) - 1)
	}
	ok(fmt.Sprintf("TCP 延迟 %.2f ms（抖动 %.2f ms）", r.AvgMs, r.JitterMs))

	// 尝试 HTTP 下载测速（对方若提供 HTTP 服务）
	client := newClient(8 * time.Second)
	defer client.CloseIdleConnections()
	for _, scheme := range []string{"http", "https"} {
		u := scheme + "://" + target + "/"
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		r.HTTPCode = resp.StatusCode
		start := time.Now()
		n, _ := io.Copy(io.Discard, resp.Body)
		el := time.Since(start).Seconds()
		resp.Body.Close()
		if el > 0 && n > 0 {
			r.DownMbps = float64(n) * 8 / el / 1e6
			ok(fmt.Sprintf("HTTP %d  下载 %s（%d 字节 / %.2fs）", resp.StatusCode, rate(r.DownMbps*1e6), n, el))
		} else {
			info(fmt.Sprintf("HTTP %d（无可下载内容）", resp.StatusCode))
		}
		break
	}
	return r
}

// ================= 报告 =================

type Report struct {
	Time     string          `json:"time"`
	Tool     string          `json:"tool"`
	Version  string          `json:"version"`
	Env      *EnvInfo        `json:"env,omitempty"`
	Latency  []latencyResult `json:"latency,omitempty"`
	Download *speedResult    `json:"download,omitempty"`
	Upload   *speedResult    `json:"upload,omitempty"`
	NAT      *natResult      `json:"nat,omitempty"`
	IPv6     *v6Result       `json:"ipv6,omitempty"`
	Upstream *upstreamResult `json:"upstream,omitempty"`
	LAN      *lanResult      `json:"lan,omitempty"`
}

func saveReport(name string, rep *Report) {
	dir := cfg.SaveDir
	if dir == "" {
		dir = "results"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		warn("创建报告目录失败: " + err.Error())
		return
	}
	fn := filepath.Join(dir, time.Now().Format("20060102_150405")+"_"+name+".json")
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		warn("序列化报告失败: " + err.Error())
		return
	}
	if err := os.WriteFile(fn, b, 0o644); err != nil {
		warn("写入报告失败: " + err.Error())
		return
	}
	info("报告已保存: " + fn)
}

func newReport() *Report {
	return &Report{
		Time:    time.Now().Format("2006-01-02 15:04:05"),
		Tool:    "FastNet 本地版",
		Version: version,
	}
}

// ================= 汇总 =================

func summaryBanner(rep *Report) {
	title("体检结论")
	if rep.Env != nil {
		line("公网 IPv4", rep.Env.PublicIPv4)
		if rep.Env.Location != "" {
			line("位置/运营商", rep.Env.Location)
		}
		if rep.Env.PublicIPv6 != "" {
			line("公网 IPv6", rep.Env.PublicIPv6)
		}
	}
	if len(rep.Latency) > 0 {
		best := rep.Latency[0]
		var okCount int
		var sum float64
		for _, l := range rep.Latency {
			if l.Err == "" {
				okCount++
				sum += l.AvgMs
				if l.AvgMs < best.AvgMs {
					best = l
				}
			}
		}
		if okCount > 0 {
			line("平均延迟", fmt.Sprintf("%.1f ms（最佳 %s %.1f ms）", sum/float64(okCount), best.Name, best.AvgMs))
		}
	}
	if rep.Download != nil {
		if rep.Download.Skipped {
			line("下行带宽", "已跳过（代理环境，不测代理链路）")
		} else if rep.Download.Bps > 0 {
			line("下行带宽", rate(rep.Download.Bps))
		}
	}
	if rep.Upload != nil {
		if rep.Upload.Skipped {
			line("上行带宽", "已跳过（代理环境，不测代理链路）")
		} else if rep.Upload.Bps > 0 {
			line("上行带宽", rate(rep.Upload.Bps))
		}
	}
	if rep.NAT != nil && rep.NAT.Type != "" {
		line("NAT 类型", rep.NAT.Type)
	}
	if rep.IPv6 != nil {
		line("IPv6", fmt.Sprintf("%s（%d/10）", rep.IPv6.Verdict, rep.IPv6.Score))
	}
	if rep.LAN != nil {
		if rep.LAN.LatencyMs > 0 {
			line("本机→网关", fmt.Sprintf("%.2f ms（%s）", rep.LAN.LatencyMs, defStr(rep.LAN.Gateway, "未知")))
		}
		if rep.LAN.DownMbps > 0 {
			up := "-"
			if rep.LAN.UpMbps > 0 {
				up = rate(rep.LAN.UpMbps * 1e6)
			}
			line("内网带宽", fmt.Sprintf("下行 %s / 上行 %s（%s）", rate(rep.LAN.DownMbps*1e6), up, rep.LAN.Verdict))
		} else if rep.LAN.Err != "" {
			line("内网带宽", "未测（"+rep.LAN.Err+"）")
		}
	}
	fmt.Println()
}

// ================= 主流程 =================

const version = "1.1.1"

var stdin = bufio.NewReader(os.Stdin)

func readLine() string {
	s, err := stdin.ReadString('\n')
	if err != nil {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(s)
}

func showHelp() {
	title("说明")
	fmt.Println(`  本工具完全在本机运行，测的就是运行它的这台电脑的网络，
  与原来的路由器 WebUI 无关，也不需要能访问任何特定设备（如 192.168.1.1）。

  检测项
    1 环境概览    出口 IP / 运营商 / 本机网卡地址
    2 延迟抖动    TCP 握手到 5 个公共节点
    3 下载测速    Cloudflare 公共测速端点
    4 上传测速    同上
    5 NAT 类型    STUN 检测，输出 NAT1-4
    6 IPv6       地址 / AAAA 解析 / 真实连通性
    7 上游测速    指定 IP:Port 的 TCP 延迟 + HTTP 下载
    8 内网带宽    本机 ↔ 路由器，自动识别网关，测延迟与双向吞吐
    S 测速服务端  在本机开一个端点，让另一台电脑也能测这段内网

  内网带宽测速怎么用
    - 目标设备若提供 /download /upload（OpenWrt、FastNet 类固件），
      程序会自动识别端口并直接测出双向真实吞吐
    - 若目标只是个普通路由器，没有测速接口：
        在另一台电脑/笔记本上运行   fastnet.exe serve
        然后本机选 8，填那台机器的   IP:5201
      测出来的就是两台设备之间这段网线+交换机的真实带宽
    - 网卡协商速率（1 Gbps / 2.5 Gbps）会自动显示，用于判断是否跑满

  与原网页的差异
    - 网页测的是「路由器到公网」，这里测「本机到公网」
    - 网页的 SpeedTest(Ookla) 换成 Cloudflare 端点（Ookla 协议未公开）
    - 开了系统代理 / TUN 时，测速前会做出口体检；确认不了直连就跳过测速，
      不再把代理链路的吞吐当成本机宽带报出来

  手机/平板
    菜单 W（或 fastnet web）把手机版页面共享到局域网，
    手机浏览器打开 http://电脑IP:8899 即可用，可「添加到主屏幕」

  报告      保存在 exe 同目录的 results 文件夹，JSON 格式
  命令行    fastnet.exe all | env | latency | speed | nat | ipv6 | upstream 1.2.3.4:80
            fastnet.exe lan [IP:Port]    fastnet.exe serve [端口]
            fastnet.exe web [端口]
  代理      测速前自动体检出口；检测到代理且无法直连时跳过测速，避免假带宽
            -proxy 使用代理环境变量；-force-speed 强制测速（结果不可信）`)
	fmt.Println()
}

func pause() {
	fmt.Print("\n  按回车返回菜单...")
	readLine()
}

func runAll() {
	rep := newReport()
	rep.Env = runEnv()
	rep.Latency = runLatency()
	d := runSpeed(false)
	rep.Download = &d
	u := runSpeed(true)
	rep.Upload = &u
	rep.NAT = runNAT()
	rep.IPv6 = runIPv6()
	rep.LAN = runLAN("", false)
	summaryBanner(rep)
	saveReport("all", rep)
}

func menu() {
	for {
		fmt.Println()
		fmt.Println(col(cCyan, strings.Repeat("=", 64)))
		fmt.Println("  " + col(cBold, "FastNet 本地网络体检  v"+version))
		fmt.Println(col(cGray, "  在本机直接测试，不依赖任何路由器/服务器"))
		fmt.Println(col(cCyan, strings.Repeat("=", 64)))
		fmt.Println("   1  环境概览        出口 IP / 运营商 / 本机地址")
		fmt.Println("   2  延迟与抖动      到 5 个公共节点")
		fmt.Println("   3  下载测速        Cloudflare 多线程")
		fmt.Println("   4  上传测速        Cloudflare 多线程")
		fmt.Println("   5  NAT 类型检测    STUN，NAT1-4")
		fmt.Println("   6  IPv6 就绪度     地址 / 解析 / 连通")
		fmt.Println("   7  上游节点测速    自定义 IP:Port")
		fmt.Println("   8  内网带宽测速    本机 ↔ 路由器 / 内网设备（不走公网）")
		fmt.Println("   S  启动内网测速服务端（供另一台电脑测本机）")
		fmt.Println("   W  手机版页面共享（手机浏览器访问本机使用）")
		fmt.Println()
		fmt.Println("   A  一键完整体检（1-6 + 内网）")
		fmt.Println("   C  设置（秒数 / 并发）")
		fmt.Println("   H  说明")
		fmt.Println("   0  退出")
		fmt.Println()
		fmt.Print("  请选择: ")
		ch := strings.ToUpper(readLine())
		switch ch {
		case "1":
			rep := newReport()
			rep.Env = runEnv()
			saveReport("env", rep)
			pause()
		case "2":
			rep := newReport()
			rep.Latency = runLatency()
			saveReport("latency", rep)
			pause()
		case "3":
			rep := newReport()
			d := runSpeed(false)
			rep.Download = &d
			saveReport("download", rep)
			pause()
		case "4":
			rep := newReport()
			u := runSpeed(true)
			rep.Upload = &u
			saveReport("upload", rep)
			pause()
		case "5":
			rep := newReport()
			rep.NAT = runNAT()
			saveReport("nat", rep)
			pause()
		case "6":
			rep := newReport()
			rep.IPv6 = runIPv6()
			saveReport("ipv6", rep)
			pause()
		case "7":
			rep := newReport()
			rep.Upstream = runUpstream("")
			saveReport("upstream", rep)
			pause()
		case "8":
			rep := newReport()
			rep.LAN = runLAN("", true)
			saveReport("lan", rep)
			pause()
		case "S":
			title("内网测速服务端")
			fmt.Print("  监听端口（回车=5201）: ")
			p := strings.TrimSpace(readLine())
			fmt.Println()
			info("服务启动后会一直运行，按 Ctrl+C 或关闭窗口结束")
			runServe("0.0.0.0:" + defStr(p, "5201"))
			pause()
		case "W":
			title("手机版页面共享")
			fmt.Print("  端口（回车=8899）: ")
			p := strings.TrimSpace(readLine())
			fmt.Println()
			runWeb(p)
			pause()
		case "A":
			runAll()
			pause()
		case "C":
			fmt.Printf("  测速时长（秒，当前 %d）: ", cfg.SpeedSeconds)
			if v := readLine(); v != "" {
				var n int
				if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n >= 3 && n <= 60 {
					cfg.SpeedSeconds = n
				}
			}
			fmt.Printf("  并发连接数（当前 %d）: ", cfg.SpeedConns)
			if v := readLine(); v != "" {
				var n int
				if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n >= 1 && n <= 16 {
					cfg.SpeedConns = n
				}
			}
			ok("设置已更新")
			pause()
		case "H":
			showHelp()
			pause()
		case "0", "Q", "EXIT":
			fmt.Println("\n  再见")
			return
		default:
			warn("无效选项")
			time.Sleep(300 * time.Millisecond)
		}
	}
}

func main() {
	useColor = initConsole()
	// 报告固定落在 exe 所在目录，双击运行时不会乱丢
	if exe, err := os.Executable(); err == nil {
		cfg.SaveDir = filepath.Join(filepath.Dir(exe), "results")
	}

	useProxy = false
	mode := ""
	var extra string
	for _, a := range os.Args[1:] {
		switch strings.ToLower(a) {
		case "-proxy", "--proxy":
			useProxy = true
		case "-force-speed", "--force-speed":
			forceSpeed = true
		case "-h", "--help", "help":
			fmt.Println("用法: fastnet [选项] [命令]")
			fmt.Println("命令: menu(默认) all env latency speed nat ipv6 upstream lan serve web")
			fmt.Println("  lan [IP:Port]   内网（本机↔路由器）带宽测速，留空自动识别网关")
			fmt.Println("  serve [端口]    启动内网测速服务端，供另一台电脑测本机（默认 5201）")
			fmt.Println("  web [端口]      把手机版页面共享到局域网（默认 8899）")
			fmt.Println("选项: -proxy        使用代理环境变量（默认直连）")
			fmt.Println("      -force-speed 代理环境下仍强制测速（结果不代表宽带，仅供诊断）")
			return
		default:
			if mode == "" {
				mode = strings.ToLower(a)
			} else {
				extra = a
			}
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\n  已中断")
		os.Exit(1)
	}()

	switch mode {
	case "all":
		runAll()
	case "env":
		rep := newReport()
		rep.Env = runEnv()
		saveReport("env", rep)
	case "latency":
		rep := newReport()
		rep.Latency = runLatency()
		saveReport("latency", rep)
	case "speed":
		rep := newReport()
		d := runSpeed(false)
		rep.Download = &d
		u := runSpeed(true)
		rep.Upload = &u
		saveReport("speed", rep)
	case "nat":
		rep := newReport()
		rep.NAT = runNAT()
		saveReport("nat", rep)
	case "ipv6":
		rep := newReport()
		rep.IPv6 = runIPv6()
		saveReport("ipv6", rep)
	case "upstream":
		rep := newReport()
		rep.Upstream = runUpstream(extra)
		saveReport("upstream", rep)
	case "lan":
		rep := newReport()
		rep.LAN = runLAN(extra, extra == "")
		saveReport("lan", rep)
	case "serve":
		runServe(extra)
	case "web":
		runWeb(extra)
	default:
		menu()
	}
}
