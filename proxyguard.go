package main

// 测速出口体检。
//
// 公网测速报出来的数字必须是「本机宽带 → 直连」的吞吐。
// 一旦开了系统代理 / Clash TUN / 分流规则，Go 客户端即使设置 Proxy: nil，
// 流量仍会在 IP 层被虚拟网卡接管，测到的其实是代理节点到服务器的速率。
// 这种情况下旧版本会给出一个看起来正常、实际完全失真的带宽值。
//
// 本文件的策略：
//   1. 检查代理环境变量、Windows 系统代理、TUN 虚拟网卡；
//   2. 用与测速完全相同的 HTTP 客户端探测 speed.cloudflare.com 的真实出口；
//   3. 与本机宽带出口（国内直连站点）比对地区/IP，识别「分流代理」；
//   4. 发现代理痕迹时，先尝试绑定物理网卡源地址强制直连；
//   5. 只有确认直连才允许测速，否则直接跳过并给出可操作的提示。

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	forceSpeed bool // -force-speed：明知走代理也要测（结果会被明确标注不可信）
	pathOnce   sync.Once
	pathResult speedPath
)

type speedPath struct {
	ProxyLike    bool
	DirectOK     bool
	BindPhysical bool
	Reasons      []string
	LocalIP      string // 本机宽带出口 IP（基准）
	LocalRegion  string // 本机宽带出口地区
	SpeedIP      string // 测速目标实际出口 IP
	SpeedRegion  string // 测速目标实际出口地区
	Note         string
}

type egress struct {
	ip     string
	region string
	colo   string
}

// 系统代理：Go 的 ProxyFromEnvironment 不读 Windows 注册表，
// 而 Clash / V2Ray 等默认就是写这里的 ProxyEnable + ProxyServer。
func systemProxyValue() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	const key = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	en, err := exec.Command("reg", "query", key, "/v", "ProxyEnable").Output()
	if err != nil || !strings.Contains(strings.ToLower(string(en)), "0x1") {
		return ""
	}
	sv, err := exec.Command("reg", "query", key, "/v", "ProxyServer").Output()
	if err != nil {
		return "系统代理已开启"
	}
	if f := strings.Fields(string(sv)); len(f) > 0 {
		v := f[len(f)-1]
		if strings.ContainsAny(v, "=:") {
			return v
		}
	}
	return "系统代理已开启"
}

// TUN / 透明代理虚拟网卡（Clash Meta、Wintun、TAP 等）。
func tunNames() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		n := strings.ToLower(ifc.Name)
		matched := false
		for _, k := range []string{"meta", "wintun", "tun", "tap", "clash", "mihomo"} {
			if strings.Contains(n, k) {
				matched = true
				break
			}
		}
		if !matched {
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					if ip4 := ipn.IP.To4(); ip4 != nil && isFakeIPv4(ip4) {
						matched = true
						break
					}
				}
			}
		}
		if matched {
			out = append(out, ifc.Name)
		}
	}
	return out
}

// 取一张真实物理网卡的 IPv4，用于绑定源地址尝试绕开 TUN 默认路由。
func physicalIPv4() net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	skip := map[string]bool{}
	for _, n := range tunNames() {
		skip[n] = true
	}
	for _, ifc := range ifaces {
		if skip[ifc.Name] || ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipn.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || isFakeIPv4(ip4) {
				continue
			}
			return append(net.IP(nil), ip4...)
		}
	}
	return nil
}

// 测速专用客户端：显式禁用 HTTP 代理，可选绑定物理网卡源地址。
// 探测与正式测速必须使用同一个客户端，否则探测结果没有参考价值。
func directClient(bindPhysical bool, timeout time.Duration) *http.Client {
	var localAddr net.Addr
	if bindPhysical {
		if ip := physicalIPv4(); ip != nil {
			localAddr = &net.TCPAddr{IP: ip}
		}
	}
	tr := &http.Transport{
		Proxy: nil, // 不读环境变量、不走任何 HTTP 代理
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
			LocalAddr: localAddr,
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

func httpText(c *http.Client, rawurl string) (string, error) {
	req, err := http.NewRequest("GET", rawurl, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// 分块读、拿到内容就走，不等服务器主动关连接。
	// 有些站点 keep-alive 不主动断流，ReadAll 会一直等到 client 超时。
	r := io.LimitReader(resp.Body, 1<<16)
	var sb strings.Builder
	buf := make([]byte, 4096)
	for i := 0; i < 16 && sb.Len() < 1<<16; i++ {
		n, e := r.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if e != nil {
			break
		}
	}
	return sb.String(), nil
}

// 测速端点自己的 trace：这才是测速流量真正走的出口。
// 不能拿 myip.ipip.net 之类国内站点的出口当依据（分流规则下两者完全不同）。
func probeSpeedEgress(c *http.Client) (egress, error) {
	var e egress
	txt, err := httpText(c, "https://speed.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return e, err
	}
	for _, l := range strings.Split(txt, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "ip="):
			e.ip = strings.TrimPrefix(l, "ip=")
		case strings.HasPrefix(l, "loc="):
			e.region = strings.TrimPrefix(l, "loc=")
		case strings.HasPrefix(l, "colo="):
			e.colo = strings.TrimPrefix(l, "colo=")
		}
	}
	if e.ip == "" {
		return e, fmt.Errorf("trace 未返回出口 IP")
	}
	return e, nil
}

// 本机宽带出口基准：优先用国内直连站点，失败再用 geoip 接口。
func probeLocalEgress(c *http.Client) (ip, region string) {
	if txt, err := httpText(c, "https://myip.ipip.net"); err == nil {
		if m := ipv4Re.FindStringSubmatch(txt); len(m) > 1 {
			ip = m[1]
		}
		if i := strings.Index(txt, "来自于"); i >= 0 {
			s := strings.TrimSpace(txt[i+len("来自于"):])
			s = strings.TrimPrefix(strings.TrimPrefix(s, "："), ":")
			if f := strings.Fields(s); len(f) > 0 {
				region = f[0]
			}
		}
	}
	if region == "" {
		if txt, err := httpText(c, "https://api.ip.sb/geoip"); err == nil {
			var j struct {
				IP          string `json:"ip"`
				CountryCode string `json:"country_code"`
			}
			if json.Unmarshal([]byte(txt), &j) == nil {
				if ip == "" {
					ip = j.IP
				}
				region = j.CountryCode
			}
		}
	}
	return
}

// 把「中国」和「CN」这类写法归一到同一代码，便于比较。
func normRegion(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	m := map[string]string{
		"中国": "CN", "CHINA": "CN", "大陆": "CN", "CN": "CN",
		"中国香港": "HK", "HK": "HK",
		"中国澳门": "MO", "MO": "MO",
		"中国台湾": "TW", "TW": "TW",
		"美国": "US", "US": "US",
		"日本": "JP", "JP": "JP",
		"新加坡": "SG", "SG": "SG",
		"韩国": "KR", "KR": "KR",
		"英国": "GB", "GB": "GB",
		"德国": "DE", "DE": "DE",
	}
	if v, ok := m[s]; ok {
		return v
	}
	return s
}

// 家宽出口不会是机房 ASN；命中这些关键字基本可以断定是代理/云主机出口。
func probeOrg(c *http.Client, ip string) string {
	if ip == "" {
		return ""
	}
	txt, err := httpText(c, "https://api.ip.sb/geoip/"+ip)
	if err != nil {
		return ""
	}
	var j struct {
		ASNOrg string `json:"asn_organization"`
		ISP    string `json:"isp"`
	}
	if json.Unmarshal([]byte(txt), &j) != nil {
		return ""
	}
	return j.ASNOrg + " " + j.ISP
}

func hostingEgress(org string) bool {
	o := strings.ToLower(org)
	for _, k := range []string{
		"g-core", "cloudflare", "amazon", "google", "microsoft",
		"digitalocean", "linode", "vultr", "hetzner", "ovh", "oracle",
		"akamai", "leaseweb", "contabo", "choopa", "m247", "datacamp",
	} {
		if strings.Contains(o, k) {
			return true
		}
	}
	return false
}

// 一次进程内只体检一次，下载/上传共用结论。
// 原则：只有「系统层确实会接管流量」的证据才跳过测速；
// 单纯的环境变量、或一次探测超时，都不能把测速卡住或误判成代理环境。
func checkSpeedPath() speedPath {
	pathOnce.Do(func() {
		info("正在核对测速路径（最多 2 秒）…")
		r := speedPath{}

		envProxy := proxyEnvValue()
		sysProxy := systemProxyValue()
		tuns := tunNames()
		hardProxy := false
		if sysProxy != "" {
			hardProxy = true
			r.Reasons = append(r.Reasons, "Windows 系统代理: "+sysProxy)
		}
		if len(tuns) > 0 {
			hardProxy = true
			r.Reasons = append(r.Reasons, "TUN/虚拟网卡: "+strings.Join(tuns, ", "))
		}
		if envProxy != "" {
			r.ProxyLike = true
			r.Reasons = append(r.Reasons, "代理环境变量: "+envProxy+"（测速客户端不使用它）")
		}

		// 两个出口探测并发跑，整体 2.2 秒硬上限；失败只影响提示，不阻塞测速。
		type baseRes struct{ ip, region string }
		type cfRes struct {
			e   egress
			err error
		}
		baseCh := make(chan baseRes, 1)
		cfCh := make(chan cfRes, 1)
		probe := directClient(false, 2*time.Second)
		defer probe.CloseIdleConnections()
		go func() {
			ip, reg := probeLocalEgress(probe)
			baseCh <- baseRes{ip, reg}
		}()
		go func() {
			e, err := probeSpeedEgress(probe)
			cfCh <- cfRes{e, err}
		}()
		deadline := time.After(2200 * time.Millisecond)
		gotBase, gotCF := false, false
		for !gotBase || !gotCF {
			select {
			case b := <-baseCh:
				r.LocalIP, r.LocalRegion = b.ip, b.region
				gotBase = true
			case c := <-cfCh:
				gotCF = true
				if c.err == nil {
					r.SpeedIP, r.SpeedRegion = c.e.ip, c.e.region
				} else {
					r.Note = "国际端点探测失败: " + c.err.Error()
				}
			case <-deadline:
				gotBase, gotCF = true, true
				r.Note = "出口探测超时，按本地配置判定"
			}
		}

		// 测速目标出口与宽带出口地区不同 = 分流/代理的硬证据。
		if r.SpeedRegion != "" && r.LocalRegion != "" &&
			normRegion(r.SpeedRegion) != normRegion(r.LocalRegion) {
			hardProxy = true
			r.Reasons = append(r.Reasons, fmt.Sprintf(
				"国际端点出口在 %s (%s)，本机宽带出口在 %s —— 流量被分流/代理",
				r.SpeedRegion, r.SpeedIP, r.LocalRegion))
		}

		if !hardProxy {
			r.DirectOK = true
			if r.ProxyLike {
				info("仅检测到代理环境变量，测速强制直连，按直连处理")
			}
			pathResult = r
			return
		}

		// 系统层代理：绑定物理网卡源地址，尝试强制走本地直连。
		bound := directClient(true, 2*time.Second)
		defer bound.CloseIdleConnections()
		e2, err2 := probeSpeedEgress(bound)
		if err2 == nil && r.LocalIP != "" && e2.ip == r.LocalIP {
			r.DirectOK = true
			r.BindPhysical = true
			r.SpeedIP, r.SpeedRegion = e2.ip, e2.region
			r.Reasons = append(r.Reasons, "已绑定物理网卡直连，成功绕过代理")
			r.Note = ""
			pathResult = r
			return
		}

		// 绕不过去就跳过：绝不把代理链路的速率报成宽带带宽。
		r.DirectOK = false
		if err2 != nil {
			r.Note = "物理网卡直连探测失败: " + err2.Error()
		} else {
			r.Note = fmt.Sprintf("物理网卡直连出口 %s ≠ 本机宽带出口 %s，无法确认直连", e2.ip, r.LocalIP)
		}
		pathResult = r
	})
	return pathResult
}
