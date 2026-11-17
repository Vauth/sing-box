package libbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	utls "github.com/metacubex/utls"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
	"golang.org/x/net/publicsuffix"
)

// FirefoxResponse is bound by Gomobile as io.nekohasekai.libbox.FirefoxResponse.
// Using int32 guarantees that getStatusCode() returns standard 32-bit int in Java and Kotlin.
type FirefoxResponse struct {
	StatusCode int32
	HeaderJSON string
	Body       []byte
}

// SocketProtector allows Android VpnService to protect outbound sockets from looping into the VPN TUN.
// Gomobile binds this as io.nekohasekai.libbox.SocketProtector.
type SocketProtector interface {
	Protect(fd int32) error
}

var (
	ffConfigLock        sync.RWMutex
	ffCookieJar         *cookiejar.Jar
	ffSessions          = utls.NewLRUClientSessionCache(64)
	ffHTTPClient        *http.Client
	ffHTTP2Client       *http.Client
	ffHTTPAutoClient    *http.Client
	ffHTTP2Sessions     = utls.NewLRUClientSessionCache(64)
	ffRequireProtection bool
	ffProxyDNSLocal     bool
	ffAllowPrivateDNS   bool
	ffFollowRedirects   bool
	ffUpstreamProxy     string
	ffDoHURL            string
	ffCustomDNS         string
	ffSocketProtector   SocketProtector
	ffDohClient         *http.Client
	ffMaxResponseBytes  int64 = 16 * 1024 * 1024
)

type ffNetworkSnapshot struct {
	proxy, doh, dns                                            string
	localDNS, requireProtection, allowPrivate, followRedirects bool
	protector                                                  SocketProtector
	dohClient                                                  *http.Client
}
type ffNetworkSnapshotKey struct{}

func ffSnapshotLocked() ffNetworkSnapshot {
	return ffNetworkSnapshot{proxy: ffUpstreamProxy, doh: ffDoHURL, dns: ffCustomDNS, localDNS: ffProxyDNSLocal, requireProtection: ffRequireProtection, allowPrivate: ffAllowPrivateDNS, followRedirects: ffFollowRedirects, protector: ffSocketProtector, dohClient: ffDohClient}
}
func ffWithSnapshot(ctx context.Context) context.Context {
	if _, ok := ctx.Value(ffNetworkSnapshotKey{}).(ffNetworkSnapshot); ok {
		return ctx
	}
	ffConfigLock.RLock()
	cfg := ffSnapshotLocked()
	ffConfigLock.RUnlock()
	return context.WithValue(ctx, ffNetworkSnapshotKey{}, cfg)
}
func ffSnapshotFrom(ctx context.Context) ffNetworkSnapshot {
	if cfg, ok := ctx.Value(ffNetworkSnapshotKey{}).(ffNetworkSnapshot); ok {
		return cfg
	}
	ffConfigLock.RLock()
	defer ffConfigLock.RUnlock()
	return ffSnapshotLocked()
}
func init()                        { ffDohClient = ffNewDoHClient() }
func ffNewDoHClient() *http.Client { return ffNewDoHClientWithRoots(nil) }

// ffNewDoHClientWithRoots uses the system roots unless an explicit pool is supplied.
// The latter is only used for local regression tests.
func ffNewDoHClientWithRoots(roots *x509.CertPool) *http.Client {
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		ctx = ffWithSnapshot(ctx)
		if ffSnapshotFrom(ctx).proxy != "" {
			return ffDialWithOptionalProxyMode(ctx, address, false)
		}
		host, port, err := net.SplitHostPort(address)
		dialer := ffNewProtectedDialer(ctx, 5*time.Second)
		if err == nil {
			// Keep the same built-in bootstrap choices as FoxyVPN and race both
			// addresses; unknown providers use the platform's hostname resolver.
			var ips []string
			switch strings.ToLower(host) {
			case "cloudflare-dns.com", "one.one.one.one":
				ips = []string{"1.1.1.1", "1.0.0.1"}
			case "dns.google":
				ips = []string{"8.8.8.8", "8.8.4.4"}
			case "dns.quad9.net":
				ips = []string{"9.9.9.9", "149.112.112.112"}
			}
			if len(ips) > 0 {
				return ffRaceDial(ctx, ips, func(ctx context.Context, ip string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
				})
			}
		}
		return dialer.DialContext(ctx, network, address)
	}
	dialTLS := func(ctx context.Context, network, address string, alpn ...string) (*utls.UConn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		raw, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		shakeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return ffHandshakeTLS(shakeCtx, raw, host, roots, nil, alpn...)
	}
	h1 := &http.Transport{
		Proxy: nil, DialContext: dial, DisableCompression: true,
		MaxIdleConns: 4, IdleConnTimeout: 60 * time.Second,
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialTLS(ctx, network, address, "http/1.1")
		},
	}
	h2 := &http2.Transport{
		DisableCompression: true, IdleConnTimeout: 60 * time.Second,
		DialTLSContext: func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
			conn, err := dialTLS(ctx, network, address, "h2", "http/1.1")
			if err != nil {
				return nil, err
			}
			if conn.ConnectionState().NegotiatedProtocol != "h2" {
				_ = conn.Close()
				return nil, errFirefoxNoHTTP2
			}
			return conn, nil
		},
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &ffAutoTransport{h1: h1, h2: h2},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return errors.New("refusing insecure DoH redirect")
			}
			if len(via) >= 10 {
				return errors.New("too many DoH redirects")
			}
			return nil
		},
	}
}

// FirefoxSetSocketProtector sets a socket protector callback (VpnService.protect(fd)).
// Protects Go-managed sockets; the Android system resolver and network binding require separate handling.
func FirefoxSetSocketProtector(protector SocketProtector) {
	ffConfigLock.Lock()
	defer ffConfigLock.Unlock()
	ffSocketProtector = protector
	ffCloseIdleLocked()
}

func ffCloseIdleLocked() {
	for _, client := range []*http.Client{ffHTTPClient, ffHTTP2Client, ffHTTPAutoClient, ffDohClient} {
		if client != nil {
			client.CloseIdleConnections()
		}
	}
	ffHTTPClient = nil
	ffHTTP2Client = nil
	ffHTTPAutoClient = nil
	// A new pool isolates future DoH requests from old routing settings.
	ffDohClient = ffNewDoHClient()
}

// FirefoxRequireSocketProtection makes new Go-managed sockets fail closed if no protector is installed.
// It does not protect sockets created internally by the OS system resolver.
// The Android VPN lifecycle must enable this while protection is required.
func FirefoxRequireSocketProtection(required bool) {
	ffConfigLock.Lock()
	defer ffConfigLock.Unlock()
	ffRequireProtection = required
	ffCloseIdleLocked()
}

// FirefoxSetProxyDNSMode chooses destination resolution when a proxy is configured.
// "remote" (default) lets the proxy resolve the name. "local" uses the configured
// DoH/custom/system resolver before connecting through the proxy. DoH itself uses
// the proxy when one is configured. Custom and system DNS may still be direct.
func FirefoxSetProxyDNSMode(mode string) error {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "remote", "":
		ffConfigLock.Lock()
		defer ffConfigLock.Unlock()
		ffProxyDNSLocal = false
		ffCloseIdleLocked()
		return nil
	case "local":
		ffConfigLock.Lock()
		defer ffConfigLock.Unlock()
		ffProxyDNSLocal = true
		ffCloseIdleLocked()
		return nil
	default:
		return errors.New("proxy DNS mode must be remote or local")
	}
}

// FirefoxAllowPrivateDNS allows private, loopback and link-local DNS answers.
// The default is false. Enable only for trusted private network names.
func FirefoxAllowPrivateDNS(allow bool) {
	ffConfigLock.Lock()
	defer ffConfigLock.Unlock()
	ffAllowPrivateDNS = allow
	ffCloseIdleLocked()
}
func ffAllowedIP(ctx context.Context, ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	return ffSnapshotFrom(ctx).allowPrivate || (!ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast())
}

// FirefoxSetFollowRedirects enables up to 10 redirects for future clients.
// HTTPS to HTTP downgrades are always refused. Default is false.
func FirefoxSetFollowRedirects(follow bool) {
	ffConfigLock.Lock()
	defer ffConfigLock.Unlock()
	ffFollowRedirects = follow
	ffCloseIdleLocked()
}
func ffRedirectPolicy(follow bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if !follow {
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		if len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return errors.New("refusing HTTPS redirect downgrade")
		}
		return nil
	}
}

// FirefoxSetUpstreamProxy sets an upstream proxy for all Firefox uTLS requests.
// Accepts: "socks5://host:port", "socks5://user:pass@host:port", "http://host:port", or "" to disable.
func FirefoxSetUpstreamProxy(proxyURL string) error {
	ffConfigLock.Lock()
	defer ffConfigLock.Unlock()

	trimmed := strings.TrimSpace(proxyURL)
	if trimmed != "" {
		parsed, err := url.Parse(trimmed)
		if err != nil {
			return errors.New("invalid proxy URL")
		}
		scheme := strings.ToLower(parsed.Scheme)
		if scheme != "socks5" && scheme != "http" && scheme != "https" {
			return fmt.Errorf("unsupported proxy scheme %q", scheme)
		}
		if parsed.Hostname() == "" || parsed.Opaque != "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return errors.New("proxy URL must contain only a scheme, host, optional port and credentials")
		}
		if port := parsed.Port(); port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 {
				return errors.New("invalid proxy port")
			}
		}
	}

	ffUpstreamProxy = trimmed
	ffCloseIdleLocked()
	return nil
}

// FirefoxSetDoH sets a DNS-over-HTTPS URL (e.g. "https://cloudflare-dns.com/dns-query" or "https://dns.google/dns-query").
// Pass empty string "" to disable DoH and use system/UDP DNS.
func FirefoxSetDoH(dohURL string) {
	ffConfigLock.Lock()
	defer ffConfigLock.Unlock()
	ffDoHURL = strings.TrimSpace(dohURL)
	ffCloseIdleLocked()
}

// FirefoxSetDNS sets a custom UDP DNS resolver (e.g. "1.1.1.1" or "8.8.8.8:53").
// Pass empty string "" to use system DNS.
func FirefoxSetDNS(dnsServer string) {
	ffConfigLock.Lock()
	defer ffConfigLock.Unlock()
	ffCustomDNS = strings.TrimSpace(dnsServer)
	ffCloseIdleLocked()
}

// FirefoxSetMaxResponseBytes sets the maximum buffered response size in bytes.
// A positive limit is required. The default is 16 MiB. Set before requests start;
// it applies to subsequent requests and does not enable streaming.
func FirefoxSetMaxResponseBytes(limit int64) error {
	if limit <= 0 || limit == int64(^uint64(0)>>1) {
		return errors.New("response limit must be positive and less than MaxInt64")
	}
	ffConfigLock.Lock()
	ffMaxResponseBytes = limit
	ffConfigLock.Unlock()
	return nil
}

// FirefoxClearCookies resets the shared cookie jar.
func FirefoxClearCookies() {
	ffConfigLock.Lock()
	defer ffConfigLock.Unlock()
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	ffCookieJar = jar
	// Existing requests may still use the old jar; do not mutate a client in use.
	ffCloseIdleLocked()
}

// FirefoxSetCookie sets a cookie for targetURL in the shared jar.
func FirefoxSetCookie(targetURL string, cookieHeader string) error {
	ffConfigLock.Lock()
	defer ffConfigLock.Unlock()
	if ffCookieJar == nil {
		jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
		if err != nil {
			return err
		}
		ffCookieJar = jar
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}
	rawResp := &http.Response{Header: http.Header{"Set-Cookie": []string{cookieHeader}}}
	ffCookieJar.SetCookies(u, rawResp.Cookies())
	return nil
}

// FirefoxGetCookies returns the Cookie header string for targetURL from the shared jar (e.g. "name1=val1; name2=val2").
func FirefoxGetCookies(targetURL string) string {
	ffConfigLock.RLock()
	defer ffConfigLock.RUnlock()
	if ffCookieJar == nil {
		return ""
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	cookies := ffCookieJar.Cookies(u)
	if len(cookies) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		parts = append(parts, c.String())
	}
	return strings.Join(parts, "; ")
}

func ffNewProtectedDialer(ctx context.Context, timeout time.Duration) *net.Dialer {
	cfg := ffSnapshotFrom(ctx)
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var protectErr error
			err := c.Control(func(fd uintptr) {
				if cfg.protector != nil {
					protectErr = cfg.protector.Protect(int32(fd))
				} else if cfg.requireProtection {
					protectErr = errors.New("socket protection required but no protector is installed")
				}
			})
			if err != nil {
				return err
			}
			return protectErr
		},
	}
}

func ffResolveHost(ctx context.Context, host string) ([]string, error) {
	ctx = ffWithSnapshot(ctx)
	if net.ParseIP(host) != nil {
		return []string{host}, nil
	}

	cfg := ffSnapshotFrom(ctx)
	customDNS := cfg.dns

	if customDNS != "" {
		targetDNS := customDNS
		if _, _, err := net.SplitHostPort(targetDNS); err != nil {
			targetDNS = net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(targetDNS, "["), "]"), "53")
		}
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := ffNewProtectedDialer(ctx, 5*time.Second)
				return d.DialContext(ctx, network, targetDNS)
			},
		}
		ips, err := resolver.LookupIP(ctx, "ip", host)
		if err == nil && len(ips) > 0 {
			var res []string
			for _, ip := range ips {
				if ffAllowedIP(ctx, ip) {
					res = append(res, ip.String())
				}
			}
			if len(res) > 0 {
				return res, nil
			}
		}
		if err == nil {
			err = errors.New("no permitted address")
		}
		return nil, fmt.Errorf("custom DNS resolution for %s: %w", host, err)
	}

	// System resolver is used only when no DNS override is configured.
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var res []string
	for _, ip := range ips {
		if ffAllowedIP(ctx, ip) {
			res = append(res, ip.String())
		}
	}
	if len(res) > 0 {
		return res, nil
	}
	return nil, fmt.Errorf("no resolved IP for %s", host)
}

func ffResolveViaDoHType(ctx context.Context, dohURL string, host string, kind dnsmessage.Type) ([]net.IP, error) {
	u, err := url.Parse(dohURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, errors.New("DoH URL must be an absolute HTTPS URL")
	}
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: kind, Class: dnsmessage.ClassINET}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := ffSnapshotFrom(ctx).dohClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", resp.StatusCode)
	}

	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(contentType, "application/dns-message") {
		return nil, errors.New("unexpected DoH content type")
	}
	const maxDNSMessage = 65535
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSMessage+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDNSMessage {
		return nil, errors.New("DoH response too large")
	}
	var answer dnsmessage.Message
	if err := answer.Unpack(body); err != nil {
		return nil, err
	}
	if !answer.Header.Response || answer.Header.Truncated || answer.Header.ID != 0 {
		return nil, errors.New("invalid or truncated DoH response")
	}
	if answer.Header.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("DoH error code %s", answer.Header.RCode)
	}
	if len(answer.Questions) != 1 {
		return nil, errors.New("invalid DoH question count")
	}
	question := answer.Questions[0]
	if !strings.EqualFold(question.Name.String(), name.String()) || question.Type != kind || question.Class != dnsmessage.ClassINET {
		return nil, errors.New("DoH question mismatch")
	}
	// Only accept addresses belonging to the queried name or its CNAME chain.
	names := map[string]bool{strings.ToLower(name.String()): true}
	for i := 0; i < len(answer.Answers); i++ {
		changed := false
		for _, r := range answer.Answers {
			if r.Header.Class != dnsmessage.ClassINET || !names[strings.ToLower(r.Header.Name.String())] {
				continue
			}
			if cname, ok := r.Body.(*dnsmessage.CNAMEResource); ok {
				next := strings.ToLower(cname.CNAME.String())
				if !names[next] {
					names[next] = true
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
	var ips []net.IP
	for _, r := range answer.Answers {
		if r.Header.Class != dnsmessage.ClassINET || !names[strings.ToLower(r.Header.Name.String())] {
			continue
		}
		var ip net.IP
		if a, ok := r.Body.(*dnsmessage.AResource); ok && kind == dnsmessage.TypeA {
			ip = net.IP(a.A[:])
		}
		if a, ok := r.Body.(*dnsmessage.AAAAResource); ok && kind == dnsmessage.TypeAAAA {
			ip = net.IP(a.AAAA[:])
		}
		if !ffAllowedIP(ctx, ip) {
			continue
		}
		ips = append(ips, ip)
	}

	if len(ips) == 0 {
		return nil, errors.New("no public address in DoH response")
	}
	return ips, nil
}

type ffBufferedConn struct {
	r io.Reader
	net.Conn
}

func (c *ffBufferedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

// ffRaceDial staggers address attempts and closes losing connections.
func ffRaceDial(ctx context.Context, ips []string, dial func(context.Context, string) (net.Conn, error)) (net.Conn, error) {
	var v4, v6 []string
	seen := map[string]bool{}
	for _, ip := range ips {
		if seen[ip] {
			continue
		}
		seen[ip] = true
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	ordered := make([]string, 0, len(v4)+len(v6))
	firstV6 := len(ips) > 0 && net.ParseIP(ips[0]) != nil && net.ParseIP(ips[0]).To4() == nil
	for len(v4) > 0 || len(v6) > 0 {
		if firstV6 {
			if len(v6) > 0 {
				ordered = append(ordered, v6[0])
				v6 = v6[1:]
			}
			if len(v4) > 0 {
				ordered = append(ordered, v4[0])
				v4 = v4[1:]
			}
		} else {
			if len(v4) > 0 {
				ordered = append(ordered, v4[0])
				v4 = v4[1:]
			}
			if len(v6) > 0 {
				ordered = append(ordered, v6[0])
				v6 = v6[1:]
			}
		}
	}
	if len(ordered) == 0 {
		return nil, errors.New("no IP addresses to dial")
	}
	if len(ordered) > 32 {
		ordered = ordered[:32]
	}
	ctx, cancel := context.WithCancel(ctx)
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, len(ordered))
	for i, ip := range ordered {
		go func(i int, ip string) {
			if i > 0 {
				timer := time.NewTimer(time.Duration(i) * 250 * time.Millisecond)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					results <- result{nil, ctx.Err()}
					return
				case <-timer.C:
				}
			}
			conn, err := dial(ctx, ip)
			results <- result{conn, err}
		}(i, ip)
	}
	cleanup := func(n int) {
		cancel()
		go func() {
			for i := 0; i < n; i++ {
				r := <-results
				if r.conn != nil {
					r.conn.Close()
				}
			}
		}()
	}
	var last error
	for i := 0; i < len(ordered); i++ {
		select {
		case <-ctx.Done():
			cleanup(len(ordered) - i)
			return nil, ctx.Err()
		case r := <-results:
			if r.err == nil && r.conn != nil {
				if err := ctx.Err(); err != nil {
					_ = r.conn.Close()
					cleanup(len(ordered) - i - 1)
					return nil, err
				}
				cleanup(len(ordered) - i - 1)
				return r.conn, nil
			}
			if r.conn != nil {
				r.conn.Close()
			}
			last = r.err
		}
	}
	cancel()
	if last == nil {
		last = errors.New("all connection attempts failed")
	}
	return nil, last
}

// ffDialDoH races connections as DNS answers arrive. A late answer remains
// usable until a connection succeeds or the request is cancelled.
func ffDialDoH(ctx context.Context, lookup func(context.Context, dnsmessage.Type) ([]net.IP, error), dial func(context.Context, string) (net.Conn, error)) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	type dnsResult struct {
		kind dnsmessage.Type
		ips  []net.IP
		err  error
	}
	type dialResult struct {
		conn net.Conn
		err  error
	}
	dnsResults := make(chan dnsResult, 2)
	dialResults := make(chan dialResult, 32)
	for _, kind := range []dnsmessage.Type{dnsmessage.TypeAAAA, dnsmessage.TypeA} {
		go func(k dnsmessage.Type) { ips, err := lookup(ctx, k); dnsResults <- dnsResult{k, ips, err} }(kind)
	}
	var pending4, pending6 []string
	seen := make(map[string]bool)
	var lastErr error
	queries, active, attempts := 2, 0, 0
	v6Pending := true
	prefer6 := true
	var resolveTimer, attemptTimer *time.Timer
	var resolveC, attemptC <-chan time.Time
	stopTimer := func(timer **time.Timer, ch *<-chan time.Time) {
		if *timer != nil {
			(*timer).Stop()
			*timer = nil
		}
		*ch = nil
	}
	defer func() {
		stopTimer(&resolveTimer, &resolveC)
		stopTimer(&attemptTimer, &attemptC)
		cancel()
	}()
	start := func(ip string) {
		attempts++
		active++
		go func() { c, err := dial(ctx, ip); dialResults <- dialResult{c, err} }()
	}
	cleanup := func(n int) {
		cancel()
		go func() {
			for i := 0; i < n; i++ {
				r := <-dialResults
				if r.conn != nil {
					_ = r.conn.Close()
				}
			}
		}()
	}
	for {
		// Prefer IPv6, but wait no longer than the RFC-recommended resolution
		// delay when IPv4 is available before the AAAA answer.
		if active == 0 && len(pending6) == 0 && len(pending4) > 0 && v6Pending && resolveTimer == nil && attempts == 0 {
			resolveTimer = time.NewTimer(50 * time.Millisecond)
			resolveC = resolveTimer.C
		}
		waitingFor6 := resolveC != nil && len(pending6) == 0 && attempts == 0
		if !waitingFor6 && attempts < 32 && (len(pending4) > 0 || len(pending6) > 0) && (active == 0 || attemptC == nil) {
			var ip string
			if (prefer6 && len(pending6) > 0) || len(pending4) == 0 {
				ip, pending6 = pending6[0], pending6[1:]
				prefer6 = false
			} else {
				ip, pending4 = pending4[0], pending4[1:]
				prefer6 = true
			}
			start(ip)
			stopTimer(&attemptTimer, &attemptC)
			attemptTimer = time.NewTimer(250 * time.Millisecond)
			attemptC = attemptTimer.C
		}
		if active == 0 && queries == 0 && (attempts >= 32 || (len(pending4) == 0 && len(pending6) == 0)) {
			if lastErr == nil {
				lastErr = errors.New("no permitted DNS addresses")
			}
			return nil, lastErr
		}
		select {
		case <-ctx.Done():
			cleanup(active)
			return nil, ctx.Err()
		case <-resolveC:
			stopTimer(&resolveTimer, &resolveC)
			v6Pending = false
		case <-attemptC:
			stopTimer(&attemptTimer, &attemptC)
		case r := <-dnsResults:
			queries--
			if r.kind == dnsmessage.TypeAAAA {
				v6Pending = false
				stopTimer(&resolveTimer, &resolveC)
			}
			if r.err != nil {
				lastErr = r.err
			}
			for _, ip := range r.ips {
				if ip == nil || seen[ip.String()] {
					continue
				}
				key := ip.String()
				seen[key] = true
				if ip.To4() == nil {
					pending6 = append(pending6, key)
				} else {
					pending4 = append(pending4, key)
				}
			}
		case r := <-dialResults:
			active--
			if r.err == nil && r.conn != nil {
				if err := ctx.Err(); err != nil {
					_ = r.conn.Close()
					cleanup(active)
					return nil, err
				}
				cleanup(active)
				return r.conn, nil
			}
			if r.conn != nil {
				_ = r.conn.Close()
			}
			if r.err != nil {
				lastErr = r.err
			}
			// A failure need not consume the full stagger delay.
			stopTimer(&attemptTimer, &attemptC)
		}
	}
}

func ffDialWithOptionalProxy(ctx context.Context, address string) (net.Conn, error) {
	return ffDialWithOptionalProxyMode(ctx, address, true)
}
func ffDialWithOptionalProxyMode(ctx context.Context, address string, applyLocalDNS bool) (net.Conn, error) {
	ctx = ffWithSnapshot(ctx)
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		port = "443"
	}

	cfg := ffSnapshotFrom(ctx)
	proxyStr, localDNS := cfg.proxy, cfg.localDNS

	baseDialer := ffNewProtectedDialer(ctx, 20*time.Second)

	// For DoH, race connection attempts against both DNS responses rather than
	// discarding a family that arrives after the initial resolution delay.
	if cfg.doh != "" && net.ParseIP(host) == nil && (proxyStr == "" || (localDNS && applyLocalDNS)) {
		return ffDialDoH(ctx, func(ctx context.Context, kind dnsmessage.Type) ([]net.IP, error) {
			return ffResolveViaDoHType(ctx, cfg.doh, host, kind)
		}, func(ctx context.Context, ip string) (net.Conn, error) {
			if proxyStr != "" {
				return ffDialProxy(ctx, proxyStr, ip, port)
			}
			return baseDialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
		})
	}

	// When no proxy is configured, resolve destination via custom/system DNS directly
	if proxyStr == "" {
		ips, err := ffResolveHost(ctx, host)
		if err != nil {
			return nil, err
		}
		return ffRaceDial(ctx, ips, func(ctx context.Context, ip string) (net.Conn, error) {
			return baseDialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
		})
	}

	if localDNS && applyLocalDNS && net.ParseIP(host) == nil {
		ips, err := ffResolveHost(ctx, host)
		if err != nil {
			return nil, err
		}
		return ffRaceDial(ctx, ips, func(ctx context.Context, ip string) (net.Conn, error) {
			return ffDialProxy(ctx, proxyStr, ip, port)
		})
	}
	return ffDialProxy(ctx, proxyStr, host, port)
}

func ffDialProxy(ctx context.Context, proxyStr, host, port string) (net.Conn, error) {
	baseDialer := ffNewProtectedDialer(ctx, 20*time.Second)
	proxyParsed, err := url.Parse(proxyStr)
	if err != nil {
		return nil, errors.New("invalid upstream proxy URL")
	}

	scheme := strings.ToLower(proxyParsed.Scheme)
	proxyPort := proxyParsed.Port()
	if proxyPort == "" {
		switch scheme {
		case "socks5":
			proxyPort = "1080"
		case "https":
			proxyPort = "443"
		default:
			proxyPort = "80"
		}
	}
	proxyHost := net.JoinHostPort(proxyParsed.Hostname(), proxyPort)

	switch scheme {
	case "socks5":
		var auth *proxy.Auth
		if proxyParsed.User != nil {
			pwd, _ := proxyParsed.User.Password()
			auth = &proxy.Auth{
				User:     proxyParsed.User.Username(),
				Password: pwd,
			}
		}
		dialer, err := proxy.SOCKS5("tcp", proxyHost, auth, baseDialer)
		if err != nil {
			return nil, fmt.Errorf("create socks5 dialer: %w", err)
		}
		// Proxy resolves the destination hostname remotely
		targetAddr := net.JoinHostPort(host, port)
		if ctxDialer, ok := dialer.(proxy.ContextDialer); ok {
			return ctxDialer.DialContext(ctx, "tcp", targetAddr)
		}
		return dialer.Dial("tcp", targetAddr)

	case "http", "https":
		proxyConn, err := baseDialer.DialContext(ctx, "tcp", proxyHost)
		if err != nil {
			return nil, fmt.Errorf("connect to http proxy: %w", err)
		}

		// DialContext's deadline ends at TCP connect. Bound and cancel proxy negotiation too.
		tcpConn := proxyConn
		stopCancel := context.AfterFunc(ctx, func() { _ = tcpConn.Close() })
		defer stopCancel()
		deadline := time.Now().Add(20 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		if err := proxyConn.SetDeadline(deadline); err != nil {
			proxyConn.Close()
			return nil, err
		}
		if scheme == "https" {
			tlsConn := tls.Client(proxyConn, &tls.Config{ServerName: proxyParsed.Hostname(), MinVersion: tls.VersionTLS12})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				proxyConn.Close()
				return nil, fmt.Errorf("TLS to HTTPS proxy: %w", err)
			}
			proxyConn = tlsConn
		}
		targetHostPort := net.JoinHostPort(host, port)
		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n", targetHostPort, targetHostPort)
		if proxyParsed.User != nil {
			username := proxyParsed.User.Username()
			password, _ := proxyParsed.User.Password()
			encoded := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
			connectReq = fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\nProxy-Authorization: Basic %s\r\n\r\n", targetHostPort, targetHostPort, encoded)
		}

		if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
			_ = proxyConn.Close()
			return nil, fmt.Errorf("write http proxy CONNECT: %w", err)
		}

		limited := &io.LimitedReader{R: proxyConn, N: 64 * 1024}
		br := bufio.NewReader(limited)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			_ = proxyConn.Close()
			return nil, fmt.Errorf("read http proxy response: %w", err)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = proxyConn.Close()
			return nil, fmt.Errorf("http proxy CONNECT refused with status: %s", resp.Status)
		}
		// On a successful CONNECT, the connection is the tunnel; do not close resp.Body.
		if err := proxyConn.SetDeadline(time.Time{}); err != nil {
			proxyConn.Close()
			return nil, err
		}
		if ctx.Err() != nil {
			proxyConn.Close()
			return nil, ctx.Err()
		}

		if br.Buffered() > 0 {
			buffered := make([]byte, br.Buffered())
			if _, err := io.ReadFull(br, buffered); err != nil {
				proxyConn.Close()
				return nil, err
			}
			return &ffBufferedConn{r: io.MultiReader(bytes.NewReader(buffered), proxyConn), Conn: proxyConn}, nil
		}
		return proxyConn, nil

	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", scheme)
	}
}

func ffGetOrCreateClient() (*http.Client, error) { return ffGetOrCreateClientForMode(false) }
func ffGetOrCreateClientForMode(useHTTP2 bool) (*http.Client, error) {
	ffConfigLock.Lock()
	defer ffConfigLock.Unlock()
	return ffGetOrCreateClientLocked(useHTTP2)
}

// Caller holds ffConfigLock, so HTTP/1.1 and HTTP/2 use the same snapshot.
func ffGetOrCreateClientLocked(useHTTP2 bool) (*http.Client, error) {

	if useHTTP2 && ffHTTP2Client != nil {
		return ffHTTP2Client, nil
	}
	if !useHTTP2 && ffHTTPClient != nil {
		return ffHTTPClient, nil
	}

	if ffCookieJar == nil {
		jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
		if err != nil {
			return nil, fmt.Errorf("cookiejar: %w", err)
		}
		ffCookieJar = jar
	}

	cfg := ffSnapshotLocked()
	withCfg := func(ctx context.Context) context.Context { return context.WithValue(ctx, ffNetworkSnapshotKey{}, cfg) }

	if useHTTP2 {
		transport := &http2.Transport{
			DisableCompression: true,
			MaxHeaderListSize:  1 << 20,
			IdleConnTimeout:    90 * time.Second,
			DialTLSContext: func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
				ctx = withCfg(ctx)
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				raw, err := ffDialWithOptionalProxy(ctx, address)
				if err != nil {
					return nil, err
				}
				shakeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				defer cancel()
				conn, err := ffHandshakeTLS(shakeCtx, raw, host, nil, ffHTTP2Sessions, "h2", "http/1.1")
				if err != nil {
					return nil, err
				}
				if conn.ConnectionState().NegotiatedProtocol != "h2" {
					conn.Close()
					return nil, errFirefoxNoHTTP2
				}
				return conn, nil
			},
		}
		ffHTTP2Client = &http.Client{Transport: transport, Jar: ffCookieJar, CheckRedirect: ffRedirectPolicy(cfg.followRedirects)}
		return ffHTTP2Client, nil
	}

	transport := &http.Transport{
		Proxy:              nil,
		DisableCompression: true, // Do not add default Accept-Encoding: gzip; strictly send caller headers
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return ffDialWithOptionalProxy(withCfg(ctx), address)
		},
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			ctx = withCfg(ctx)
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				host = address
			}

			raw, err := ffDialWithOptionalProxy(ctx, address)
			if err != nil {
				return nil, err
			}

			// Complete a version-pinned Firefox-style TLS handshake
			shakeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			conn, err := ffHandshakeTLS(shakeCtx, raw, host, nil, ffSessions, "http/1.1")
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
		ForceAttemptHTTP2:      false,
		MaxResponseHeaderBytes: 1 << 20,
		MaxIdleConns:           64,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    15 * time.Second,
		ExpectContinueTimeout:  1 * time.Second,
	}

	ffHTTPClient = &http.Client{
		Transport: transport,
		Jar:       ffCookieJar,
		// FirefoxFetch supplies the per-request deadline.
		Timeout:       0,
		CheckRedirect: ffRedirectPolicy(cfg.followRedirects),
	}
	return ffHTTPClient, nil
}

// errFirefoxNoHTTP2 is emitted only before any HTTP request bytes are sent.
var errFirefoxNoHTTP2 = errors.New("server did not negotiate HTTP/2")

type ffAutoTransport struct {
	h1 http.RoundTripper
	h2 http.RoundTripper
}

func (t *ffAutoTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return t.h1.RoundTrip(req)
	}
	resp, err := t.h2.RoundTrip(req)
	if !errors.Is(err, errFirefoxNoHTTP2) {
		return resp, err
	}
	// A failed ALPN negotiation happens before an HTTP/2 ClientConn exists;
	// no request was sent. Recreate the body instead of reusing a possibly
	// closed reader. Do not retry for any other error.
	fallback := req.Clone(req.Context())
	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return nil, errors.New("HTTP/1.1 fallback requires a replayable request body")
		}
		body, bodyErr := req.GetBody()
		if bodyErr != nil {
			return nil, bodyErr
		}
		_ = req.Body.Close()
		fallback.Body = body
	}
	return t.h1.RoundTrip(fallback)
}

func (t *ffAutoTransport) CloseIdleConnections() {
	for _, tr := range []http.RoundTripper{t.h1, t.h2} {
		if c, ok := tr.(interface{ CloseIdleConnections() }); ok {
			c.CloseIdleConnections()
		}
	}
}

func ffGetOrCreateAutoClient() (*http.Client, error) {
	ffConfigLock.Lock()
	defer ffConfigLock.Unlock()
	if ffHTTPAutoClient != nil {
		return ffHTTPAutoClient, nil
	}
	h1, err := ffGetOrCreateClientLocked(false)
	if err != nil {
		return nil, err
	}
	h2, err := ffGetOrCreateClientLocked(true)
	if err != nil {
		return nil, err
	}
	ffHTTPAutoClient = &http.Client{
		Transport:     &ffAutoTransport{h1: h1.Transport, h2: h2.Transport},
		Jar:           ffCookieJar,
		CheckRedirect: ffRedirectPolicy(ffFollowRedirects),
	}
	return ffHTTPAutoClient, nil
}

// FirefoxFetchAuto negotiates HTTP/2 with an HTTP/1.1 fallback.
func FirefoxFetchAuto(method, targetURL, headersJSON string, body []byte, timeoutSeconds int32) (*FirefoxResponse, error) {
	return FirefoxNewAutoRequest(method, targetURL, headersJSON, body, timeoutSeconds).Execute()
}

// FirefoxNewAutoRequest creates a cancellable request with protocol fallback.
func FirefoxNewAutoRequest(method, targetURL, headersJSON string, body []byte, timeoutSeconds int32) *FirefoxRequest {
	r := FirefoxNewRequest(method, targetURL, headersJSON, body, timeoutSeconds, false)
	r.auto = true
	return r
}

// FirefoxFetch executes an HTTP request using Desktop Firefox 158 uTLS ClientHello.
// It applies caller headers; net/http can still add protocol headers and the cookie jar can add cookies.
// Uses the configured upstream proxy and DNS policy. See FirefoxSetProxyDNSMode.
// Sockets are protected via VpnService.protect (if FirefoxSetSocketProtector is registered).
// Gomobile export: io.nekohasekai.libbox.Libbox.firefoxFetch(...)
func FirefoxFetch(method string, targetURL string, headersJSON string, body []byte, timeoutSeconds int32) (*FirefoxResponse, error) {
	r := FirefoxNewRequest(method, targetURL, headersJSON, body, timeoutSeconds, false)
	return r.Execute()
}

// FirefoxFetchHTTP2 sends an HTTP/2 request through the configured route.
// The underlying HTTP transport may retry requests when permitted by Go.
func FirefoxFetchHTTP2(method string, targetURL string, headersJSON string, body []byte, timeoutSeconds int32) (*FirefoxResponse, error) {
	r := FirefoxNewRequest(method, targetURL, headersJSON, body, timeoutSeconds, true)
	return r.Execute()
}

// FirefoxRequest is single-use. Cancel can be called concurrently with Execute.
type FirefoxRequest struct {
	method, targetURL, headersJSON string
	body                           []byte
	useHTTP2                       bool
	auto                           bool
	ctx                            context.Context
	cancel                         context.CancelFunc
	mu                             sync.Mutex
	used                           bool
}

// FirefoxNewRequest creates a single-use cancellable request. The timeout starts now.
func FirefoxNewRequest(method string, targetURL string, headersJSON string, body []byte, timeoutSeconds int32, useHTTP2 bool) *FirefoxRequest {
	timeout := 30 * time.Second
	if timeoutSeconds > 0 {
		timeout = time.Duration(timeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return &FirefoxRequest{method: method, targetURL: targetURL, headersJSON: headersJSON, body: append([]byte(nil), body...), useHTTP2: useHTTP2, ctx: ctx, cancel: cancel}
}
func (r *FirefoxRequest) Cancel() { r.cancel() }
func (r *FirefoxRequest) Execute() (*FirefoxResponse, error) {
	r.mu.Lock()
	if r.used {
		r.mu.Unlock()
		return nil, errors.New("request already executed")
	}
	r.used = true
	r.mu.Unlock()
	defer r.cancel()
	return ffExecuteRequest(r.ctx, r.method, r.targetURL, r.headersJSON, r.body, r.useHTTP2, r.auto)
}
func ffExecuteRequest(ctx context.Context, method, targetURL, headersJSON string, body []byte, useHTTP2, auto bool) (*FirefoxResponse, error) {
	ffConfigLock.RLock()
	maxBody := ffMaxResponseBytes
	ffConfigLock.RUnlock()
	var client *http.Client
	var err error
	if auto {
		client, err = ffGetOrCreateAutoClient()
	} else {
		client, err = ffGetOrCreateClientForMode(useHTTP2)
	}
	if err != nil {
		return nil, err
	}

	cleanMethod := strings.ToUpper(strings.TrimSpace(method))
	if cleanMethod == "" {
		cleanMethod = http.MethodGet
	}

	cleanURL := strings.TrimSpace(targetURL)
	if cleanURL == "" {
		return nil, errors.New("targetURL must not be empty")
	}

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, cleanMethod, cleanURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return nil, errors.New("only HTTP and HTTPS URLs are supported")
	}
	if req.URL.Hostname() == "" {
		return nil, errors.New("URL must contain a hostname")
	}
	if useHTTP2 && req.URL.Scheme != "https" {
		return nil, errors.New("HTTP/2 requires HTTPS")
	}
	// Start with an empty caller header map. net/http may still add protocol headers.
	req.Header = make(http.Header)

	// Header JSON values must be strings, string arrays, or null.
	if strings.TrimSpace(headersJSON) != "" {
		var headerMap map[string]json.RawMessage
		if err := json.Unmarshal([]byte(headersJSON), &headerMap); err != nil {
			return nil, fmt.Errorf("parse request headers: %w", err)
		}
		if headerMap == nil {
			return nil, errors.New("request headers must be a JSON object")
		}
		for k, raw := range headerMap {
			if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				continue
			}
			var value string
			if err := json.Unmarshal(raw, &value); err == nil {
				if strings.EqualFold(k, "host") {
					req.Host = value
				} else {
					req.Header.Set(k, value)
				}
				continue
			}
			var values []string
			if err := json.Unmarshal(raw, &values); err != nil || strings.EqualFold(k, "host") {
				return nil, fmt.Errorf("header %q must be a string or array of strings", k)
			}
			for _, v := range values {
				req.Header.Add(k, v)
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Bound the buffered response to protect Android memory.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if int64(len(respBody)) > maxBody {
		return nil, fmt.Errorf("response body exceeds %d bytes", maxBody)
	}

	respHeaderMap := make(map[string][]string)
	for k, v := range resp.Header {
		respHeaderMap[k] = v
	}
	headerBytes, _ := json.Marshal(respHeaderMap)

	return &FirefoxResponse{
		StatusCode: int32(resp.StatusCode),
		HeaderJSON: string(headerBytes),
		Body:       respBody,
	}, nil
}
