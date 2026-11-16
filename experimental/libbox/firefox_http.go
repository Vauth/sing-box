package libbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	utls "github.com/metacubex/utls"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/proxy"
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
	globalJarMu  sync.RWMutex
	globalJar, _ = cookiejar.New(nil)

	globalStateMu       sync.RWMutex
	globalProtector     SocketProtector
	globalUpstreamProxy *url.URL
	globalDoHURL        string
	globalDNSServer     string
)

var (
	dohBootstrapMu sync.RWMutex
	dohIPCache     = make(map[string][]net.IP)
	hardcodedDoHIPs = map[string][]string{
		"cloudflare-dns.com": {"1.1.1.1", "1.0.0.1"},
		"dns.google":         {"8.8.8.8", "8.8.4.4"},
		"dns.quad9.net":      {"9.9.9.9", "149.112.112.112"},
	}
)

func FirefoxSetSocketProtector(protector SocketProtector) {
	globalStateMu.Lock()
	defer globalStateMu.Unlock()
	globalProtector = protector
}

func getSocketProtector() SocketProtector {
	globalStateMu.RLock()
	defer globalStateMu.RUnlock()
	return globalProtector
}

func FirefoxSetUpstreamProxy(proxyURL string) error {
	globalStateMu.Lock()
	defer globalStateMu.Unlock()
	if strings.TrimSpace(proxyURL) == "" {
		globalUpstreamProxy = nil
		return nil
	}
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("invalid upstream proxy URL: %w", err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" && scheme != "socks5" && scheme != "socks5h" {
		return fmt.Errorf("unsupported upstream proxy scheme: %s (supported: http, https, socks5, socks5h)", scheme)
	}
	globalUpstreamProxy = parsed
	return nil
}

func getUpstreamProxy() *url.URL {
	globalStateMu.RLock()
	defer globalStateMu.RUnlock()
	return globalUpstreamProxy
}

func FirefoxSetDoH(dohURL string) {
	globalStateMu.Lock()
	defer globalStateMu.Unlock()
	globalDoHURL = strings.TrimSpace(dohURL)
}

func FirefoxSetDNS(dnsServer string) {
	globalStateMu.Lock()
	defer globalStateMu.Unlock()
	globalDNSServer = strings.TrimSpace(dnsServer)
}

func FirefoxClearCookies() {
	globalJarMu.Lock()
	defer globalJarMu.Unlock()
	globalJar, _ = cookiejar.New(nil)
}

func FirefoxSetCookie(targetURL string, cookieHeader string) error {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return err
	}
	req := &http.Request{Header: http.Header{"Set-Cookie": []string{cookieHeader}}}
	cookies := req.Cookies()
	if len(cookies) == 0 {
		return errors.New("no valid cookie parsed from header")
	}
	globalJarMu.Lock()
	defer globalJarMu.Unlock()
	if globalJar == nil {
		globalJar, _ = cookiejar.New(nil)
	}
	globalJar.SetCookies(parsed, cookies)
	return nil
}

func FirefoxGetCookies(targetURL string) string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	globalJarMu.RLock()
	jar := globalJar
	globalJarMu.RUnlock()
	if jar == nil {
		return ""
	}
	cookies := jar.Cookies(parsed)
	if len(cookies) == 0 {
		return ""
	}
	var pairs []string
	for _, c := range cookies {
		pairs = append(pairs, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}
	return strings.Join(pairs, "; ")
}

func dialWithProtection(ctx context.Context, network, address string, protector SocketProtector) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	if protector != nil {
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			var protectErr error
			err := c.Control(func(fd uintptr) {
				protectErr = protector.Protect(int32(fd))
			})
			if err != nil {
				return err
			}
			return protectErr
		}
	}
	return dialer.DialContext(ctx, network, address)
}

func resolveBootstrapDoHIP(ctx context.Context, host string, protector SocketProtector) net.IP {
	dohBootstrapMu.RLock()
	cached, ok := dohIPCache[host]
	dohBootstrapMu.RUnlock()
	if ok && len(cached) > 0 {
		return cached[0]
	}
	if ips, found := hardcodedDoHIPs[host]; found && len(ips) > 0 {
		for _, ipStr := range ips {
			if parsed := net.ParseIP(ipStr); parsed != nil {
				return parsed
			}
		}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if protector != nil {
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			var protectErr error
			_ = c.Control(func(fd uintptr) {
				protectErr = protector.Protect(int32(fd))
			})
			return protectErr
		}
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}
	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err == nil && len(addrs) > 0 {
		var resolved []net.IP
		for _, a := range addrs {
			resolved = append(resolved, a.IP)
		}
		dohBootstrapMu.Lock()
		dohIPCache[host] = resolved
		dohBootstrapMu.Unlock()
		return resolved[0]
	}
	return nil
}

func queryDoH(ctx context.Context, dohURLStr string, host string, protector SocketProtector) ([]net.IP, error) {
	dohURL, err := url.Parse(dohURLStr)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH URL: %w", err)
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               0x4658,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(dnsmessage.Fqdn(host)),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed packing DNS query: %w", err)
	}

	bootstrapIP := resolveBootstrapDoHIP(ctx, dohURL.Hostname(), protector)

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(dCtx context.Context, network, address string) (net.Conn, error) {
			targetAddr := address
			if bootstrapIP != nil {
				port := dohURL.Port()
				if port == "" {
					port = "443"
				}
				targetAddr = net.JoinHostPort(bootstrapIP.String(), port)
			}
			return dialWithProtection(dCtx, network, targetAddr, protector)
		},
		TLSClientConfig: &tls.Config{
			ServerName: dohURL.Hostname(),
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   6 * time.Second,
	}

	dnsParam := base64.RawURLEncoding.EncodeToString(packed)
	dohReqURL := fmt.Sprintf("%s?dns=%s", dohURLStr, dnsParam)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dohReqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) Gecko/20100101 Firefox/158.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, err
	}

	var parsedMsg dnsmessage.Message
	if err := parsedMsg.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed unpacking DoH response: %w", err)
	}

	var ips []net.IP
	for _, ans := range parsedMsg.Answers {
		if ans.Header.Type == dnsmessage.TypeA {
			if aResource, ok := ans.Body.(*dnsmessage.AResource); ok {
				ips = append(ips, net.IP(aResource.A[:]))
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no A records returned by DoH for %s", host)
	}
	return ips, nil
}

func resolveHost(ctx context.Context, host string, protector SocketProtector) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	globalStateMu.RLock()
	doh := globalDoHURL
	targetDNS := globalDNSServer
	globalStateMu.RUnlock()

	if doh != "" {
		ips, err := queryDoH(ctx, doh, host, protector)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
	}

	if targetDNS != "" {
		hostPart, portPart, err := net.SplitHostPort(targetDNS)
		if err != nil {
			targetDNS = net.JoinHostPort(targetDNS, "53")
		} else if portPart == "" {
			targetDNS = net.JoinHostPort(hostPart, "53")
		}

		dialer := &net.Dialer{Timeout: 5 * time.Second}
		if protector != nil {
			dialer.Control = func(network, address string, c syscall.RawConn) error {
				var protectErr error
				_ = c.Control(func(fd uintptr) {
					protectErr = protector.Protect(int32(fd))
				})
				return protectErr
			}
		}
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(dCtx context.Context, network, address string) (net.Conn, error) {
				return dialer.DialContext(dCtx, "udp", targetDNS)
			},
		}
		addrs, err := resolver.LookupIPAddr(ctx, host)
		if err == nil && len(addrs) > 0 {
			var ips []net.IP
			for _, a := range addrs {
				ips = append(ips, a.IP)
			}
			return ips, nil
		}
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if protector != nil {
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			var protectErr error
			_ = c.Control(func(fd uintptr) {
				protectErr = protector.Protect(int32(fd))
			})
			return protectErr
		}
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(dCtx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(dCtx, network, address)
		},
	}
	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("failed resolving %s: %w", host, err)
	}
	var ips []net.IP
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

func dialUpstreamProxy(ctx context.Context, proxyURL *url.URL, targetHost, targetPort string, protector SocketProtector) (net.Conn, error) {
	scheme := strings.ToLower(proxyURL.Scheme)
	proxyHost := proxyURL.Hostname()
	proxyPort := proxyURL.Port()

	switch scheme {
	case "http", "https":
		if proxyPort == "" {
			if scheme == "https" {
				proxyPort = "443"
			} else {
				proxyPort = "8080"
			}
		}
		proxyAddr := net.JoinHostPort(proxyHost, proxyPort)

		proxyIPs, err := resolveHost(ctx, proxyHost, protector)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve upstream HTTP proxy host %s: %w", proxyHost, err)
		}

		var rawConn net.Conn
		var lastErr error
		for _, ip := range proxyIPs {
			dialAddr := net.JoinHostPort(ip.String(), proxyPort)
			rawConn, lastErr = dialWithProtection(ctx, "tcp", dialAddr, protector)
			if lastErr == nil {
				break
			}
		}
		if rawConn == nil {
			return nil, fmt.Errorf("failed connecting to upstream HTTP proxy %s: %w", proxyAddr, lastErr)
		}

		if scheme == "https" {
			tlsConn := tls.Client(rawConn, &tls.Config{ServerName: proxyHost})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = rawConn.Close()
				return nil, fmt.Errorf("TLS handshake with upstream proxy failed: %w", err)
			}
			rawConn = tlsConn
		}

		target := net.JoinHostPort(targetHost, targetPort)
		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
		if proxyURL.User != nil {
			auth := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.String()))
			connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
		}
		connectReq += "Proxy-Connection: Keep-Alive\r\n\r\n"

		if _, err := rawConn.Write([]byte(connectReq)); err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("failed sending CONNECT to proxy: %w", err)
		}

		br := bufio.NewReader(rawConn)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("failed reading CONNECT response from proxy: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			_ = rawConn.Close()
			return nil, fmt.Errorf("upstream proxy refused CONNECT tunnel with status %d", resp.StatusCode)
		}
		return rawConn, nil

	case "socks5", "socks5h":
		if proxyPort == "" {
			proxyPort = "1080"
		}
		proxyAddr := net.JoinHostPort(proxyHost, proxyPort)

		proxyIPs, err := resolveHost(ctx, proxyHost, protector)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve upstream SOCKS5 host %s: %w", proxyHost, err)
		}

		var directDialer proxy.ContextDialer = &netDialerWrapper{
			protector: protector,
			proxyIPs:  proxyIPs,
			proxyPort: proxyPort,
		}

		var auth *proxy.Auth
		if proxyURL.User != nil {
			pwd, _ := proxyURL.User.Password()
			auth = &proxy.Auth{
				User:     proxyURL.User.Username(),
				Password: pwd,
			}
		}

		socksDialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, directDialer)
		if err != nil {
			return nil, fmt.Errorf("failed initializing SOCKS5 dialer: %w", err)
		}

		target := net.JoinHostPort(targetHost, targetPort)
		if ctxDialer, ok := socksDialer.(proxy.ContextDialer); ok {
			return ctxDialer.DialContext(ctx, "tcp", target)
		}
		return socksDialer.Dial("tcp", target)

	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", scheme)
	}
}

type netDialerWrapper struct {
	protector SocketProtector
	proxyIPs  []net.IP
	proxyPort string
}

func (w *netDialerWrapper) Dial(network, addr string) (net.Conn, error) {
	return w.DialContext(context.Background(), network, addr)
}

func (w *netDialerWrapper) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var lastErr error
	for _, ip := range w.proxyIPs {
		dialAddr := net.JoinHostPort(ip.String(), w.proxyPort)
		conn, err := dialWithProtection(ctx, network, dialAddr, w.protector)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("failed connecting to any proxy IP: %w", lastErr)
}

func dialTarget(ctx context.Context, host, port string, protector SocketProtector) (net.Conn, error) {
	upstream := getUpstreamProxy()
	if upstream != nil {
		return dialUpstreamProxy(ctx, upstream, host, port, protector)
	}

	ips, err := resolveHost(ctx, host, protector)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, ip := range ips {
		addr := net.JoinHostPort(ip.String(), port)
		conn, err := dialWithProtection(ctx, "tcp", addr, protector)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("failed connecting to %s:%s (tried %d IPs): %w", host, port, len(ips), lastErr)
}

func FirefoxFetch(method string, targetURL string, headersJSON string, body []byte, timeoutSeconds int32) (*FirefoxResponse, error) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 30
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	scheme := strings.ToLower(parsedURL.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme: %s", scheme)
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	protector := getSocketProtector()

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), targetURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed building request: %w", err)
	}

	if headersJSON != "" {
		var headersMap map[string]interface{}
		if err := json.Unmarshal([]byte(headersJSON), &headersMap); err == nil {
			for k, v := range headersMap {
				switch val := v.(type) {
				case string:
					req.Header.Set(k, val)
				case []interface{}:
					req.Header.Del(k)
					for _, item := range val {
						if s, ok := item.(string); ok {
							req.Header.Add(k, s)
						}
					}
				}
			}
		}
	}

	globalJarMu.RLock()
	jar := globalJar
	globalJarMu.RUnlock()
	if jar != nil {
		for _, cookie := range jar.Cookies(parsedURL) {
			req.AddCookie(cookie)
		}
	}

	transport := &http.Transport{
		DisableCompression: true,
		ForceAttemptHTTP2:  false,
		DialContext: func(dCtx context.Context, network, addr string) (net.Conn, error) {
			return dialTarget(dCtx, host, port, protector)
		},
		DialTLSContext: func(dCtx context.Context, network, addr string) (net.Conn, error) {
			rawConn, err := dialTarget(dCtx, host, port, protector)
			if err != nil {
				return nil, err
			}
			return handshakeFirefoxTLS(dCtx, rawConn, host, nil, nil, "http/1.1")
		},
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if jar != nil {
		if rc := resp.Cookies(); len(rc) > 0 {
			jar.SetCookies(parsedURL, rc)
		}
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading response body: %w", err)
	}

	headersOut := make(map[string][]string)
	for k, v := range resp.Header {
		headersOut[k] = v
	}
	headerJSONBytes, _ := json.Marshal(headersOut)

	return &FirefoxResponse{
		StatusCode: int32(resp.StatusCode),
		HeaderJSON: string(headerJSONBytes),
		Body:       respBody,
	}, nil
}
