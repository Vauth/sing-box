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
	ffConfigLock      sync.RWMutex
	ffCookieJar       *cookiejar.Jar
	ffSessions        = utls.NewLRUClientSessionCache(64)
	ffHTTPClient      *http.Client
	ffUpstreamProxy   string
	ffDoHURL          string
	ffCustomDNS       string
	ffSocketProtector SocketProtector
	ffDohClient       = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        4,
			IdleConnTimeout:     60 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(address)
				if err == nil {
					// Bootstrap well-known DoH providers directly by IP to bypass local DNS poisoning
					switch strings.ToLower(host) {
					case "cloudflare-dns.com", "one.one.one.one":
						address = net.JoinHostPort("1.1.1.1", port)
					case "dns.google":
						address = net.JoinHostPort("8.8.8.8", port)
					case "dns.quad9.net":
						address = net.JoinHostPort("9.9.9.9", port)
					}
				}
				dialer := ffNewProtectedDialer(5 * time.Second)
				return dialer.DialContext(ctx, network, address)
			},
		},
	}
)

// FirefoxSetSocketProtector sets a socket protector callback (VpnService.protect(fd)).
// Ensures outbound sockets are routed through the physical network when the VPN is active.
func FirefoxSetSocketProtector(protector SocketProtector) {
	ffConfigLock.Lock()
	defer ffConfigLock.Unlock()
	ffSocketProtector = protector
}

func ffCloseIdleLocked() {
	if ffHTTPClient != nil {
		if tr, ok := ffHTTPClient.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
		ffHTTPClient = nil
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
			return fmt.Errorf("invalid proxy url: %w", err)
		}
		scheme := strings.ToLower(parsed.Scheme)
		if scheme != "socks5" && scheme != "http" && scheme != "https" {
			return fmt.Errorf("unsupported proxy scheme %q, must be socks5 or http", scheme)
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

// FirefoxClearCookies resets the shared cookie jar.
func FirefoxClearCookies() {
	ffConfigLock.Lock()
	defer ffConfigLock.Unlock()
	jar, _ := cookiejar.New(nil)
	ffCookieJar = jar
	if ffHTTPClient != nil {
		ffHTTPClient.Jar = jar
	}
}

// FirefoxSetCookie sets a cookie for targetURL in the shared jar.
func FirefoxSetCookie(targetURL string, cookieHeader string) error {
	ffConfigLock.Lock()
	defer ffConfigLock.Unlock()
	if ffCookieJar == nil {
		jar, err := cookiejar.New(nil)
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

func ffNewProtectedDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var protectErr error
			err := c.Control(func(fd uintptr) {
				ffConfigLock.RLock()
				protector := ffSocketProtector
				ffConfigLock.RUnlock()
				if protector != nil {
					protectErr = protector.Protect(int32(fd))
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
	if net.ParseIP(host) != nil {
		return []string{host}, nil
	}

	ffConfigLock.RLock()
	dohURL := ffDoHURL
	customDNS := ffCustomDNS
	ffConfigLock.RUnlock()

	if dohURL != "" {
		ips, err := ffResolveViaDoH(ctx, dohURL, host)
		if err == nil && len(ips) > 0 {
			res := make([]string, 0, len(ips))
			for _, ip := range ips {
				res = append(res, ip.String())
			}
			return res, nil
		}
	}

	if customDNS != "" {
		targetDNS := customDNS
		if _, _, err := net.SplitHostPort(targetDNS); err != nil {
			targetDNS = net.JoinHostPort(targetDNS, "53")
		}
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := ffNewProtectedDialer(5 * time.Second)
				return d.DialContext(ctx, "udp", targetDNS)
			},
		}
		ips, err := resolver.LookupIP(ctx, "ip4", host)
		if err == nil && len(ips) > 0 {
			var res []string
			for _, ip := range ips {
				if !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast() {
					res = append(res, ip.String())
				}
			}
			if len(res) > 0 {
				return res, nil
			}
		}
	}

	// Fallback to system resolver
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	var res []string
	for _, ip := range ips {
		if !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast() {
			res = append(res, ip.String())
		}
	}
	if len(res) > 0 {
		return res, nil
	}
	return nil, fmt.Errorf("no resolved IP for %s", host)
}

func ffResolveViaDoH(ctx context.Context, dohURL string, host string) ([]net.IP, error) {
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
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

	resp, err := ffDohClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	var p dnsmessage.Parser
	header, err := p.Start(body)
	if err != nil {
		return nil, err
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("DoH error code %s", header.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}

	var ips []net.IP
	for {
		h, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Type != dnsmessage.TypeA {
			if err := p.SkipAnswer(); err != nil {
				return nil, err
			}
			continue
		}
		r, err := p.AResource()
		if err != nil {
			return nil, err
		}
		ip := net.IP(r.A[:])
		// Matches Arman's IsBlockPage check: filter out private, loopback, link-local, and Iranian DNS poison IPs (10.10.34.34-36)
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			continue
		}
		ips = append(ips, ip)
	}

	if len(ips) == 0 {
		return nil, errors.New("no public A record in DoH response")
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

func ffDialWithOptionalProxy(ctx context.Context, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		port = "443"
	}

	ffConfigLock.RLock()
	proxyStr := ffUpstreamProxy
	ffConfigLock.RUnlock()

	baseDialer := ffNewProtectedDialer(20 * time.Second)

	// When no proxy is configured, resolve destination via DoH/custom DNS directly
	if proxyStr == "" {
		ips, err := ffResolveHost(ctx, host)
		if err == nil && len(ips) > 0 {
			for _, ip := range ips {
				targetTCPAddr := net.JoinHostPort(ip, port)
				conn, err := baseDialer.DialContext(ctx, "tcp", targetTCPAddr)
				if err == nil {
					return conn, nil
				}
			}
		}
		// Fallback to dialing host directly
		return baseDialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	}

	proxyParsed, err := url.Parse(proxyStr)
	if err != nil {
		return nil, fmt.Errorf("parse upstream proxy: %w", err)
	}

	scheme := strings.ToLower(proxyParsed.Scheme)
	proxyHost := proxyParsed.Host
	if _, _, err := net.SplitHostPort(proxyHost); err != nil {
		defaultPort := "1080"
		if scheme != "socks5" {
			defaultPort = "8080"
		}
		proxyHost = net.JoinHostPort(proxyHost, defaultPort)
	}

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

		br := bufio.NewReader(proxyConn)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			_ = proxyConn.Close()
			return nil, fmt.Errorf("read http proxy response: %w", err)
		}
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_ = proxyConn.Close()
			return nil, fmt.Errorf("http proxy CONNECT refused with status: %s", resp.Status)
		}

		if br.Buffered() > 0 {
			return &ffBufferedConn{r: br, Conn: proxyConn}, nil
		}
		return proxyConn, nil

	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", scheme)
	}
}

func ffGetOrCreateClient() (*http.Client, error) {
	ffConfigLock.Lock()
	defer ffConfigLock.Unlock()

	if ffHTTPClient != nil {
		return ffHTTPClient, nil
	}

	if ffCookieJar == nil {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, fmt.Errorf("cookiejar: %w", err)
		}
		ffCookieJar = jar
	}

	transport := &http.Transport{
		Proxy:               nil,
		DisableCompression: true, // Do not add default Accept-Encoding: gzip; strictly send caller headers
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return ffDialWithOptionalProxy(ctx, address)
		},
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				host = address
			}

			raw, err := ffDialWithOptionalProxy(ctx, address)
			if err != nil {
				return nil, err
			}

			// Complete desktop Firefox 158 TLS ClientHello handshake
			conn, err := ffHandshakeTLS(ctx, raw, host, nil, ffSessions, "http/1.1")
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	ffHTTPClient = &http.Client{
		Transport:     transport,
		Jar:           ffCookieJar,
		Timeout:       35 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return ffHTTPClient, nil
}

// FirefoxFetch executes an HTTP request using Desktop Firefox 158 uTLS ClientHello.
// It sends ONLY the exact headers provided by the caller in headersJSON without injecting any default or synthetic headers.
// Automatically routes through upstream proxy (if configured) and resolves via DoH (if configured).
// Sockets are protected via VpnService.protect (if FirefoxSetSocketProtector is registered).
// Gomobile export: io.nekohasekai.libbox.Libbox.firefoxFetch(...)
func FirefoxFetch(method string, targetURL string, headersJSON string, body []byte, timeoutSeconds int32) (*FirefoxResponse, error) {
	client, err := ffGetOrCreateClient()
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

	timeout := 30 * time.Second
	if timeoutSeconds > 0 {
		timeout = time.Duration(timeoutSeconds) * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, cleanMethod, cleanURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Reset headers to guarantee NO default or automatic headers are injected by Go
	req.Header = make(http.Header)

	// Apply STRICTLY and ONLY headers passed by caller in headersJSON
	if strings.TrimSpace(headersJSON) != "" && headersJSON != "{}" {
		var headerMap map[string]interface{}
		if err := json.Unmarshal([]byte(headersJSON), &headerMap); err == nil {
			for k, v := range headerMap {
				if v == nil {
					continue
				}
				if strings.EqualFold(k, "host") {
					req.Host = fmt.Sprint(v)
					continue
				}
				switch val := v.(type) {
				case string:
					req.Header.Set(k, val)
				case []interface{}:
					for _, item := range val {
						if item != nil {
							req.Header.Add(k, fmt.Sprint(item))
						}
					}
				default:
					req.Header.Set(k, fmt.Sprint(val))
				}
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Limit to 16MB to protect Android memory
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
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
