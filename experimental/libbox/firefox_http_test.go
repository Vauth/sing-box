package libbox

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	utls "github.com/metacubex/utls"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func resetFirefoxTestState(t *testing.T) {
	t.Helper()
	ffConfigLock.Lock()
	ffCloseIdleLocked()
	ffCookieJar = nil
	ffUpstreamProxy = ""
	ffDoHURL = ""
	ffCustomDNS = ""
	ffSocketProtector = nil
	ffRequireProtection = false
	ffProxyDNSLocal = false
	ffAllowPrivateDNS = false
	ffFollowRedirects = false
	ffMaxResponseBytes = 16 * 1024 * 1024
	ffConfigLock.Unlock()
}
func TestFetchAndHeaders(t *testing.T) {
	resetFirefoxTestState(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") != "ok" {
			t.Error("missing custom header")
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	r, err := FirefoxFetch("GET", srv.URL, `{"X-Custom":"ok"}`, nil, 3)
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Body) != "ok" || r.StatusCode != 200 {
		t.Fatalf("response %v", r)
	}
	if _, err = FirefoxFetch("GET", srv.URL, `{bad`, nil, 3); err == nil {
		t.Fatal("malformed JSON accepted")
	}
}
func TestResponseLimit(t *testing.T) {
	resetFirefoxTestState(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, strings.NewReader(strings.Repeat("x", 16*1024*1024+1)))
	}))
	defer srv.Close()
	_, err := FirefoxFetch("GET", srv.URL, "{}", nil, 10)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("got %v", err)
	}
}
func TestDoHFailureDoesNotFallBack(t *testing.T) {
	resetFirefoxTestState(t)
	FirefoxSetDoH("https://127.0.0.1:1/dns-query")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := ffDialWithOptionalProxy(ctx, "localhost:443"); err == nil {
		t.Fatal("unexpected fallback")
	}
}
func TestTLSHandshakeAndVerification(t *testing.T) {
	resetFirefoxTestState(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	host, _, _ := net.SplitHostPort(u.Host)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := net.DialTimeout("tcp", u.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ffHandshakeTLS(ctx, raw, host, roots, nil, "http/1.1")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	raw, err = net.DialTimeout("tcp", u.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c, err = ffHandshakeTLS(ctx, raw, "wrong.invalid", roots, nil, "http/1.1")
	if err == nil {
		c.Close()
		t.Fatal("wrong hostname accepted")
	}
}
func TestHTTPSProxyMustVerifyCertificate(t *testing.T) {
	resetFirefoxTestState(t)
	var mu sync.Mutex
	var method string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		method = r.Method
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	u.User = url.UserPassword("user", "secret")
	if err := FirefoxSetUpstreamProxy(u.String()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := ffDialWithOptionalProxy(ctx, "example.com:443")
	if err == nil {
		c.Close()
		t.Fatal("untrusted TLS proxy accepted")
	}
	mu.Lock()
	defer mu.Unlock()
	if method != "" {
		t.Fatal("request reached untrusted proxy")
	}
}
func TestProxyCancellation(t *testing.T) {
	resetFirefoxTestState(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			io.Copy(io.Discard, c)
		}
	}()
	if err = FirefoxSetUpstreamProxy("http://" + ln.Addr().String()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	c, err := ffDialWithOptionalProxy(ctx, "example.com:443")
	if err == nil {
		c.Close()
		t.Fatal("expected timeout")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("proxy cancellation too slow")
	}
	<-done
}
func TestClearCookiesConcurrent(t *testing.T) {
	resetFirefoxTestState(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "a", Value: "b"})
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 15; j++ {
				if _, err := FirefoxFetch("GET", srv.URL, "{}", nil, 3); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		FirefoxClearCookies()
	}
	wg.Wait()
}
func TestHTTPConnectTunnel(t *testing.T) {
	resetFirefoxTestState(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			t.Errorf("method %s", r.Method)
		}
		if r.Host != "example.com:443" {
			t.Errorf("target %s", r.Host)
		}
		if r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpzZWNyZXQ=" {
			t.Error("missing proxy authentication")
		}
		c, br, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		_, _ = br.WriteString("HTTP/1.1 200 Connection Established\r\n\r\nhello")
		_ = br.Flush()
		b := make([]byte, 4)
		_, err = io.ReadFull(br, b)
		if err != nil || string(b) != "ping" {
			t.Errorf("tunnel read %q %v", b, err)
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	u.User = url.UserPassword("user", "secret")
	if err := FirefoxSetUpstreamProxy(u.String()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := ffDialWithOptionalProxy(ctx, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b := make([]byte, 5)
	if _, err = io.ReadFull(c, b); err != nil || string(b) != "hello" {
		t.Fatalf("tunnel read %q %v", b, err)
	}
	if _, err = c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
}
func TestRejectHTTPDoH(t *testing.T) {
	resetFirefoxTestState(t)
	if _, err := ffResolveViaDoHType(context.Background(), "http://example.com/dns-query", "example.com", dnsmessage.TypeA); err == nil {
		t.Fatal("HTTP DoH accepted")
	}
}
func TestRequireSocketProtection(t *testing.T) {
	resetFirefoxTestState(t)
	FirefoxRequireSocketProtection(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	if _, err := FirefoxFetch("GET", srv.URL, "{}", nil, 2); err == nil || !strings.Contains(err.Error(), "protection required") {
		t.Fatalf("expected protection failure, got %v", err)
	}
	FirefoxRequireSocketProtection(false)
	if _, err := FirefoxFetch("GET", srv.URL, "{}", nil, 2); err != nil {
		t.Fatal(err)
	}
}
func TestRequestCancellation(t *testing.T) {
	resetFirefoxTestState(t)
	started := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer srv.Close()
	req := FirefoxNewRequest("GET", srv.URL, "{}", nil, 10, false)
	done := make(chan error, 1)
	go func() { _, err := req.Execute(); done <- err }()
	<-started
	req.Cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancel returned no error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancel timed out")
	}
	if _, err := req.Execute(); err == nil {
		t.Fatal("reuse accepted")
	}
}
func TestHTTP2RealHandshake(t *testing.T) {
	if u := os.Getenv("FF_HTTP2_TEST_URL"); u != "" {
		r, err := FirefoxFetchHTTP2("GET", u, `{"User-Agent":"test"}`, nil, 5)
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Body) != "h2" {
			t.Fatalf("body: %s", r.Body)
		}
		FirefoxSetFollowRedirects(true)
		r, err = FirefoxFetchHTTP2("GET", u+"/redirect", `{"User-Agent":"test"}`, nil, 5)
		if err != nil || r.StatusCode != 200 || string(r.Body) != "h2" {
			t.Fatalf("HTTP/2 redirect: %v %v", r, err)
		}
		return
	}
	resetFirefoxTestState(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		if r.ProtoMajor != 2 {
			t.Errorf("protocol %s", r.Proto)
		}
		fmt.Fprint(w, "h2")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHTTP2RealHandshake$")
	cmd.Env = append(os.Environ(), "FF_HTTP2_TEST_URL="+srv.URL, "SSL_CERT_FILE="+file, "SSL_CERT_DIR="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess: %v\n%s", err, out)
	}
}
func TestDualStackDoHViaProxy(t *testing.T) {
	resetFirefoxTestState(t)
	doh := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Error("not POST")
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		var q dnsmessage.Message
		if err = q.Unpack(b); err != nil {
			t.Error(err)
			return
		}
		typ := q.Questions[0].Type
		ans := dnsmessage.Message{Header: dnsmessage.Header{Response: true, RecursionAvailable: true}, Questions: q.Questions}
		h := dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: typ, Class: dnsmessage.ClassINET, TTL: 60}
		if typ == dnsmessage.TypeA {
			ans.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 7}}}}
		} else {
			ans.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}}}}
		}
		out, err := ans.Pack()
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
	}))
	defer doh.Close()
	roots := x509.NewCertPool()
	roots.AddCert(doh.Certificate())
	var mu sync.Mutex
	var count int
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			t.Error("not CONNECT")
			return
		}
		mu.Lock()
		count++
		mu.Unlock()
		remote, err := net.DialTimeout("tcp", r.Host, time.Second)
		if err != nil {
			t.Error(err)
			w.WriteHeader(502)
			return
		}
		c, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			remote.Close()
			t.Error(err)
			return
		}
		buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		buf.Flush()
		go func() { defer c.Close(); defer remote.Close(); go io.Copy(remote, buf); io.Copy(c, remote) }()
	}))
	defer proxySrv.Close()
	if err := FirefoxSetUpstreamProxy(proxySrv.URL); err != nil {
		t.Fatal(err)
	}
	if err := FirefoxSetProxyDNSMode("local"); err != nil {
		t.Fatal(err)
	}
	ffDohClient.CloseIdleConnections()
	ffDohClient = ffNewDoHClientWithRoots(roots)
	defer ffDohClient.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = ffWithSnapshot(ctx)
	for _, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		ips, err := ffResolveViaDoHType(ctx, doh.URL, "example.test", kind)
		if err != nil || len(ips) != 1 {
			t.Fatalf("query %v: ips=%v error=%v", kind, ips, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if count == 0 {
		t.Fatal("DoH did not use proxy")
	}
}
func TestConfigSnapshotPreservesProxy(t *testing.T) {
	resetFirefoxTestState(t)
	hit := make(chan bool, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit <- true; w.WriteHeader(http.StatusForbidden) }))
	defer srv.Close()
	if err := FirefoxSetUpstreamProxy(srv.URL); err != nil {
		t.Fatal(err)
	}
	ctx := ffWithSnapshot(context.Background())
	if err := FirefoxSetUpstreamProxy(""); err != nil {
		t.Fatal(err)
	}
	_, err := ffDialWithOptionalProxy(ctx, "no-such-host.invalid:443")
	if err == nil {
		t.Fatal("proxy refusal expected")
	}
	select {
	case <-hit:
	case <-time.After(time.Second):
		t.Fatal("snapshot lost proxy")
	}
}
func TestRaceDialFallsBackAndClosesLoser(t *testing.T) {
	firstClient, firstServer := net.Pipe()
	defer firstServer.Close()
	secondClient, secondServer := net.Pipe()
	defer secondServer.Close()
	result, err := ffRaceDial(context.Background(), []string{"2001:db8::1", "192.0.2.1"}, func(ctx context.Context, ip string) (net.Conn, error) {
		if strings.Contains(ip, ":") {
			<-ctx.Done()
			return firstClient, nil
		}
		return secondClient, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result != secondClient {
		t.Fatal("wrong winner")
	}
	result.Close()
	firstServer.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := firstServer.Read(buf); err != io.EOF {
		t.Fatalf("loser not closed: %v", err)
	}
}
func TestAllowPrivateDNS(t *testing.T) {
	resetFirefoxTestState(t)
	if _, err := ffResolveHost(context.Background(), "localhost"); err == nil {
		t.Fatal("private resolution allowed by default")
	}
	FirefoxAllowPrivateDNS(true)
	ips, err := ffResolveHost(context.Background(), "localhost")
	if err != nil || len(ips) == 0 {
		t.Fatalf("private resolution: %v %v", ips, err)
	}
}
func TestCustomDNSFallbackToTCP(t *testing.T) {
	resetFirefoxTestState(t)
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			reply := dnsmessage.Message{Header: dnsmessage.Header{ID: q.Header.ID, Response: true, Truncated: true}, Questions: q.Questions}
			b, _ := reply.Pack()
			udp.WriteTo(b, addr)
		}
	}()
	go func() {
		defer wg.Done()
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				var n [2]byte
				if _, err := io.ReadFull(c, n[:]); err != nil {
					return
				}
				b := make([]byte, int(binary.BigEndian.Uint16(n[:])))
				if _, err := io.ReadFull(c, b); err != nil {
					return
				}
				var q dnsmessage.Message
				if q.Unpack(b) != nil || len(q.Questions) != 1 {
					return
				}
				h := dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: q.Questions[0].Type, Class: dnsmessage.ClassINET, TTL: 60}
				reply := dnsmessage.Message{Header: dnsmessage.Header{ID: q.Header.ID, Response: true, RecursionAvailable: true}, Questions: q.Questions}
				if h.Type == dnsmessage.TypeA {
					reply.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 2}}}}
				} else if h.Type == dnsmessage.TypeAAAA {
					reply.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}}}}
				}
				out, _ := reply.Pack()
				binary.BigEndian.PutUint16(n[:], uint16(len(out)))
				c.Write(n[:])
				c.Write(out)
			}()
		}
	}()
	FirefoxSetDNS(tcp.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := ffResolveHost(ctx, "foo.example.test")
	if err != nil || len(ips) != 2 {
		t.Errorf("TCP fallback: %v %v", ips, err)
	}
	udp.Close()
	tcp.Close()
	wg.Wait()
}
func TestHTTPSProxyTrusted(t *testing.T) {
	if p := os.Getenv("FF_PROXY_TEST_URL"); p != "" {
		if err := FirefoxSetUpstreamProxy(p); err != nil {
			t.Fatal(err)
		}
		r, err := FirefoxFetch("GET", os.Getenv("FF_PROXY_TARGET"), "{}", nil, 5)
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Body) != "through proxy" {
			t.Fatalf("body: %s", r.Body)
		}
		return
	}
	resetFirefoxTestState(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "through proxy") }))
	defer target.Close()
	proxySrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpzZWNyZXQ=" {
			t.Error("bad CONNECT or credentials")
			return
		}
		remote, err := net.Dial("tcp", r.Host)
		if err != nil {
			t.Error(err)
			return
		}
		c, b, err := w.(http.Hijacker).Hijack()
		if err != nil {
			remote.Close()
			t.Error(err)
			return
		}
		b.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		b.Flush()
		go func() { defer c.Close(); defer remote.Close(); go io.Copy(remote, b); io.Copy(c, remote) }()
	}))
	defer proxySrv.Close()
	file := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxySrv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(proxySrv.URL)
	u.User = url.UserPassword("user", "secret")
	cmd := exec.Command(os.Args[0], "-test.run=^TestHTTPSProxyTrusted$")
	cmd.Env = append(os.Environ(), "FF_PROXY_TEST_URL="+u.String(), "FF_PROXY_TARGET="+target.URL, "SSL_CERT_FILE="+file, "SSL_CERT_DIR="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess: %v\n%s", err, out)
	}
}
func TestSOCKS5Authenticated(t *testing.T) {
	resetFirefoxTestState(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		read := func(n int) ([]byte, error) { b := make([]byte, n); _, e := io.ReadFull(c, b); return b, e }
		h, e := read(2)
		if e != nil {
			done <- e
			return
		}
		methods, e := read(int(h[1]))
		if e != nil {
			done <- e
			return
		}
		if h[0] != 5 || !strings.Contains(string(methods), string([]byte{2})) {
			done <- fmt.Errorf("no username auth method")
			return
		}
		c.Write([]byte{5, 2})
		a, e := read(2)
		if e != nil {
			done <- e
			return
		}
		user, e := read(int(a[1]))
		if e != nil {
			done <- e
			return
		}
		plen, e := read(1)
		if e != nil {
			done <- e
			return
		}
		pass, e := read(int(plen[0]))
		if e != nil {
			done <- e
			return
		}
		if a[0] != 1 || string(user) != "user" || string(pass) != "secret" {
			done <- fmt.Errorf("wrong credentials")
			return
		}
		c.Write([]byte{1, 0})
		req, e := read(4)
		if e != nil {
			done <- e
			return
		}
		switch req[3] {
		case 1:
			_, e = read(4)
		case 4:
			_, e = read(16)
		case 3:
			l, x := read(1)
			if x != nil {
				done <- x
				return
			}
			_, e = read(int(l[0]))
		default:
			e = fmt.Errorf("bad SOCKS address")
		}
		if e != nil {
			done <- e
			return
		}
		if _, e = read(2); e != nil {
			done <- e
			return
		}
		c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		b := bufio.NewReader(c)
		for {
			line, e := b.ReadString('\n')
			if e != nil {
				done <- e
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, e = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		done <- e
	}()
	if err := FirefoxSetUpstreamProxy("socks5://user:secret@" + ln.Addr().String()); err != nil {
		t.Fatal(err)
	}
	r, err := FirefoxFetch("GET", "http://example.test/", "{}", nil, 5)
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Body) != "ok" {
		t.Fatal("wrong body")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
func TestLocalDNSModeResolvesDestinationThroughProxy(t *testing.T) {
	resetFirefoxTestState(t)
	doh := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var q dnsmessage.Message
		if err := q.Unpack(b); err != nil {
			t.Error(err)
			return
		}
		h := dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: q.Questions[0].Type, Class: dnsmessage.ClassINET, TTL: 60}
		m := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Questions: q.Questions}
		if h.Type == dnsmessage.TypeA {
			m.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 7}}}}
		}
		data, _ := m.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(data)
	}))
	defer doh.Close()
	dohURL, _ := url.Parse(doh.URL)
	targetSeen := make(chan string, 2)
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			t.Error("expected CONNECT")
			return
		}
		if r.Host == dohURL.Host {
			remote, err := net.Dial("tcp", r.Host)
			if err != nil {
				t.Error(err)
				return
			}
			c, b, err := w.(http.Hijacker).Hijack()
			if err != nil {
				remote.Close()
				t.Error(err)
				return
			}
			b.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			b.Flush()
			go func() { defer c.Close(); defer remote.Close(); go io.Copy(remote, b); io.Copy(c, remote) }()
			return
		}
		targetSeen <- r.Host
		c, b, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		b.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		b.Flush()
		request, err := http.ReadRequest(b.Reader)
		if err != nil {
			t.Error(err)
			return
		}
		if request.Host != "example.test" {
			t.Errorf("origin Host = %q", request.Host)
		}
		b.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		b.Flush()
	}))
	defer proxySrv.Close()
	if err := FirefoxSetUpstreamProxy(proxySrv.URL); err != nil {
		t.Fatal(err)
	}
	FirefoxSetDoH(doh.URL)
	if err := FirefoxSetProxyDNSMode("local"); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(doh.Certificate())
	ffDohClient.CloseIdleConnections()
	ffDohClient = ffNewDoHClientWithRoots(roots)
	defer ffDohClient.CloseIdleConnections()
	r, err := FirefoxFetch("GET", "http://example.test/path", "{}", nil, 5)
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Body) != "ok" {
		t.Fatal("wrong body")
	}
	select {
	case target := <-targetSeen:
		if target != "203.0.113.7:80" {
			t.Fatalf("proxy target %s", target)
		}
	case <-time.After(time.Second):
		t.Fatal("destination was not tunneled")
	}
}

func TestRedirectPolicy(t *testing.T) {
	resetFirefoxTestState(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	r, err := FirefoxFetch("GET", srv.URL, "{}", nil, 3)
	if err != nil || r.StatusCode != 302 {
		t.Fatalf("default redirect %v %v", r, err)
	}
	FirefoxSetFollowRedirects(true)
	r, err = FirefoxFetch("GET", srv.URL, "{}", nil, 3)
	if err != nil || r.StatusCode != 200 || string(r.Body) != "ok" {
		t.Fatalf("follow redirect %v %v", r, err)
	}
	policy := ffRedirectPolicy(true)
	from, _ := http.NewRequest("GET", "https://example.com", nil)
	to, _ := http.NewRequest("GET", "http://example.com", nil)
	if err := policy(to, []*http.Request{from}); err == nil {
		t.Fatal("HTTPS downgrade accepted")
	}
}

func TestHeaderJSONTypes(t *testing.T) {
	resetFirefoxTestState(t)
	for _, v := range []string{`null`, `{"Header":123}`, `{"Host":["one"]}`, `{"Header":[1]}`} {
		if _, err := FirefoxFetch("GET", "http://127.0.0.1:1", v, nil, 2); err == nil || !strings.Contains(err.Error(), "header") {
			t.Fatalf("invalid header JSON %s: %v", v, err)
		}
	}
}

func TestDoHSlowAAAAKeepsSuccessfulA(t *testing.T) {
	resetFirefoxTestState(t)
	sawCancel := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q dnsmessage.Message
		payload, err := io.ReadAll(r.Body)
		if err != nil || q.Unpack(payload) != nil {
			return
		}
		if q.Questions[0].Type == dnsmessage.TypeAAAA {
			<-r.Context().Done()
			close(sawCancel)
			return
		}
		reply := dnsmessage.Message{
			Header: dnsmessage.Header{Response: true}, Questions: q.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.AResource{A: [4]byte{203, 0, 113, 7}},
			}},
		}
		b, _ := reply.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(b)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, ffNetworkSnapshotKey{}, ffNetworkSnapshot{dohClient: srv.Client()})
	conn, err := ffDialDoH(ctx, func(ctx context.Context, kind dnsmessage.Type) ([]net.IP, error) {
		return ffResolveViaDoHType(ctx, srv.URL, "example.com", kind)
	}, func(ctx context.Context, ip string) (net.Conn, error) {
		if ip != "203.0.113.7" {
			return nil, fmt.Errorf("unexpected address %s", ip)
		}
		a, b := net.Pipe()
		b.Close()
		return a, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	select {
	case <-sawCancel:
	case <-time.After(time.Second):
		t.Fatal("slow DNS request not cancelled")
	}
}

func TestAutoHTTPNegotiation(t *testing.T) {
	if u := os.Getenv("FF_AUTO_TEST_URL"); u != "" {
		response, err := FirefoxFetchAuto("POST", u, `{"Content-Type":"text/plain"}`, []byte("payload"), 5)
		if err != nil || response.StatusCode != 200 || string(response.Body) != os.Getenv("FF_AUTO_EXPECTED") {
			t.Fatalf("auto response: %#v, error %v", response, err)
		}
		FirefoxSetFollowRedirects(true)
		response, err = FirefoxFetchAuto("POST", u+"/redirect", `{"Content-Type":"text/plain"}`, []byte("payload"), 5)
		if err != nil || response.StatusCode != 200 || string(response.Body) != os.Getenv("FF_AUTO_EXPECTED") {
			t.Fatalf("auto redirect: %#v, error %v", response, err)
		}
		return
	}
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2_%v", h2), func(t *testing.T) {
			var count atomic.Int32
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				b, err := io.ReadAll(r.Body)
				if err != nil || r.Method != "POST" || string(b) != "payload" {
					t.Errorf("invalid request %s %q %v", r.Method, b, err)
				}
				if r.URL.Path == "/redirect" {
					http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
					return
				}
				fmt.Fprint(w, r.Proto)
			}))
			srv.EnableHTTP2 = h2
			srv.StartTLS()
			defer srv.Close()
			file := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			expected := "HTTP/1.1"
			if h2 {
				expected = "HTTP/2.0"
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestAutoHTTPNegotiation$")
			cmd.Env = append(os.Environ(), "FF_AUTO_TEST_URL="+srv.URL, "FF_AUTO_EXPECTED="+expected, "SSL_CERT_FILE="+file, "SSL_CERT_DIR="+t.TempDir())
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("subprocess: %v\n%s", err, out)
			}
			if n := count.Load(); n != 3 {
				t.Fatalf("sent %d requests; expected one initial and two redirect requests", n)
			}
		})
	}
}

func TestAutoDoesNotFallbackOnUntrustedTLS(t *testing.T) {
	resetFirefoxTestState(t)
	var count atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1) }))
	defer srv.Close()
	_, err := FirefoxFetchAuto("POST", srv.URL, "{}", []byte("payload"), 3)
	if err == nil {
		t.Fatal("untrusted server accepted")
	}
	if count.Load() != 0 {
		t.Fatal("request sent to untrusted server")
	}
}

func TestDoHLateIPv6SurvivesFailedIPv4(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	aStarted := make(chan struct{})
	lookup := func(ctx context.Context, kind dnsmessage.Type) ([]net.IP, error) {
		if kind == dnsmessage.TypeA {
			return []net.IP{net.ParseIP("192.0.2.1")}, nil
		}
		select {
		case <-aStarted:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		select {
		case <-time.After(80 * time.Millisecond):
			return []net.IP{net.ParseIP("2001:db8::1")}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	dial := func(ctx context.Context, ip string) (net.Conn, error) {
		if ip == "192.0.2.1" {
			close(aStarted)
			return nil, fmt.Errorf("IPv4 unavailable")
		}
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	c, err := ffDialDoH(ctx, lookup, dial)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestDoHRaceDoesNotWaitForStalledFamily(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stopped := make(chan struct{})
	lookup := func(ctx context.Context, kind dnsmessage.Type) ([]net.IP, error) {
		if kind == dnsmessage.TypeAAAA {
			<-ctx.Done()
			close(stopped)
			return nil, ctx.Err()
		}
		return []net.IP{net.ParseIP("192.0.2.1")}, nil
	}
	dial := func(context.Context, string) (net.Conn, error) { a, b := net.Pipe(); b.Close(); return a, nil }
	c, err := ffDialDoH(ctx, lookup, dial)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("DNS lookup did not cancel")
	}
}

func TestDoHRaceCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	lookup := func(ctx context.Context, kind dnsmessage.Type) ([]net.IP, error) { <-ctx.Done(); return nil, ctx.Err() }
	_, err := ffDialDoH(ctx, lookup, func(context.Context, string) (net.Conn, error) {
		t.Error("unexpected dial")
		return nil, fmt.Errorf("unexpected")
	})
	if err != context.DeadlineExceeded {
		t.Fatalf("got %v", err)
	}
}

func TestConfigurableResponseLimit(t *testing.T) {
	resetFirefoxTestState(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "12345") }))
	defer srv.Close()
	if err := FirefoxSetMaxResponseBytes(4); err != nil {
		t.Fatal(err)
	}
	if _, err := FirefoxFetch("GET", srv.URL, "", nil, 2); err == nil || !strings.Contains(err.Error(), "exceeds 4 bytes") {
		t.Fatalf("expected size limit, got %v", err)
	}
	if err := FirefoxSetMaxResponseBytes(5); err != nil {
		t.Fatal(err)
	}
	if _, err := FirefoxFetch("GET", srv.URL, "", nil, 2); err != nil {
		t.Fatal(err)
	}
	if err := FirefoxSetMaxResponseBytes(0); err == nil {
		t.Fatal("zero limit accepted")
	}
}

func TestDoHTLSNegotiation(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2_%v", h2), func(t *testing.T) {
			resetFirefoxTestState(t)
			var mu sync.Mutex
			var offers [][]string
			var served atomic.Int32
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				served.Add(1)
				if (r.ProtoMajor == 2) != h2 {
					t.Errorf("protocol %s", r.Proto)
				}
				fmt.Fprint(w, "ok")
			}))
			srv.EnableHTTP2 = h2
			srv.TLS = &tls.Config{GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
				mu.Lock()
				defer mu.Unlock()
				offers = append(offers, append([]string(nil), info.SupportedProtos...))
				if len(info.SupportedCurves) == 0 || uint16(info.SupportedCurves[0]) != uint16(ffCurveX25519MLKEM768) {
					t.Errorf("unexpected curves %v", info.SupportedCurves)
				}
				return nil, nil
			}}
			srv.StartTLS()
			defer srv.Close()
			roots := x509.NewCertPool()
			roots.AddCert(srv.Certificate())
			client := ffNewDoHClientWithRoots(roots)
			defer client.CloseIdleConnections()
			resp, err := client.Post(srv.URL, "application/dns-message", strings.NewReader("payload"))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if served.Load() != 1 {
				t.Fatalf("requests = %d", served.Load())
			}
			mu.Lock()
			defer mu.Unlock()
			if len(offers) == 0 || strings.Join(offers[0], ",") != "h2,http/1.1" {
				t.Fatalf("offers: %v", offers)
			}
			if !h2 && (len(offers) < 2 || strings.Join(offers[len(offers)-1], ",") != "http/1.1") {
				t.Fatalf("no h1 fallback: %v", offers)
			}
		})
	}
}

func TestDoHLateIPv4SurvivesFailedIPv6(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	firstStarted := make(chan struct{})
	lookup := func(ctx context.Context, kind dnsmessage.Type) ([]net.IP, error) {
		if kind == dnsmessage.TypeAAAA {
			return []net.IP{net.ParseIP("2001:db8::1")}, nil
		}
		select {
		case <-firstStarted:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		select {
		case <-time.After(80 * time.Millisecond):
			return []net.IP{net.ParseIP("192.0.2.1")}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	dial := func(ctx context.Context, ip string) (net.Conn, error) {
		if ip == "2001:db8::1" {
			close(firstStarted)
			return nil, fmt.Errorf("IPv6 unavailable")
		}
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	conn, err := ffDialDoH(ctx, lookup, dial)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestDoHRejectsUntrustedTLS(t *testing.T) {
	resetFirefoxTestState(t)
	var count atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1) }))
	defer srv.Close()
	client := ffNewDoHClient()
	defer client.CloseIdleConnections()
	_, err := client.Post(srv.URL, "application/dns-message", strings.NewReader("secret"))
	if err == nil {
		t.Fatal("untrusted DoH certificate accepted")
	}
	if count.Load() != 0 {
		t.Fatal("DoH request sent to untrusted server")
	}
}

func TestInvalidProxyDoesNotExposeCredentials(t *testing.T) {
	resetFirefoxTestState(t)
	err := FirefoxSetUpstreamProxy("http://user:topsecret%zz@proxy.example")
	if err == nil {
		t.Fatal("invalid proxy URL accepted")
	}
	if strings.Contains(err.Error(), "topsecret") {
		t.Fatalf("credential leaked: %v", err)
	}
}

type testFirefoxNetwork struct {
	ip        string
	protected atomic.Int32
	lookups   atomic.Int32
}

func (n *testFirefoxNetwork) Protect(fd int32) error { n.protected.Add(1); return nil }
func (n *testFirefoxNetwork) LookupIP(host string) (string, error) {
	n.lookups.Add(1)
	return `["` + n.ip + `"]`, nil
}

func TestIsolatedClientNoCookiesOrRedirects(t *testing.T) {
	resetFirefoxTestState(t)
	var cookieSeen atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" {
			cookieSeen.Store(true)
		}
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/next", http.StatusFound)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "secret", Value: "value", Path: "/"})
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	client, err := FirefoxNewClient("", "", nil, false, true, false, 1024, 3000)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, path := range []string{"/", "/", "/redirect"} {
		req, err := client.NewRequest("GET", srv.URL+path, "{}", nil, 3000)
		if err != nil {
			t.Fatal(err)
		}
		got, err := req.Execute()
		if err != nil {
			t.Fatal(err)
		}
		if path == "/redirect" && got.StatusCode != 302 {
			t.Fatalf("redirect was followed: %d", got.StatusCode)
		}
		if got.Protocol != "HTTP/1.1" {
			t.Fatalf("unexpected protocol %s", got.Protocol)
		}
	}
	if cookieSeen.Load() {
		t.Fatal("client stored or sent cookies")
	}
}

func TestIsolatedClientsResolveAndProtect(t *testing.T) {
	resetFirefoxTestState(t)
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "one") }))
	defer a.Close()
	u, _ := url.Parse(a.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	b, err := net.Listen("tcp", net.JoinHostPort("127.0.0.2", port))
	if err != nil {
		t.Skipf("second loopback unavailable: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "two") })}
	go srv.Serve(b)
	defer srv.Close()
	n1, n2 := &testFirefoxNetwork{ip: "127.0.0.1"}, &testFirefoxNetwork{ip: "127.0.0.2"}
	c1, err := FirefoxNewClient("", "", n1, true, true, false, 1024, 3000)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := FirefoxNewClient("", "", n2, true, true, false, 1024, 3000)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 20; i++ {
		for j, c := range []*FirefoxClient{c1, c2} {
			wg.Add(1)
			go func(j int, c *FirefoxClient) {
				defer wg.Done()
				r, e := c.NewRequest("GET", "http://isolated.example:"+port, "{}", nil, 3000)
				if e != nil {
					errs <- e
					return
				}
				v, e := r.Execute()
				if e != nil {
					errs <- e
					return
				}
				want := []string{"one", "two"}[j]
				if string(v.Body) != want {
					errs <- fmt.Errorf("got %s want %s", v.Body, want)
				}
			}(j, c)
		}
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if n1.protected.Load() == 0 || n2.protected.Load() == 0 || n1.lookups.Load() == 0 || n2.lookups.Load() == 0 {
		t.Fatal("platform callbacks were not used")
	}
}

func TestIsolatedClientValidationAndCancellation(t *testing.T) {
	if _, err := FirefoxNewClient("bad://proxy", "", nil, false, true, false, 1024, 3000); err == nil {
		t.Fatal("invalid proxy accepted")
	}
	if _, err := FirefoxNewClient("", "http://insecure/dns", nil, false, true, false, 1024, 3000); err == nil {
		t.Fatal("insecure DoH accepted")
	}
	if _, err := FirefoxNewClient("", "", nil, true, true, false, 1024, 3000); err == nil {
		t.Fatal("missing protector accepted")
	}
	c, err := FirefoxNewClient("", "", nil, false, true, false, 1024, 3000)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r, err := c.NewRequest("GET", "http://127.0.0.1/", "{}", nil, 3000)
	if err != nil {
		t.Fatal(err)
	}
	r.Cancel()
	if _, err = r.Execute(); err == nil {
		t.Fatal("cancelled request succeeded")
	}
	if _, err = r.Execute(); err == nil {
		t.Fatal("single-use request executed twice")
	}
	if _, err = c.NewRequest("GET", "http://127.0.0.1/", "{}", nil, 0); err == nil {
		t.Fatal("invalid timeout accepted")
	}
}

func TestIsolatedUninitializedValues(t *testing.T) {
	var client FirefoxClient
	client.Close()
	if _, err := client.NewRequest("GET", "http://x", "{}", nil, 1); err == nil {
		t.Fatal("zero client accepted")
	}
	var request FirefoxRequest
	request.Cancel()
	if _, err := request.Execute(); err == nil {
		t.Fatal("zero request accepted")
	}
}

type testFailProtection struct{ testFirefoxNetwork }

func (n *testFailProtection) Protect(int32) error { return fmt.Errorf("refused") }
func TestIsolatedProtectionFailsClosed(t *testing.T) {
	n := &testFailProtection{testFirefoxNetwork{ip: "127.0.0.1"}}
	c, err := FirefoxNewClient("", "", n, true, true, false, 1024, 3000)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r, err := c.NewRequest("GET", "http://isolated.example:12345", "{}", nil, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Execute(); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("expected protection error, got %v", err)
	}
}

func TestIsolatedProxyHostnameUsesPlatformDNS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		req, e := http.ReadRequest(br)
		if e != nil {
			done <- e
			return
		}
		if req.Method != "CONNECT" || req.Host != "example.org:443" {
			done <- fmt.Errorf("unexpected CONNECT %s %s", req.Method, req.Host)
			return
		}
		_, e = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		done <- e
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	n := &testFirefoxNetwork{ip: "127.0.0.1"}
	cfg := ffNetworkSnapshot{proxy: "http://proxy.test:" + port, network: n, protector: n, requireProtection: true}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), ffNetworkSnapshotKey{}, cfg), 3*time.Second)
	defer cancel()
	conn, err := ffDialWithOptionalProxy(ctx, "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if n.lookups.Load() == 0 || n.protected.Load() == 0 {
		t.Fatal("proxy did not use platform callbacks")
	}
}

type slowTestNetwork struct{}

func (slowTestNetwork) Protect(int32) error { return nil }
func (slowTestNetwork) LookupIP(string) (string, error) {
	time.Sleep(250 * time.Millisecond)
	return `["127.0.0.1"]`, nil
}
func TestIsolatedConnectTimeoutIncludesPlatformDNS(t *testing.T) {
	c, err := FirefoxNewClient("", "", slowTestNetwork{}, true, true, false, 1024, 40)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r, err := c.NewRequest("GET", "http://slow.example/", "{}", nil, 3000)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = r.Execute()
	if err == nil {
		t.Fatal("expected timeout")
	}
	if time.Since(start) > time.Second {
		t.Fatal("connect timeout did not bound DNS")
	}
}

func TestIsolatedClientNegotiatesHTTP2OrHTTP1(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("h2=%v", h2), func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
			server.EnableHTTP2 = h2
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			cfg := ffNetworkSnapshot{allowPrivate: true, roots: roots, connectTimeout: 3 * time.Second, dohClient: ffNewDoHClient()}
			h1c := ffBuildClient(cfg, nil, false, utls.NewLRUClientSessionCache(4))
			h2c := ffBuildClient(cfg, nil, true, utls.NewLRUClientSessionCache(4))
			c := &FirefoxClient{client: &http.Client{Transport: &ffAutoTransport{h1: h1c.Transport, h2: h2c.Transport}, CheckRedirect: ffRedirectPolicy(false)}, dohClient: cfg.dohClient, maxBody: 1024}
			defer c.Close()
			req, err := c.NewRequest("GET", server.URL, "{}", nil, 3000)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := req.Execute()
			if err != nil {
				t.Fatal(err)
			}
			want := "HTTP/1.1"
			if h2 {
				want = "HTTP/2.0"
			}
			if resp.Protocol != want || string(resp.Body) != "ok" {
				t.Fatalf("got %s %s", resp.Protocol, resp.Body)
			}
		})
	}
}

type blockedTestNetwork struct {
	entered chan struct{}
	release chan struct{}
}

func (*blockedTestNetwork) Protect(int32) error { return nil }
func (n *blockedTestNetwork) LookupIP(string) (string, error) {
	n.entered <- struct{}{}
	<-n.release
	return `["127.0.0.1"]`, nil
}
func TestPlatformDNSLimitsUninterruptibleCallbacks(t *testing.T) {
	n := &blockedTestNetwork{entered: make(chan struct{}, 8), release: make(chan struct{})}
	defer close(n.release)
	cfg := ffNetworkSnapshot{network: n, lookupSlots: make(chan struct{}, 2)}
	ctx := context.WithValue(context.Background(), ffNetworkSnapshotKey{}, cfg)
	for i := 0; i < 2; i++ {
		ctxShort, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
		_, err := ffLookupPlatform(ctxShort, n, "test.example")
		cancel()
		if err == nil {
			t.Fatal("expected cancellation")
		}
	}
	for i := 0; i < 2; i++ {
		<-n.entered
	}
	ctxShort, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := ffLookupPlatform(ctxShort, n, "test.example"); err == nil {
		t.Fatal("expected bounded wait")
	}
	select {
	case <-n.entered:
		t.Fatal("exceeded callback limit")
	default:
	}
}
