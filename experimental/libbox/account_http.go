package libbox

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"syscall"
	"time"
)

type AccountHTTPNetwork interface {
	Resolve(host string) (string, error)
	BindSocket(fd int32) error
}

type AccountHTTPClient struct {
	client    *http.Client
	transport *http.Transport
	ctx       context.Context
	cancel    context.CancelFunc
}

type AccountHTTPRequest struct {
	client   *http.Client
	request  *http.Request
	cancel   context.CancelFunc
	mu       sync.Mutex
	executed bool
}

type AccountHTTPResponse struct {
	Status      int32
	HeadersJSON string
	Content     []byte
	Protocol    string
	TLSVersion  string
}

func NewAccountHTTPClient(rootsPEM string, network AccountHTTPNetwork) (*AccountHTTPClient, error) {
	if network == nil {
		return nil, errors.New("account network is required")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(rootsPEM)) {
		return nil, errors.New("account trust store is empty")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	transport.ForceAttemptHTTP2 = true
	transport.MaxResponseHeaderBytes = 64 << 10
	resolveSlot := make(chan struct{}, 1)
	transport.DialContext = func(ctx context.Context, kind, address string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("invalid account address")
		}
		addresses, err := resolveAccountAddresses(ctx, network, resolveSlot, host)
		if err != nil {
			return nil, err
		}
		dialer := net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		dialer.Control = func(_, _ string, raw syscall.RawConn) error {
			var bindErr error
			err := raw.Control(func(fd uintptr) { bindErr = network.BindSocket(int32(fd)) })
			if err != nil {
				return err
			}
			return bindErr
		}
		return dialAccountAddresses(ctx, kind, port, addresses, dialer.DialContext)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &AccountHTTPClient{client: &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, transport: transport, ctx: ctx, cancel: cancel}, nil
}

func resolveAccountAddresses(ctx context.Context, network AccountHTTPNetwork, slot chan struct{}, host string) ([]net.IP, error) {
	select {
	case slot <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	type result struct {
		encoded string
		err     error
	}
	resolved := make(chan result, 1)
	go func() {
		defer func() { <-slot }()
		encoded, err := network.Resolve(host)
		resolved <- result{encoded, err}
	}()
	var encoded string
	select {
	case value := <-resolved:
		if value.err != nil {
			return nil, errors.New("account DNS lookup failed")
		}
		encoded = value.encoded
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var values []string
	if len(encoded) > 64<<10 || json.Unmarshal([]byte(encoded), &values) != nil {
		return nil, errors.New("invalid account DNS response")
	}
	addresses := make([]net.IP, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		ip := net.ParseIP(value)
		if ip == nil || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		addresses = append(addresses, ip)
	}
	if len(addresses) == 0 {
		return nil, errors.New("account DNS returned no addresses")
	}
	return addresses, nil
}

func dialAccountAddresses(ctx context.Context, kind, port string, addresses []net.IP, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	if len(addresses) == 0 {
		return nil, errors.New("account DNS returned no addresses")
	}
	primary := make([]net.IP, 0, len(addresses))
	fallback := make([]net.IP, 0, len(addresses))
	firstIPv4 := addresses[0].To4() != nil
	for _, address := range addresses {
		ipv4 := address.To4() != nil
		if (kind == "tcp4" && !ipv4) || (kind == "tcp6" && ipv4) {
			continue
		}
		if ipv4 == firstIPv4 {
			primary = append(primary, address)
		} else {
			fallback = append(fallback, address)
		}
	}
	if len(primary) == 0 {
		primary, fallback = fallback, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result)
	start := func(candidates []net.IP) {
		go func() {
			var conn net.Conn
			var err error
			for index, address := range candidates {
				if ctx.Err() != nil {
					err = ctx.Err()
					break
				}
				attemptCtx := ctx
				stop := func() {}
				if deadline, ok := ctx.Deadline(); ok {
					budget := time.Until(deadline) / time.Duration(len(candidates)-index)
					attemptCtx, stop = context.WithTimeout(ctx, budget)
				}
				conn, err = dial(attemptCtx, kind, net.JoinHostPort(address.String(), port))
				stop()
				if err == nil {
					break
				}
			}
			if conn == nil && err == nil {
				err = errors.New("account connection failed")
			}
			select {
			case results <- result{conn, err}:
			case <-ctx.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}()
	}
	start(primary)
	pending := 1
	var fallbackTimer <-chan time.Time
	if len(fallback) > 0 {
		timer := time.NewTimer(300 * time.Millisecond)
		defer timer.Stop()
		fallbackTimer = timer.C
	}
	for pending > 0 {
		select {
		case value := <-results:
			pending--
			if value.err == nil {
				if err := ctx.Err(); err != nil {
					value.conn.Close()
					return nil, err
				}
				return value.conn, nil
			}
			if fallbackTimer != nil {
				start(fallback)
				pending++
				fallbackTimer = nil
			}
		case <-fallbackTimer:
			start(fallback)
			pending++
			fallbackTimer = nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("account connection failed")
}

func (c *AccountHTTPClient) NewRequest(method, link, headersJSON string, content []byte, timeoutMillis int64) (*AccountHTTPRequest, error) {
	target, err := url.Parse(link)
	if err != nil || target.Scheme != "https" || target.User != nil || target.Fragment != "" || (target.Port() != "" && target.Port() != "443") {
		return nil, errors.New("invalid account URL")
	}
	switch target.Hostname() {
	case "api.accounts.firefox.com", "accounts.firefox.com", "vpn.mozilla.org", "product-details.mozilla.org":
	default:
		return nil, errors.New("untrusted account host")
	}
	if method != http.MethodGet && method != http.MethodPost {
		return nil, errors.New("unsupported account method")
	}
	if len(content) > 1<<20 || len(headersJSON) > 64<<10 {
		return nil, errors.New("account request is too large")
	}
	if timeoutMillis < 1 || timeoutMillis > 120000 {
		return nil, errors.New("invalid account timeout")
	}
	var headers http.Header
	if json.Unmarshal([]byte(headersJSON), &headers) != nil {
		return nil, errors.New("invalid account headers")
	}
	ctx, cancel := context.WithTimeout(c.ctx, time.Duration(timeoutMillis)*time.Millisecond)
	req, err := http.NewRequestWithContext(ctx, method, link, bytes.NewReader(content))
	if err != nil {
		cancel()
		return nil, errors.New("invalid account request")
	}
	req.Header = headers
	req.Header.Del("Host")
	req.Header.Del("Content-Length")
	return &AccountHTTPRequest{client: c.client, request: req, cancel: cancel}, nil
}

func (r *AccountHTTPRequest) Cancel() { r.cancel() }

func (r *AccountHTTPRequest) Execute() (*AccountHTTPResponse, error) {
	r.mu.Lock()
	if r.executed {
		r.mu.Unlock()
		return nil, errors.New("account request already executed")
	}
	r.executed = true
	r.mu.Unlock()
	defer r.cancel()
	response, err := r.client.Do(r.request)
	if err != nil {
		if r.request.Context().Err() != nil {
			return nil, r.request.Context().Err()
		}
		return nil, errors.New("account HTTPS exchange failed")
	}
	defer response.Body.Close()
	const maxBody = 4 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil {
		return nil, errors.New("account response could not be read")
	}
	if len(body) > maxBody {
		return nil, errors.New("account response is too large")
	}
	headers, err := json.Marshal(response.Header)
	if err != nil {
		return nil, errors.New("invalid account response headers")
	}
	result := &AccountHTTPResponse{Status: int32(response.StatusCode), HeadersJSON: string(headers), Content: body, Protocol: response.Proto}
	if response.TLS != nil {
		result.TLSVersion = tls.VersionName(response.TLS.Version)
	}
	return result, nil
}

func (c *AccountHTTPClient) Close() {
	c.cancel()
	c.transport.CloseIdleConnections()
}
