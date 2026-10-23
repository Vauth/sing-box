package http

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	E "github.com/sagernet/sing/common/exceptions"
)

// BearerTokenProvider belongs to one credential lifetime. Clearing the libbox
// token revokes this provider permanently; a later login gets a new provider.
// Only explicitly enrolled HTTP outbounds retain a reference to it.
type BearerTokenProvider struct {
	token atomic.Pointer[string]
}

var bearerTokens struct {
	sync.Mutex
	current *BearerTokenProvider
}

// SetDynamicBearerToken updates enrolled outbounds without resetting transports.
// An empty token revokes existing providers and prevents stale-header fallback.
// The caller must serialize account/session changes and stop obsolete refreshes.
func SetDynamicBearerToken(token string) {
	bearerTokens.Lock()
	defer bearerTokens.Unlock()
	if token == "" {
		if bearerTokens.current != nil {
			bearerTokens.current.token.Store(nil)
			bearerTokens.current = nil
		}
		return
	}
	if bearerTokens.current == nil {
		bearerTokens.current = new(BearerTokenProvider)
	}
	bearerTokens.current.token.Store(&token)
}

// AcquireBearerTokenProvider is called only for HTTP proxy outbounds, not for
// general HTTP clients. An explicit false always opts out. For older FoxyVPN
// configs, an exact match with the installed Proxy-Authorization bearer token
// enrolls the outbound; upstream proxies without that header remain untouched.
func AcquireBearerTokenProvider(headers http.Header, enabled *bool) (*BearerTokenProvider, error) {
	if enabled != nil && !*enabled {
		return nil, nil
	}
	bearerTokens.Lock()
	defer bearerTokens.Unlock()
	provider := bearerTokens.current
	if enabled != nil && *enabled {
		if provider == nil || provider.token.Load() == nil {
			return nil, E.New("install a bearer token before creating a dynamic HTTP outbound")
		}
		return provider, nil
	}
	if provider == nil {
		return nil, nil
	}
	token := provider.token.Load()
	values := headers.Values("Proxy-Authorization")
	if token != nil && len(values) == 1 {
		scheme, value, found := strings.Cut(values[0], " ")
		if found && strings.EqualFold(scheme, "Bearer") && value == *token {
			return provider, nil
		}
	}
	return nil, nil
}
