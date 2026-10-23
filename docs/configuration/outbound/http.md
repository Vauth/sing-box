`http` outbound is a HTTP CONNECT proxy client.

### Structure

```json
{
  "type": "http",
  "tag": "http-out",
  
  "server": "127.0.0.1",
  "server_port": 1080,
  "username": "sekai",
  "password": "admin",
  "path": "",
  "headers": {},
  "version": 0,
  "disable_version_fallback": false,
  "tls": {},

  ... // HTTP2 Fields / QUIC Fields
  ... // Dial Fields
}
```

### Fields

#### server

==Required==

The server address.

#### server_port

==Required==

The server port.

#### username

Basic authorization username.

#### password

Basic authorization password.

#### path

Path of HTTP request.

#### headers

Extra headers of HTTP request.

#### version

!!! question "Since sing-box 1.15.0"

HTTP version.

Available values: `1`, `2`, `3`.

`2` is used by default, or `1` if `path` or the `Host` header is set.

`path` and the `Host` header are only available for `1`.

When `3`, [HTTP2 Fields](#http2-fields) are replaced by [QUIC Fields](#quic-fields).

#### disable_version_fallback

!!! question "Since sing-box 1.15.0"

Disable automatic fallback to lower HTTP version.

#### dynamic_bearer_token (Foxy fork)

Enroll this HTTP proxy outbound in libbox bearer-token rotation. Call
`Libbox.setBearerToken(token)` before starting the service. Set this field to
`true` only on Guardian/Fastly outbounds and to `false` on upstream proxies.
Username/password authentication cannot be combined with enrollment.

When omitted, older FoxyVPN configurations remain compatible: enrollment occurs
only when the outbound's single `Proxy-Authorization: Bearer ...` header exactly
matches the token currently installed through libbox. General HTTP clients and
HTTP outbounds without that matching header are not enrolled.

Enrolled outbounds require TLS and HTTP/2 or HTTP/3. HTTP/3 may fall back to
HTTP/2 unless `disable_version_fallback` is true; HTTP/1.1 is never used.
Other outbounds keep their normal protocol and authentication behavior.

Rotation changes headers for new requests; it does not reauthenticate existing
streams or guarantee that the server will keep them alive. Clearing the token
with `Libbox.setBearerToken("")` permanently revokes the existing credential
provider. Subsequent requests fail instead of reusing the initial config header.
Install a new token and recreate the service after revocation. The Android app
must still serialize login/logout and cancel obsolete refresh operations; the
legacy setter cannot identify which session an asynchronous caller belongs to.

#### tls

TLS configuration, see [TLS](/configuration/shared/tls/#outbound).

### HTTP2 Fields

!!! question "Since sing-box 1.15.0"

When `version` is `2` (default).

See [HTTP2 Fields](/configuration/shared/http2/) for details.

### QUIC Fields

!!! question "Since sing-box 1.15.0"

When `version` is `3`.

See [QUIC Fields](/configuration/shared/quic/) for details.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
