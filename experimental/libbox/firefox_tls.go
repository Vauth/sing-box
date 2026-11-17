package libbox

import (
	"context"
	"crypto/x509"
	"net"

	utls "github.com/metacubex/utls"
	"github.com/metacubex/utls/dicttls"
)

// ffCurveX25519MLKEM768 is the IANA TLS ID for X25519MLKEM768 (0x11ec).
const ffCurveX25519MLKEM768 utls.CurveID = 0x11ec

// ffFirefoxHelloSpec is adapted from arman-vpn-client core/internal/firefoxtls
// (commit 492dd7f389c539790cde3d07167535d28788a0d0, GPL-3.0).
// It defines a version-pinned Firefox 158-style ClientHello.
// The full browser fingerprint depends on more than the ClientHello and must
// be verified separately against real browser captures.
func ffFirefoxHelloSpec(alpn ...string) *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []uint8{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				ffCurveX25519MLKEM768, utls.X25519, utls.CurveP256, utls.CurveP384, utls.CurveP521,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: alpn},
			&utls.StatusRequestExtension{},
			&utls.FakeDelegatedCredentialsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.ECDSAWithP384AndSHA384, utls.ECDSAWithP521AndSHA512, utls.ECDSAWithSHA1,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: ffCurveX25519MLKEM768}, {Group: utls.X25519}, {Group: utls.CurveP256},
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.ECDSAWithP384AndSHA384, utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256, utls.PSSWithSHA384, utls.PSSWithSHA512,
				utls.PKCS1WithSHA256, utls.PKCS1WithSHA384, utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1, utls.PKCS1WithSHA1,
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.FakeRecordSizeLimitExtension{Limit: 0x4001},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionZlib, utls.CertCompressionBrotli, utls.CertCompressionZstd,
			}},
			&utls.GREASEEncryptedClientHelloExtension{
				CandidateCipherSuites: []utls.HPKESymmetricCipherSuite{
					{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_AES_128_GCM},
					{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_CHACHA20_POLY1305},
				},
				CandidatePayloadLens: []uint16{224},
			},
			&utls.UtlsPreSharedKeyExtension{},
		},
	}
}

// ffHandshakeTLS executes the TLS handshake with desktop Firefox ClientHello.
// It guarantees the socket is closed if the handshake fails.
func ffHandshakeTLS(ctx context.Context, raw net.Conn, name string, roots *x509.CertPool, cache utls.ClientSessionCache, alpn ...string) (*utls.UConn, error) {
	conn := utls.UClient(raw, &utls.Config{
		RootCAs:            roots,
		ServerName:         name,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, utls.HelloCustom)
	if err := conn.ApplyPreset(ffFirefoxHelloSpec(alpn...)); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}
