package pulseclient

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"
)

const alpnProtocol = "pulse"

var (
	// ErrNilRootCAs is returned when WithRootCAs is given a nil pool.
	ErrNilRootCAs = errors.New("pulseclient: root CA pool must not be nil")
	// ErrInvalidSPKIPin is returned when an SPKI SHA-256 pin isn't 32 bytes.
	ErrInvalidSPKIPin = errors.New("pulseclient: SPKI SHA-256 pin must be exactly 32 bytes")
	// ErrInvalidTimeout is returned when a configured protocol wait is not positive.
	ErrInvalidTimeout = errors.New("pulseclient: timeout must be greater than zero")
	// ErrInvalidQueueCapacity is returned when the sig-first queue capacity is not positive.
	ErrInvalidQueueCapacity = errors.New("pulseclient: sig-first queue capacity must be greater than zero")
	// ErrConflictingTLSOptions is returned when custom trust or certificate
	// pinning is combined with the explicitly insecure local-development mode.
	ErrConflictingTLSOptions = errors.New("pulseclient: custom trust or SPKI pinning cannot be combined with insecure local-development TLS")
	// ErrInsecureTLSNonLoopback is returned when the local-development-only
	// insecure TLS option is used with a target outside the loopback interface.
	ErrInsecureTLSNonLoopback = errors.New("pulseclient: insecure local-development TLS requires a loopback target")
)

// InsecureTLSTargetError reports a non-loopback target rejected before dialing
// because WithInsecureTLSForLocalDevelopment was configured.
type InsecureTLSTargetError struct {
	Host string
}

func (e *InsecureTLSTargetError) Error() string {
	return fmt.Sprintf("pulseclient: insecure local-development TLS cannot dial non-loopback host %q", e.Host)
}

func (e *InsecureTLSTargetError) Unwrap() error { return ErrInsecureTLSNonLoopback }

type clientConfig struct {
	token            string
	rootCAs          *x509.CertPool
	serverName       string
	spkiPinSHA256    []byte
	insecureLocalTLS bool
	ackTimeout       time.Duration
	preambleTimeout  time.Duration
	sigQueueCapacity int
}

func defaultClientConfig() clientConfig {
	return clientConfig{
		ackTimeout:       AckTimeout,
		preambleTimeout:  PreambleTimeout,
		sigQueueCapacity: SigQueueLen,
	}
}

// Option configures Connect.
//
// Options are validated before any network connection is attempted.
type Option interface {
	apply(*clientConfig) error
}

type optionFunc func(*clientConfig) error

func (f optionFunc) apply(cfg *clientConfig) error { return f(cfg) }

// WithToken authenticates the first wire-v2 control message with token.
// Pulse tokens are bearer credentials and are sent only after TLS verification
// succeeds.
func WithToken(token string) Option {
	return optionFunc(func(cfg *clientConfig) error {
		cfg.token = token
		return nil
	})
}

// WithRootCAs replaces the system trust store with roots for this connection.
// The pool is cloned before use. To add a private CA while retaining public
// roots, start with x509.SystemCertPool, append the CA, and pass that pool here.
func WithRootCAs(roots *x509.CertPool) Option {
	return optionFunc(func(cfg *clientConfig) error {
		if roots == nil {
			return ErrNilRootCAs
		}
		cfg.rootCAs = roots.Clone()
		return nil
	})
}

// WithServerName overrides the DNS name used for certificate verification and
// SNI. By default Connect derives it from the target host. This is useful when
// dialing an IP address whose certificate is issued for a DNS name.
func WithServerName(name string) Option {
	return optionFunc(func(cfg *clientConfig) error {
		if name == "" {
			return errors.New("pulseclient: TLS server name must not be empty")
		}
		cfg.serverName = name
		return nil
	})
}

// WithSPKIPinSHA256 requires the leaf certificate's SubjectPublicKeyInfo to
// match the supplied SHA-256 digest in addition to normal chain and hostname
// verification. The pin is copied before use.
func WithSPKIPinSHA256(pin []byte) Option {
	pinCopy := append([]byte(nil), pin...)
	return optionFunc(func(cfg *clientConfig) error {
		if len(pinCopy) != sha256.Size {
			return ErrInvalidSPKIPin
		}
		cfg.spkiPinSHA256 = append([]byte(nil), pinCopy...)
		return nil
	})
}

// WithInsecureTLSForLocalDevelopment disables certificate and hostname
// verification. It is intentionally explicit and is rejected before dialing
// unless the target is localhost, 127.0.0.0/8, or ::1. Never use it with a
// production token or endpoint.
func WithInsecureTLSForLocalDevelopment() Option {
	return optionFunc(func(cfg *clientConfig) error {
		cfg.insecureLocalTLS = true
		return nil
	})
}

// WithAckTimeout changes the maximum duration of a control-message round trip.
// The default is AckTimeout. A caller context with an earlier deadline wins.
func WithAckTimeout(timeout time.Duration) Option {
	return optionFunc(func(cfg *clientConfig) error {
		if timeout <= 0 {
			return ErrInvalidTimeout
		}
		cfg.ackTimeout = timeout
		return nil
	})
}

// WithPreambleTimeout changes the maximum wait for the full-tx stream and its
// wire-v2 preamble. The default is PreambleTimeout. A caller context with an
// earlier deadline wins.
func WithPreambleTimeout(timeout time.Duration) Option {
	return optionFunc(func(cfg *clientConfig) error {
		if timeout <= 0 {
			return ErrInvalidTimeout
		}
		cfg.preambleTimeout = timeout
		return nil
	})
}

// WithSigQueueCapacity changes the bounded sig-first handoff queue capacity.
// The default is SigQueueLen. Use SigFirstSub.QueueStats to observe pressure.
func WithSigQueueCapacity(capacity int) Option {
	return optionFunc(func(cfg *clientConfig) error {
		if capacity <= 0 {
			return ErrInvalidQueueCapacity
		}
		cfg.sigQueueCapacity = capacity
		return nil
	})
}

func applyOptions(options []Option) (clientConfig, error) {
	cfg := defaultClientConfig()
	for _, option := range options {
		if option == nil {
			return clientConfig{}, errors.New("pulseclient: nil connection option")
		}
		if err := option.apply(&cfg); err != nil {
			return clientConfig{}, err
		}
	}
	if cfg.insecureLocalTLS && (cfg.rootCAs != nil || len(cfg.spkiPinSHA256) != 0) {
		return clientConfig{}, ErrConflictingTLSOptions
	}
	return cfg, nil
}

func newTLSConfig(addr string, cfg clientConfig) (*tls.Config, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("pulseclient: target must be host:port: %w", err)
	}
	if cfg.insecureLocalTLS && !isLoopbackHost(host) {
		return nil, &InsecureTLSTargetError{Host: host}
	}

	serverName := cfg.serverName
	if serverName == "" {
		serverName = host
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		RootCAs:            cfg.rootCAs,
		NextProtos:         []string{alpnProtocol},
		InsecureSkipVerify: cfg.insecureLocalTLS, // #nosec G402 -- explicit local-development-only option.
	}
	if len(cfg.spkiPinSHA256) != 0 {
		pin := append([]byte(nil), cfg.spkiPinSHA256...)
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("pulseclient: TLS peer sent no certificate")
			}
			got := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(got[:], pin) != 1 {
				return errors.New("pulseclient: TLS leaf SPKI pin mismatch")
			}
			return nil
		}
	}
	return tlsConfig, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
