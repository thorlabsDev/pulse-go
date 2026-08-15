package pulseclient

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

func TestDefaultTLSConfigVerifiesHostnameAndSystemRoots(t *testing.T) {
	cfg, err := applyOptions(nil)
	if err != nil {
		t.Fatalf("applyOptions: %v", err)
	}
	tlsConfig, err := newTLSConfig("pulse.example.com:443", cfg)
	if err != nil {
		t.Fatalf("newTLSConfig: %v", err)
	}
	if tlsConfig.InsecureSkipVerify {
		t.Fatal("default TLS config must verify certificates")
	}
	if tlsConfig.ServerName != "pulse.example.com" {
		t.Fatalf("ServerName = %q, want pulse.example.com", tlsConfig.ServerName)
	}
	if tlsConfig.RootCAs != nil {
		t.Fatal("nil RootCAs is required to use the system trust store")
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %#x, want TLS 1.3", tlsConfig.MinVersion)
	}
	if len(tlsConfig.NextProtos) != 1 || tlsConfig.NextProtos[0] != alpnProtocol {
		t.Fatalf("NextProtos = %q, want [%q]", tlsConfig.NextProtos, alpnProtocol)
	}
}

func TestTLSConfigSupportsHostnameOverrideAndCustomRoots(t *testing.T) {
	roots := x509.NewCertPool()
	cfg, err := applyOptions([]Option{
		WithServerName("pulse.internal.example"),
		WithRootCAs(roots),
	})
	if err != nil {
		t.Fatalf("applyOptions: %v", err)
	}
	tlsConfig, err := newTLSConfig("192.0.2.1:443", cfg)
	if err != nil {
		t.Fatalf("newTLSConfig: %v", err)
	}
	if tlsConfig.ServerName != "pulse.internal.example" {
		t.Fatalf("ServerName = %q", tlsConfig.ServerName)
	}
	if tlsConfig.RootCAs == nil {
		t.Fatal("custom roots were not installed")
	}
	if tlsConfig.RootCAs == roots {
		t.Fatal("WithRootCAs must clone the caller's mutable pool")
	}
}

func TestSPKIPinIsAdditionalVerification(t *testing.T) {
	spki := []byte("test subject public key info")
	pin := sha256.Sum256(spki)
	cfg, err := applyOptions([]Option{WithSPKIPinSHA256(pin[:])})
	if err != nil {
		t.Fatalf("applyOptions: %v", err)
	}
	tlsConfig, err := newTLSConfig("pulse.example.com:443", cfg)
	if err != nil {
		t.Fatalf("newTLSConfig: %v", err)
	}
	if tlsConfig.InsecureSkipVerify {
		t.Fatal("pinning must not disable normal chain and hostname verification")
	}
	if tlsConfig.VerifyConnection == nil {
		t.Fatal("pinning did not install VerifyConnection")
	}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{{RawSubjectPublicKeyInfo: spki}}}
	if err := tlsConfig.VerifyConnection(state); err != nil {
		t.Fatalf("matching pin: %v", err)
	}
	state.PeerCertificates[0].RawSubjectPublicKeyInfo = []byte("different key")
	if err := tlsConfig.VerifyConnection(state); err == nil {
		t.Fatal("mismatched pin must fail")
	}
}

func TestSPKIPinOptionCopiesCallerBytes(t *testing.T) {
	spki := []byte("spki")
	pin := sha256.Sum256(spki)
	option := WithSPKIPinSHA256(pin[:])
	pin[0] ^= 0xff
	cfg, err := applyOptions([]Option{option})
	if err != nil {
		t.Fatalf("applyOptions: %v", err)
	}
	want := sha256.Sum256(spki)
	if cfg.spkiPinSHA256[0] != want[0] {
		t.Fatal("pin option retained mutable caller storage")
	}
}

func TestInsecureTLSRequiresExplicitLocalDevelopmentOption(t *testing.T) {
	cfg, err := applyOptions([]Option{WithInsecureTLSForLocalDevelopment()})
	if err != nil {
		t.Fatalf("applyOptions: %v", err)
	}
	tlsConfig, err := newTLSConfig("localhost:8443", cfg)
	if err != nil {
		t.Fatalf("newTLSConfig: %v", err)
	}
	if !tlsConfig.InsecureSkipVerify {
		t.Fatal("explicit local-development option did not enable insecure mode")
	}
}

func TestInsecureTLSAcceptsOnlyLiteralLoopbackTargets(t *testing.T) {
	cfg, err := applyOptions([]Option{WithInsecureTLSForLocalDevelopment()})
	if err != nil {
		t.Fatalf("applyOptions: %v", err)
	}
	for _, target := range []string{
		"localhost:8443",
		"127.0.0.1:8443",
		"127.42.0.9:8443",
		"[::1]:8443",
	} {
		t.Run(target, func(t *testing.T) {
			tlsConfig, err := newTLSConfig(target, cfg)
			if err != nil {
				t.Fatalf("newTLSConfig(%q): %v", target, err)
			}
			if !tlsConfig.InsecureSkipVerify {
				t.Fatal("explicit local-development mode was not enabled")
			}
		})
	}
}

func TestInsecureTLSRejectsPublicOrArbitraryTargetsBeforeDial(t *testing.T) {
	for _, target := range []string{
		"pulse.example.com:443",
		"dev.internal:8443",
		"192.0.2.1:443",
		"0.0.0.0:8443",
		"[2001:db8::1]:443",
	} {
		t.Run(target, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := Connect(ctx, target, WithInsecureTLSForLocalDevelopment())
			if !errors.Is(err, ErrInsecureTLSNonLoopback) {
				t.Fatalf("Connect err = %v, want ErrInsecureTLSNonLoopback", err)
			}
			var targetErr *InsecureTLSTargetError
			if !errors.As(err, &targetErr) || targetErr.Host == "" {
				t.Fatalf("Connect err = %v, want typed target error", err)
			}
		})
	}
}

func TestConnectionOptionsRejectUnsafeOrUnboundedValues(t *testing.T) {
	pin := make([]byte, sha256.Size)
	tests := []struct {
		name    string
		options []Option
		want    error
	}{
		{"nil roots", []Option{WithRootCAs(nil)}, ErrNilRootCAs},
		{"short pin", []Option{WithSPKIPinSHA256([]byte{1})}, ErrInvalidSPKIPin},
		{"zero ack timeout", []Option{WithAckTimeout(0)}, ErrInvalidTimeout},
		{"negative preamble timeout", []Option{WithPreambleTimeout(-time.Second)}, ErrInvalidTimeout},
		{"zero queue", []Option{WithSigQueueCapacity(0)}, ErrInvalidQueueCapacity},
		{"pin with insecure", []Option{WithSPKIPinSHA256(pin), WithInsecureTLSForLocalDevelopment()}, ErrConflictingTLSOptions},
		{"roots with insecure", []Option{WithRootCAs(x509.NewCertPool()), WithInsecureTLSForLocalDevelopment()}, ErrConflictingTLSOptions},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := applyOptions(tt.options)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestConnectionOptionsCarryTokenBoundsAndQueueCapacity(t *testing.T) {
	cfg, err := applyOptions([]Option{
		WithToken("secret"),
		WithAckTimeout(2 * time.Second),
		WithPreambleTimeout(3 * time.Second),
		WithSigQueueCapacity(17),
	})
	if err != nil {
		t.Fatalf("applyOptions: %v", err)
	}
	if cfg.token != "secret" || cfg.ackTimeout != 2*time.Second || cfg.preambleTimeout != 3*time.Second || cfg.sigQueueCapacity != 17 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestTargetMustIncludePort(t *testing.T) {
	cfg, _ := applyOptions(nil)
	if _, err := newTLSConfig("pulse.example.com", cfg); err == nil {
		t.Fatal("expected target without a port to fail before dialing")
	}
}

func TestBoundedDeadlineUsesEarlierContextDeadline(t *testing.T) {
	contextDeadline := time.Now().Add(50 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), contextDeadline)
	defer cancel()
	got := boundedDeadline(ctx, time.Minute)
	if !got.Equal(contextDeadline) {
		t.Fatalf("deadline = %v, want context deadline %v", got, contextDeadline)
	}
}
