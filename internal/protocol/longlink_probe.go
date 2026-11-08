package protocol

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// LongLinkProbeStage describes how far a proxy got when asked to carry WeChat
// LongLink traffic. WeChat's LongLink uses MMTLS, whose TLS record version is
// 0xf103 rather than the 0x03xx a real TLS stack emits. Some proxy exit
// networks run TLS-shape filtering and tear the tunnel down the moment that
// non-TLS record version arrives, which looks identical to an ordinary
// handshake failure unless we test the discriminator explicitly.
type LongLinkProbeStage string

const (
	// ProbeStageOK means the proxy carried a full MMTLS handshake.
	ProbeStageOK LongLinkProbeStage = "ok"
	// ProbeStageDial means the proxy never accepted the CONNECT/SOCKS request.
	ProbeStageDial LongLinkProbeStage = "dial"
	// ProbeStageFiltered means the tunnel carried a TLS-shaped record but was
	// torn down for the 0xf103 record version, proving the exit network filters
	// on record version rather than the remote server rejecting the client.
	ProbeStageFiltered LongLinkProbeStage = "filtered"
	// ProbeStageHandshake means the tunnel stayed open but the handshake failed
	// or timed out for another reason.
	ProbeStageHandshake LongLinkProbeStage = "handshake"
)

// LongLinkProbeResult reports whether a proxy can actually carry WeChat
// LongLink traffic, not merely whether it can be extracted from the provider.
type LongLinkProbeResult struct {
	OK        bool               `json:"ok"`
	Stage     LongLinkProbeStage `json:"stage"`
	Target    string             `json:"target"`
	ElapsedMS int64              `json:"elapsed_ms"`
	Err       string             `json:"err,omitempty"`
}

// ProbeLongLink dials WeChat's LongLink through proxyValue and reports whether
// the MMTLS handshake completes. An empty proxyValue probes direct egress.
func ProbeLongLink(ctx context.Context, proxyValue string, timeout time.Duration) LongLinkProbeResult {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	targets, err := getLonglinkTargets(ctx, timeout, 0)
	if err != nil || len(targets) == 0 {
		targets = []Target{{IP: longlinkDomain, Port: 443}}
	}
	targets = longlinkLoginTargets(targets, 1)

	var last LongLinkProbeResult
	for _, target := range targets {
		last = probeLongLinkTarget(ctx, proxyValue, target, timeout)
		if last.OK {
			return last
		}
	}
	return last
}

func probeLongLinkTarget(ctx context.Context, proxyValue string, target Target, timeout time.Duration) LongLinkProbeResult {
	address := net.JoinHostPort(target.IP, fmt.Sprint(target.Port))
	start := time.Now()
	mc, err := connectMmtls(ctx, target, timeout, proxyValue, false)
	elapsed := time.Since(start)
	if err == nil {
		mc.close()
		return LongLinkProbeResult{OK: true, Stage: ProbeStageOK, Target: address, ElapsedMS: elapsed.Milliseconds()}
	}

	stage := ProbeStageHandshake
	switch {
	case isDialFailure(err):
		stage = ProbeStageDial
	case isHandshakeTeardown(err):
		// Confirm with the discriminator before blaming the exit network.
		if versionFiltered(ctx, proxyValue, target, timeout) {
			stage = ProbeStageFiltered
		}
	}
	return LongLinkProbeResult{
		Stage:     stage,
		Target:    address,
		ElapsedMS: elapsed.Milliseconds(),
		Err:       err.Error(),
	}
}

// versionFiltered re-sends the identical ClientHello with a TLS-1.2 record
// version. If the tunnel survives that but dies on 0xf103, the exit network is
// filtering by record version. The real MMTLS version is never changed for
// actual traffic; this only classifies the failure.
func versionFiltered(ctx context.Context, proxyValue string, target Target, timeout time.Duration) bool {
	conn, err := dialTCP(ctx, target.IP, target.Port, timeout, proxyValue, false)
	if err != nil {
		return false
	}
	defer conn.Close()

	hello, err := probeClientHello()
	if err != nil {
		return false
	}
	record, err := buildRecord(ctHandshake, hello)
	if err != nil {
		return false
	}
	binary.BigEndian.PutUint16(record[1:3], 0x0303)

	if _, err = conn.Write(record); err != nil {
		return false
	}
	// A version-filtering middlebox kills the tunnel immediately. Anything else
	// (a read timeout, a TLS alert, a partial response) means the version was
	// not what triggered the teardown.
	_ = conn.SetReadDeadline(ioDeadline(ctx, 2*time.Second))
	buf := make([]byte, 256)
	if _, err = conn.Read(buf); err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// Some exits reset instead of dropping silently; a reset on the patched
	// record is inconclusive, so only an immediate EOF counts as filtering.
	return errors.Is(err, io.EOF)
}

// probeClientHello builds the ClientHello without a connection, so the
// discriminator can reuse the exact bytes the real handshake would send.
func probeClientHello() ([]byte, error) {
	m := &mmtlsClient{}
	return m.buildClientHello()
}

func isDialFailure(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "dial proxy failed") ||
		strings.Contains(err.Error(), "proxy handshake to")
}

func isHandshakeTeardown(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		strings.Contains(err.Error(), "EOF") ||
		strings.Contains(err.Error(), "forcibly closed") ||
		strings.Contains(err.Error(), "connection reset")
}

// ExplainLongLinkFailure turns a failed login into an actionable message. A
// filtered proxy path is a property of the exit network, not of the account or
// of the provider's extraction API, so the message must say which one to change.
func ExplainLongLinkFailure(err error, proxyValue string) error {
	if err == nil || proxyValue == "" {
		return err
	}
	if !isHandshakeTeardown(err) {
		return err
	}
	return fmt.Errorf("%w；该代理出口无法承载微信 LongLink（MMTLS 记录版本 0xf103 被出口网络的 TLS 特征过滤重置）。代理提取本身正常，但微信调用必须换一条不做该过滤的出口，或改用直连/静态代理", err)
}
