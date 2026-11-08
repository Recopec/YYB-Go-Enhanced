package protocol

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// A proxy that accepts CONNECT but resets the tunnel as soon as the MMTLS
// record arrives must be reported as filtered, not as a generic handshake
// failure. This is the exact behaviour measured on TLS-shape-filtering exits.
func TestProbeLongLinkDetectsFilteredExit(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				if _, err := c.Read(buf); err != nil {
					return
				}
				// Accept the CONNECT, then drop the tunnel immediately.
				if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
					return
				}
				_, _ = c.Read(buf)
			}(conn)
		}
	}()

	proxy := "http-connect://" + listener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := probeLongLinkTarget(ctx, proxy, Target{IP: "36.155.189.94", Port: 443}, 3*time.Second)
	if result.OK {
		t.Fatalf("expected failure through resetting proxy, got %+v", result)
	}
	if result.Stage != ProbeStageFiltered {
		t.Fatalf("stage = %q, want %q (err=%s)", result.Stage, ProbeStageFiltered, result.Err)
	}
}

// A proxy that refuses CONNECT must be reported as a dial failure so the user
// fixes credentials/whitelist rather than hunting for a different exit.
func TestProbeLongLinkDetectsDialFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
			conn.Close()
		}
	}()

	proxy := "http-connect://" + listener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := probeLongLinkTarget(ctx, proxy, Target{IP: "36.155.189.94", Port: 443}, 3*time.Second)
	if result.Stage != ProbeStageDial {
		t.Fatalf("stage = %q, want %q (err=%s)", result.Stage, ProbeStageDial, result.Err)
	}
}

// The explanation must name the actual cause instead of leaving the operator
// with an opaque EOF.
func TestExplainLongLinkFailureNamesFiltering(t *testing.T) {
	original := fmt.Errorf("LongLink handshake to 36.155.189.94:443 failed: %w", io.EOF)
	explained := ExplainLongLinkFailure(original, "http-connect://1.2.3.4:8080")
	if explained == nil {
		t.Fatal("expected an error")
	}
	message := explained.Error()
	for _, want := range []string{"LongLink", "0xf103", "直连"} {
		if !strings.Contains(message, want) {
			t.Fatalf("message %q missing %q", message, want)
		}
	}
	// Direct egress has no proxy to blame and must pass through unchanged.
	if got := ExplainLongLinkFailure(original, ""); got.Error() != original.Error() {
		t.Fatalf("direct error was rewritten: %q", got)
	}
	// Non-transport failures must not be relabelled as proxy filtering.
	authErr := fmt.Errorf("manualauth failed: cmd=3")
	if got := ExplainLongLinkFailure(authErr, "http-connect://1.2.3.4:8080"); got.Error() != authErr.Error() {
		t.Fatalf("protocol error was rewritten: %q", got)
	}
}
