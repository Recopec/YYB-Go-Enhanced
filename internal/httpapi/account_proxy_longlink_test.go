package httpapi

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The proxy test endpoint must report LongLink capability, not just that the
// exit was extracted. A proxy that accepts CONNECT and then drops the tunnel
// would otherwise look healthy right up until every wx.login call fails.
func TestProxyTestReportsLongLinkCapability(t *testing.T) {
	t.Setenv("GIN_MODE", "test")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
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
				if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
					return
				}
				_, _ = c.Read(buf)
			}(conn)
		}
	}()

	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()

	handler := app.Handler()
	payload := map[string]any{
		"mode": "static", "proxy_type": "http", "static_proxy": listener.Addr().String(),
	}
	tested := apiRequest(t, handler, http.MethodPost, "/accounts/proxy/test", payload)
	if tested.Code != http.StatusOK {
		t.Fatalf("POST /accounts/proxy/test status = %d body=%s", tested.Code, tested.Body.String())
	}

	var result struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(tested.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode proxy test response: %v", err)
	}
	if ok, present := result.Data["longlink_ok"]; !present {
		t.Fatalf("response missing longlink_ok: %#v", result.Data)
	} else if ok != false {
		t.Fatalf("longlink_ok = %#v, want false for a resetting exit", ok)
	}
	if stage, _ := result.Data["longlink_stage"].(string); stage != "filtered" {
		t.Fatalf("longlink_stage = %#v, want filtered", result.Data["longlink_stage"])
	}
	hint, _ := result.Data["longlink_hint"].(string)
	if !strings.Contains(hint, "LongLink") {
		t.Fatalf("longlink_hint = %q, want an actionable message", hint)
	}
}
