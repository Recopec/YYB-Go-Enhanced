package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWXAppEgressFollowsAccountWithoutSavedPolicy(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second, TCPProxy: "socks5://127.0.0.1:1080"})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()
	status := "alive"
	account, err := app.db.UpsertAccount(context.Background(), "default-egress-openid", "buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatalf("UpsertAccount() error = %v", err)
	}

	proxyValue, fallbackDirect, err := app.resolveWXAppProxy(context.Background(), account.ID)
	if err != nil || proxyValue != "http-connect://127.0.0.1:1080" || !fallbackDirect {
		t.Fatalf("resolveWXAppProxy() = %q, %v, %v; want account default", proxyValue, fallbackDirect, err)
	}

	// The protocol default and the account connection resolve to the same proxy.
	accountProxy, fallbackDirect, err := app.resolveAccountProxy(context.Background(), account.ID)
	if err != nil || accountProxy != proxyValue || !fallbackDirect {
		t.Fatalf("resolveAccountProxy() = %q, %v, %v; want global TCP proxy", accountProxy, fallbackDirect, err)
	}
}

// "小程序调用出口 = 直连" is the documented escape hatch for exits that cannot
// carry LongLink. It must skip proxy extraction entirely, not extract and then
// throw the node away.
func TestWXAppDirectEgressSkipsProxyExtraction(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	proxyCalls := 0
	proxyAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyCalls++
		_, _ = w.Write([]byte(`{"data":{"ip":"203.0.113.31","port":8080}}`))
	}))
	defer proxyAPI.Close()

	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()
	status := "alive"
	account, err := app.db.UpsertAccount(context.Background(), "direct-egress-openid", "buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatalf("UpsertAccount() error = %v", err)
	}
	direct := "direct"
	if _, err := app.db.UpsertAccountProxySetting(context.Background(), account.ID, "api", "http", "", proxyAPI.URL, nil, "", "", "", 300, &direct); err != nil {
		t.Fatalf("UpsertAccountProxySetting() error = %v", err)
	}

	proxyValue, fallbackDirect, err := app.resolveWXAppProxy(context.Background(), account.ID)
	if err != nil {
		t.Fatalf("resolveWXAppProxy() error = %v", err)
	}
	if proxyValue != "" || fallbackDirect {
		t.Fatalf("resolveWXAppProxy() = %q, %v; want empty proxy and no fallback", proxyValue, fallbackDirect)
	}
	if proxyCalls != 0 {
		t.Fatalf("proxy API calls = %d, want 0 for direct egress", proxyCalls)
	}

	// The account's own proxy must remain intact for QR login and keepalive.
	accountProxy, _, err := app.resolveAccountProxy(context.Background(), account.ID)
	if err != nil || accountProxy != "http-connect://203.0.113.31:8080" {
		t.Fatalf("resolveAccountProxy() = %q, %v; want the configured proxy", accountProxy, err)
	}
}
