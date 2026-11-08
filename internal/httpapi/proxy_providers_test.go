package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"yyb_go/internal/store"
)

func TestProxyProviderContractsAreServed(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()

	response := apiRequest(t, app.Handler(), http.MethodGet, "/api/proxy-profiles/providers", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Data []struct {
			ID             string `json:"id"`
			CredentialKind string `json:"credential_kind"`
			AuthModes      []struct {
				Value string `json:"value"`
				Label string `json:"label"`
				Note  string `json:"note"`
			} `json:"auth_modes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byID := map[string]struct {
		Kind  string
		Modes []string
	}{}
	for _, spec := range payload.Data {
		modes := make([]string, 0, len(spec.AuthModes))
		for _, mode := range spec.AuthModes {
			if mode.Label == "" || mode.Note == "" {
				t.Fatalf("%s auth mode %q missing copy", spec.ID, mode.Value)
			}
			modes = append(modes, mode.Value)
		}
		byID[spec.ID] = struct {
			Kind  string
			Modes []string
		}{spec.CredentialKind, modes}
	}

	ipzan, ok := byID["ipzan"]
	if !ok || ipzan.Kind != "link" || len(ipzan.Modes) != 2 {
		t.Fatalf("ipzan spec = %#v", ipzan)
	}
	// Juliange only ships IP whitelisting; an account/password option here
	// would make the page advertise a mechanism the provider does not have.
	juliang, ok := byID["juliang"]
	if !ok || juliang.Kind != "trade_key" || len(juliang.Modes) != 1 || juliang.Modes[0] != "whitelist" {
		t.Fatalf("juliang spec = %#v", juliang)
	}
	if static, ok := byID["static"]; !ok || static.Kind != "address" || len(static.Modes) != 0 {
		t.Fatalf("static spec = %#v", static)
	}
}

// The channel whose auth mode does not exist must be rejected at save time
// instead of silently extracting with the wrong credentials.
func TestProxyProfileRejectsUnknownAuthMode(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()

	response := apiRequest(t, app.Handler(), http.MethodPost, "/api/proxy-profiles", map[string]any{
		"name": "静态 1", "provider": "static", "proxy_type": "http",
		"api_url": "user:pass@127.0.0.1:8080", "authorization_mode": "auth",
	})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s, want 400", response.Code, response.Body.String())
	}
}

// Omitting the mode must fall back to the provider's declared default rather
// than to an accidental zero value.
func TestProxyProfileDefaultsAuthModeFromContract(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()

	response := apiRequest(t, app.Handler(), http.MethodPost, "/api/proxy-profiles", map[string]any{
		"name": "品赞 1", "provider": "ipzan", "proxy_type": "http",
		"api_url": "https://service.ipzan.com/core-extract?no=20261027679909357588&secret=s3cret&minute=5",
	})
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Data struct {
			APIURL string `json:"api_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	parsed, err := url.Parse(payload.Data.APIURL)
	if err != nil {
		t.Fatalf("parse api_url: %v", err)
	}
	if got := parsed.Query().Get("mode"); got != "auth" {
		t.Fatalf("mode = %q, want auth (api_url=%s)", got, payload.Data.APIURL)
	}
	if got := parsed.Query().Get("minute"); got != "5" {
		t.Fatalf("minute = %q, want 5 (api_url=%s)", got, payload.Data.APIURL)
	}
}

// Juliange has no account/password authentication, so asking for it must fail
// at save time instead of storing a mode that the extractor cannot honour.
func TestJuliangProfileRejectsAccountPasswordMode(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()

	response := apiRequest(t, app.Handler(), http.MethodPost, "/api/proxy-profiles", map[string]any{
		"name": "巨量 1", "provider": "juliang", "proxy_type": "http",
		"trade_no": "6278393975360688", "api_key": "6l882ej0ma0q3asabzy3jkv5axwkb8yf",
		"authorization_mode": "auth",
	})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s, want 400", response.Code, response.Body.String())
	}
}

// A profile saved by an older build may still carry the removed account mode.
// It must normalize back to whitelist instead of breaking extraction.
func TestLegacyJuliangProfileFallsBackToWhitelist(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()

	profile, err := app.db.CreateProxyProviderProfile(context.Background(), "巨量旧配置", "juliang", "http",
		"juliang://company/dynamic?key=6l882ej0ma0q3asabzy3jkv5axwkb8yf&mode=auth&trade_no=6278393975360688")
	if err != nil {
		t.Fatalf("CreateProxyProviderProfile() error = %v", err)
	}
	spec, err := app.proxySpecForSetting(context.Background(), &store.AccountProxySetting{
		ProviderProfileID: &profile.ID,
		RegionProvince:    "云南省",
		RegionCity:        "曲靖市",
	})
	if err != nil {
		t.Fatalf("proxySpecForSetting() error = %v", err)
	}
	u, err := url.Parse(spec.APIURL)
	if err != nil {
		t.Fatalf("parse spec.APIURL: %v", err)
	}
	query := u.Query()
	if query.Get("auto_white") != "1" || query.Get("auth_type") != "" || query.Get("city") != "曲靖" {
		t.Fatalf("resolved juliang spec = %s", spec.APIURL)
	}
}
