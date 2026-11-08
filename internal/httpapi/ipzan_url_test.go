package httpapi

import (
	"net/url"
	"testing"

	"yyb_go/internal/store"
)

// Pinzan tunnel/minute-billed packages reject extraction without `minute`.
// Region switching rewrites the link, so every provider-specific parameter the
// user pasted must survive that rewrite.
func TestIPZanURLPreservesProviderParameters(t *testing.T) {
	profile := &store.ProxyProviderProfile{
		Provider:  "ipzan",
		ProxyType: "http",
		APIURL:    "https://service.ipzan.com/core-extract?no=20261027679909357588&secret=s3cret&minute=5&protocol=1&format=json",
	}

	raw, err := ipzanURLForRegion(profile, "530100")
	if err != nil {
		t.Fatalf("ipzanURLForRegion() error = %v", err)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	query := parsed.Query()

	want := map[string]string{
		"no":     "20261027679909357588",
		"secret": "s3cret",
		"minute": "5",
		"area":   "530100",
		"num":    "1",
		"format": "json",
	}
	for key, value := range want {
		if got := query.Get(key); got != value {
			t.Fatalf("query %s = %q, want %q (link %s)", key, got, value, raw)
		}
	}
}

// Account/password mode must not drop `minute` either.
func TestIPZanAuthModeKeepsMinute(t *testing.T) {
	profile := &store.ProxyProviderProfile{
		Provider:          "ipzan",
		ProxyType:         "http",
		AuthorizationMode: "auth",
		APIURL:            "https://service.ipzan.com/core-extract?no=20261027679909357588&secret=s3cret&minute=5",
	}
	raw, err := ipzanURLForRegion(profile, "")
	if err != nil {
		t.Fatalf("ipzanURLForRegion() error = %v", err)
	}
	parsed, _ := url.Parse(raw)
	query := parsed.Query()
	if query.Get("mode") != "auth" {
		t.Fatalf("mode = %q, want auth (link %s)", query.Get("mode"), raw)
	}
	if query.Get("minute") != "5" {
		t.Fatalf("minute = %q, want 5 (link %s)", query.Get("minute"), raw)
	}
	if query.Get("area") != "" {
		t.Fatalf("area should be absent for national scope, got %q", query.Get("area"))
	}
}
