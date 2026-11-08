package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"yyb_go/internal/protocol"
	"yyb_go/internal/proxysource"
	"yyb_go/internal/store"
)

func TestAccountProxyAPIAndDirectOverride(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	app, err := NewApp(Config{
		ResourceRoot:   t.TempDir(),
		RequestTimeout: time.Second,
		TCPProxy:       "http-connect://global.example:8080",
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()
	status := "alive"
	account, err := app.db.UpsertAccount(context.Background(), "proxy-openid", "buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatalf("UpsertAccount() error = %v", err)
	}

	proxyValue, fallbackDirect, err := app.resolveAccountProxy(context.Background(), account.ID)
	if err != nil || proxyValue != "http-connect://global.example:8080" || !fallbackDirect {
		t.Fatalf("global proxy = %q, fallback=%v, err=%v", proxyValue, fallbackDirect, err)
	}

	handler := app.Handler()
	response := apiRequest(t, handler, http.MethodPut, "/accounts/proxy", map[string]any{
		"ref": fmt.Sprint(account.ID), "mode": "direct", "proxy_type": "http",
	})
	if response.Code != http.StatusOK {
		t.Fatalf("PUT /accounts/proxy status = %d body=%s", response.Code, response.Body.String())
	}
	proxyValue, fallbackDirect, err = app.resolveAccountProxy(context.Background(), account.ID)
	if err != nil || proxyValue != "" || fallbackDirect {
		t.Fatalf("direct override = %q, fallback=%v, err=%v", proxyValue, fallbackDirect, err)
	}
}

func TestProxySettingPublicUsesAccountTokenTTL(t *testing.T) {
	setting := &store.AccountProxySetting{AccountID: 7, Mode: "api", ProxyType: "http", RefreshAheadSeconds: 300}
	account := &store.WechatAccount{Credentials: map[string]any{"expires_in": float64(5400)}}
	result := proxySettingPublic(setting, account)
	if result["token_ttl_minutes"] != int64(90) {
		t.Fatalf("token_ttl_minutes = %#v, want 90", result["token_ttl_minutes"])
	}
	if result["keepalive_supported"] != false || result["lifetime_class"] != "short" || result["proxy_warning"] == "" {
		t.Fatalf("dynamic proxy status = %#v, want explicit short-lived warning", result)
	}
	stable := proxySettingPublic(&store.AccountProxySetting{AccountID: 7, Mode: "static", ProxyType: "http"}, account)
	if stable["keepalive_supported"] != true || stable["proxy_warning"] != "" {
		t.Fatalf("stable proxy status = %#v, want keepalive enabled without warning", stable)
	}
}

func TestAccountProxyAPIParsesJSON2AndCascades(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	proxyAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"proxy_list":[{"server_ip":"203.0.113.30","proxy_port":"9010","account":"city-user","pwd":"city-pass"}]}}`))
	}))
	defer proxyAPI.Close()

	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()
	status := "alive"
	account, err := app.db.UpsertAccount(context.Background(), "json2-openid", "buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatalf("UpsertAccount() error = %v", err)
	}
	handler := app.Handler()
	payload := map[string]any{
		"ref": fmt.Sprint(account.ID), "mode": "api", "proxy_type": "socks5", "api_url": proxyAPI.URL + "?province=山东&city=济南",
	}
	if response := apiRequest(t, handler, http.MethodPut, "/accounts/proxy", payload); response.Code != http.StatusOK {
		t.Fatalf("PUT /accounts/proxy status = %d body=%s", response.Code, response.Body.String())
	}
	tested := apiRequest(t, handler, http.MethodPost, "/accounts/proxy/test", payload)
	if tested.Code != http.StatusOK {
		t.Fatalf("POST /accounts/proxy/test status = %d body=%s", tested.Code, tested.Body.String())
	}
	var result struct {
		Data struct {
			Resolved bool   `json:"resolved"`
			Proxy    string `json:"proxy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(tested.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode proxy test response: %v", err)
	}
	if !result.Data.Resolved || result.Data.Proxy != "socks5://203.0.113.30:9010" {
		t.Fatalf("proxy test response = %#v", result.Data)
	}

	if err := app.db.DeleteAccount(context.Background(), account.ID); err != nil {
		t.Fatalf("DeleteAccount() error = %v", err)
	}
	if _, err := app.db.GetAccountProxySetting(context.Background(), account.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("proxy setting after account deletion error = %v", err)
	}
}

func TestDynamicProxyLeaseAvoidsRepeatedExtraction(t *testing.T) {
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
	account, err := app.db.UpsertAccount(context.Background(), "lease-openid", "buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatalf("UpsertAccount() error = %v", err)
	}
	if _, err := app.db.UpsertAccountProxySetting(context.Background(), account.ID, "api", "http", "", proxyAPI.URL, nil, "", "", "", 300, nil); err != nil {
		t.Fatalf("UpsertAccountProxySetting() error = %v", err)
	}
	for range 2 {
		proxyValue, _, err := app.resolveAccountProxy(context.Background(), account.ID)
		if err != nil || proxyValue != "http-connect://203.0.113.31:8080" {
			t.Fatalf("resolveAccountProxy() = %q, %v", proxyValue, err)
		}
	}
	if proxyCalls != 1 {
		t.Fatalf("proxy API calls = %d, want 1", proxyCalls)
	}
	app.invalidateProxyLease(account.ID)
	if _, _, err := app.resolveAccountProxy(context.Background(), account.ID); err != nil {
		t.Fatalf("resolve after invalidation: %v", err)
	}
	if proxyCalls != 2 {
		t.Fatalf("proxy API calls after invalidation = %d, want 2", proxyCalls)
	}
}

func TestIPZanProfilesCanBeNamedAndBoundByRegion(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()
	status := "alive"
	account, err := app.db.UpsertAccount(context.Background(), "ipzan-openid", "buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatalf("UpsertAccount() error = %v", err)
	}
	handler := app.Handler()
	created := apiRequest(t, handler, http.MethodPost, "/api/proxy-profiles", map[string]any{
		"name": "品赞代理 1", "provider": "ipzan", "proxy_type": "http",
		"authorization_mode": "auth",
		"api_url":            "https://service.ipzan.com/core-extract?no=123&secret=test&format=txt&area=110000",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("POST /api/proxy-profiles status = %d body=%s", created.Code, created.Body.String())
	}
	var profileResponse struct {
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &profileResponse); err != nil || profileResponse.Data.ID == 0 {
		t.Fatalf("decode profile response = %#v, %v", profileResponse, err)
	}
	profileID := profileResponse.Data.ID
	saved := apiRequest(t, handler, http.MethodPut, "/accounts/proxy", map[string]any{
		"ref": fmt.Sprint(account.ID), "mode": "api", "provider_profile_id": profileID,
		"region_code": "370100", "region_province": "山东省", "region_city": "济南市",
		"refresh_ahead_minutes": 15,
	})
	if saved.Code != http.StatusOK {
		t.Fatalf("PUT /accounts/proxy status = %d body=%s", saved.Code, saved.Body.String())
	}
	setting, err := app.db.GetAccountProxySetting(context.Background(), account.ID)
	if err != nil || setting.ProviderProfileID == nil || *setting.ProviderProfileID != profileID || setting.APIURL != "" || setting.RegionCode != "370100" || setting.RefreshAheadSeconds != 900 {
		t.Fatalf("saved profile setting = %#v, %v", setting, err)
	}
	spec, err := app.proxySpecForSetting(context.Background(), setting)
	if err != nil || !strings.Contains(spec.APIURL, "area=370100") || !strings.Contains(spec.APIURL, "protocol=1") || !strings.Contains(spec.APIURL, "mode=auth") || !strings.Contains(spec.APIURL, "format=json") || strings.Contains(spec.APIURL, "area=110000") {
		t.Fatalf("resolved profile spec = %#v, %v", spec, err)
	}
	deleted := apiRequest(t, handler, http.MethodDelete, fmt.Sprintf("/api/proxy-profiles/%d", profileID), nil)
	if deleted.Code != http.StatusConflict {
		t.Fatalf("DELETE bound profile status = %d body=%s", deleted.Code, deleted.Body.String())
	}
}

func TestJuliangProfilesSignEachAccountRegion(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()
	status := "alive"
	account, err := app.db.UpsertAccount(context.Background(), "juliang-openid", "buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatalf("UpsertAccount() error = %v", err)
	}
	handler := app.Handler()
	created := apiRequest(t, handler, http.MethodPost, "/api/proxy-profiles", map[string]any{
		"name": "巨量代理 1", "provider": "juliang", "proxy_type": "http",
		"authorization_mode": "whitelist",
		"trade_no":           "1234567890123456",
		"api_key":            "0123456789abcdef0123456789abcdef",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("POST juliang profile status = %d body=%s", created.Code, created.Body.String())
	}
	var profileResponse struct {
		Data store.ProxyProviderProfile `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &profileResponse); err != nil || profileResponse.Data.ID == 0 {
		t.Fatalf("decode juliang profile = %#v, %v", profileResponse, err)
	}
	if !strings.HasPrefix(profileResponse.Data.APIURL, "juliang://company/dynamic?") {
		t.Fatalf("stored juliang profile URL = %q", profileResponse.Data.APIURL)
	}
	saved := apiRequest(t, handler, http.MethodPut, "/accounts/proxy", map[string]any{
		"ref": fmt.Sprint(account.ID), "mode": "api", "provider_profile_id": profileResponse.Data.ID,
		"region_code": "370700", "region_province": "山东省", "region_city": "潍坊市",
		"refresh_ahead_minutes": 5,
	})
	if saved.Code != http.StatusOK {
		t.Fatalf("PUT juliang account proxy status = %d body=%s", saved.Code, saved.Body.String())
	}
	setting, err := app.db.GetAccountProxySetting(context.Background(), account.ID)
	if err != nil {
		t.Fatalf("GetAccountProxySetting() error = %v", err)
	}
	spec, err := app.proxySpecForSetting(context.Background(), setting)
	if err != nil {
		t.Fatalf("proxySpecForSetting() error = %v", err)
	}
	u, err := url.Parse(spec.APIURL)
	if err != nil {
		t.Fatalf("parse juliang extraction URL: %v", err)
	}
	query := u.Query()
	if u.Scheme != "http" || u.Host != "v2.api.juliangip.com" || query.Get("province") != "山东" || query.Get("city") != "潍坊" || query.Get("area") != "" || query.Get("auto_white") != "1" || query.Get("auth_type") != "" || query.Get("result_type") != "json2" || len(query.Get("sign")) != 32 {
		t.Fatalf("resolved juliang spec = %s", spec.APIURL)
	}
}
func TestJuliangPostpayProfilesRouteToPostpayEndpoint(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()

	profile, err := app.db.CreateProxyProviderProfile(context.Background(), "巨量按量", "juliang", "http", "juliang://company/dynamic?trade_no=6483587531995538&key=0123456789abcdef0123456789abcdef&mode=whitelist")
	if err != nil {
		t.Fatalf("CreateProxyProviderProfile() error = %v", err)
	}

	spec, err := app.proxySpecForSetting(context.Background(), &store.AccountProxySetting{
		ProviderProfileID: &profile.ID,
		RegionProvince:    "云南省",
		RegionCity:        "昆明市",
	})
	if err != nil {
		t.Fatalf("proxySpecForSetting() error = %v", err)
	}

	u, err := url.Parse(spec.APIURL)
	if err != nil {
		t.Fatalf("parse spec.APIURL: %v", err)
	}
	if u.Path != "/company/postpay/getips" {
		t.Fatalf("expected /company/postpay/getips, got %s", u.Path)
	}
	spec62, err := app.proxySpecForSetting(context.Background(), &store.AccountProxySetting{
		ProviderProfileID: &profile.ID,
		RegionProvince:    "云南省",
		RegionCity:        "曲靖市",
	})
	if err != nil {
		t.Fatalf("proxySpecForSetting() error = %v", err)
	}
	u62, _ := url.Parse(spec62.APIURL)
	if u62.Path != "/company/postpay/getips" {
		t.Fatalf("expected /company/postpay/getips, got %s", u62.Path)
	}

	// Test alphanumeric key validation
	profile62, err := app.db.CreateProxyProviderProfile(context.Background(), "巨量62", "juliang", "http", "juliang://company/dynamic?trade_no=6278393975360688&key=6l882ej0ma0q3asabzy3jkv5axwkb8yf&mode=whitelist")
	if err != nil {
		t.Fatalf("CreateProxyProviderProfile() error = %v", err)
	}
	specAlpha, err := app.proxySpecForSetting(context.Background(), &store.AccountProxySetting{
		ProviderProfileID: &profile62.ID,
		RegionProvince:    "云南省",
		RegionCity:        "曲靖市",
	})
	if err != nil {
		t.Fatalf("proxySpecForSetting() alpha key error = %v", err)
	}
	uAlpha, _ := url.Parse(specAlpha.APIURL)
	if len(uAlpha.Query().Get("sign")) != 32 {
		t.Fatalf("expected 32-char sign, got %s", uAlpha.Query().Get("sign"))
	}
	if uAlpha.Path != "/company/postpay/getips" {
		t.Fatalf("expected /company/postpay/getips for 62-trade, got %s", uAlpha.Path)
	}

	// Test autonomous prefecture normalization (e.g. 大理白族自治州 -> 大理)
	specDali, err := app.proxySpecForSetting(context.Background(), &store.AccountProxySetting{
		ProviderProfileID: &profile62.ID,
		RegionProvince:    "云南省",
		RegionCity:        "大理白族自治州",
	})
	if err != nil {
		t.Fatalf("proxySpecForSetting() dali error = %v", err)
	}
	uDali, _ := url.Parse(specDali.APIURL)
	if uDali.Query().Get("city") != "大理" {
		t.Fatalf("expected city=大理, got %s", uDali.Query().Get("city"))
	}
	if uDali.Query().Get("province") != "云南" {
		t.Fatalf("expected province=云南, got %s", uDali.Query().Get("province"))
	}
}
func TestJuliangProfileExtractsFromPastedURLAndDefaultsToWhitelist(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()

	handler := app.Handler()
	pastedURL := "http://v2.api.juliangip.com/postpay/getips?auto_white=1&num=1&pt=1&result_type=json2&trade_no=6483587531995538&sign=4a2a59427526d3b7bbbd3d2858569171"
	created := apiRequest(t, handler, http.MethodPost, "/api/proxy-profiles", map[string]any{
		"name":       "巨量链接自动解析",
		"provider":   "juliang",
		"proxy_type": "http",
		"trade_no":   pastedURL,
		"api_key":    "0123456789abcdef0123456789abcdef",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("POST juliang profile status = %d body=%s", created.Code, created.Body.String())
	}
	var profileResponse struct {
		Data store.ProxyProviderProfile `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &profileResponse); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	u, err := url.Parse(profileResponse.Data.APIURL)
	if err != nil {
		t.Fatalf("parse profile APIURL: %v", err)
	}
	if u.Query().Get("trade_no") != "6483587531995538" {
		t.Fatalf("expected trade_no=6483587531995538, got %s", u.Query().Get("trade_no"))
	}
	if u.Query().Get("mode") != "whitelist" {
		t.Fatalf("expected mode=whitelist by default, got %s", u.Query().Get("mode"))
	}
	if u.Query().Get("endpoint") != "http://v2.api.juliangip.com/postpay/getips" {
		t.Fatalf("expected endpoint http://v2.api.juliangip.com/postpay/getips, got %s", u.Query().Get("endpoint"))
	}
}
func TestPinzanAndJuliangDualProviderIsolation(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()

	// 1. Create Pinzan Profile
	pinzanProfile, err := app.db.CreateProxyProviderProfile(context.Background(), "品赞测试", "ipzan", "http", "https://service.ipzan.com/core-extract?no=20261028001&secret=pinzanpass123&mode=auth&format=json")
	if err != nil {
		t.Fatalf("Create Pinzan profile: %v", err)
	}

	// 2. Create Juliang Profile
	juliangProfile, err := app.db.CreateProxyProviderProfile(context.Background(), "巨量测试", "juliang", "http", "juliang://company/dynamic?trade_no=6278393975360688&key=6l882ej0ma0q3asabzy3jkv5axwkb8yf&mode=whitelist")
	if err != nil {
		t.Fatalf("Create Juliang profile: %v", err)
	}

	// 3. Bind account to Pinzan with Qujing (code: 530300, name: 曲靖市, province: 云南省)
	pinzanSpec, err := app.proxySpecForSetting(context.Background(), &store.AccountProxySetting{
		ProviderProfileID: &pinzanProfile.ID,
		RegionCode:        "530300",
		RegionProvince:    "云南省",
		RegionCity:        "曲靖市",
	})
	if err != nil {
		t.Fatalf("resolve pinzan spec: %v", err)
	}
	uPinzan, err := url.Parse(pinzanSpec.APIURL)
	if err != nil {
		t.Fatalf("parse pinzan URL: %v", err)
	}
	// Verify Pinzan URL has 6-digit area code 530300, no province or city Chinese params
	if uPinzan.Host != "service.ipzan.com" {
		t.Fatalf("expected service.ipzan.com, got %s", uPinzan.Host)
	}
	if uPinzan.Query().Get("area") != "530300" {
		t.Fatalf("expected Pinzan area=530300, got %s", uPinzan.Query().Get("area"))
	}
	if uPinzan.Query().Get("city") != "" || uPinzan.Query().Get("province") != "" {
		t.Fatalf("Pinzan URL should not contain city or province params: %s", pinzanSpec.APIURL)
	}

	// 4. Bind account to Juliang with the EXACT same input data (code: 530300, name: 曲靖市, province: 云南省)
	juliangSpec, err := app.proxySpecForSetting(context.Background(), &store.AccountProxySetting{
		ProviderProfileID: &juliangProfile.ID,
		RegionCode:        "530300",
		RegionProvince:    "云南省",
		RegionCity:        "曲靖市",
	})
	if err != nil {
		t.Fatalf("resolve juliang spec: %v", err)
	}
	uJuliang, err := url.Parse(juliangSpec.APIURL)
	if err != nil {
		t.Fatalf("parse juliang URL: %v", err)
	}
	// Verify Juliang URL has Chinese city=曲靖 and province=云南, valid sign, no area code param
	if uJuliang.Host != "v2.api.juliangip.com" {
		t.Fatalf("expected v2.api.juliangip.com, got %s", uJuliang.Host)
	}
	if uJuliang.Query().Get("city") != "曲靖" {
		t.Fatalf("expected Juliang city=曲靖, got %s", uJuliang.Query().Get("city"))
	}
	if uJuliang.Query().Get("province") != "云南" {
		t.Fatalf("expected Juliang province=云南, got %s", uJuliang.Query().Get("province"))
	}
	if uJuliang.Query().Get("area") != "" {
		t.Fatalf("Juliang URL must not contain area param: %s", juliangSpec.APIURL)
	}
	if len(uJuliang.Query().Get("sign")) != 32 {
		t.Fatalf("expected 32-char sign in Juliang URL, got %s", uJuliang.Query().Get("sign"))
	}
}

func TestStaticProxyProfileCanBeSelectedAndReused(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()
	status := "alive"
	account, err := app.db.UpsertAccount(context.Background(), "static-profile-openid", "buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatalf("UpsertAccount() error = %v", err)
	}
	handler := app.Handler()
	created := apiRequest(t, handler, http.MethodPost, "/api/proxy-profiles", map[string]any{
		"name": "家庭固定出口", "provider": "static", "proxy_type": "http",
		"api_url": "user:pass@203.0.113.40:8080",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("POST static profile status = %d body=%s", created.Code, created.Body.String())
	}
	var profileResponse struct {
		Data store.ProxyProviderProfile `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &profileResponse); err != nil || profileResponse.Data.ID == 0 {
		t.Fatalf("decode static profile = %#v, %v", profileResponse, err)
	}
	saved := apiRequest(t, handler, http.MethodPut, "/accounts/proxy", map[string]any{
		"ref": fmt.Sprint(account.ID), "provider_profile_id": profileResponse.Data.ID,
		"refresh_ahead_minutes": 5,
	})
	if saved.Code != http.StatusOK {
		t.Fatalf("PUT static profile selection status = %d body=%s", saved.Code, saved.Body.String())
	}
	setting, err := app.db.GetAccountProxySetting(context.Background(), account.ID)
	if err != nil || setting.Mode != "static" || setting.ProviderProfileID == nil {
		t.Fatalf("static profile setting = %#v, %v", setting, err)
	}
	spec, err := app.proxySpecForSetting(context.Background(), setting)
	if err != nil || spec.Mode != "static" || !strings.Contains(spec.StaticProxy, "203.0.113.40:8080") {
		t.Fatalf("resolved static profile spec = %#v, %v", spec, err)
	}
}

func TestExistingAccountRescanPreservesProxySetting(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()
	status := "expired"
	account, err := app.db.UpsertAccount(context.Background(), "rescan-openid", "old-buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatalf("UpsertAccount() error = %v", err)
	}
	profile, err := app.db.CreateProxyProviderProfile(context.Background(), "品赞代理 2", "ipzan", "http", "https://service.ipzan.com/core-extract?no=2&secret=x")
	if err != nil {
		t.Fatalf("CreateProxyProviderProfile() error = %v", err)
	}
	policy := "direct"
	if _, err := app.db.UpsertAccountProxySetting(context.Background(), account.ID, "api", "http", "", "", &profile.ID, "370100", "山东省", "济南市", 300, &policy); err != nil {
		t.Fatalf("UpsertAccountProxySetting() error = %v", err)
	}
	direct, _ := proxysource.NormalizeSpec(proxysource.Spec{Mode: "direct"})
	if err := app.saveNewAccountProxy(context.Background(), account.ID, true, accountProxyIn{Mode: "direct"}, direct); err != nil {
		t.Fatalf("saveNewAccountProxy() error = %v", err)
	}
	setting, err := app.db.GetAccountProxySetting(context.Background(), account.ID)
	if err != nil || setting.ProviderProfileID == nil || *setting.ProviderProfileID != profile.ID || setting.RegionCode != "370100" || setting.ProtocolProxyMode != "direct" {
		t.Fatalf("proxy after rescan = %#v, %v", setting, err)
	}
}

func TestWXAppCallUsesExistingLoginBufferBeforeRefreshing(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()
	status := "alive"
	account, err := app.db.UpsertAccount(context.Background(), "reuse-login-buffer", "buffer", nil, nil, nil, nil, map[string]any{"refreshtoken": "refresh"}, &status)
	if err != nil {
		t.Fatalf("UpsertAccount() error = %v", err)
	}
	refreshCalls := 0
	app.refreshCredentials = func(context.Context, protocol.LoginBufferCredentials) (protocol.LoginBufferCredentials, error) {
		refreshCalls++
		return protocol.LoginBufferCredentials{}, errors.New("refresh should not run")
	}
	callCount := 0
	result, err := app.invokeWXApp(context.Background(), account, "wx0000000000000000", nil, func(context.Context, *store.WechatAccount, string, map[string]any, string, bool) (map[string]any, error) {
		callCount++
		return map[string]any{"code": "ok"}, nil
	})
	if err != nil || result["code"] != "ok" || callCount != 1 || refreshCalls != 0 {
		t.Fatalf("invokeWXApp() result=%#v err=%v calls=%d refreshes=%d", result, err, callCount, refreshCalls)
	}
}

func TestProtocolNetworkFailureDoesNotRefreshOrDiscardSession(t *testing.T) {
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx := context.Background()
	status := "alive"
	account, err := app.db.UpsertAccount(ctx, "network-failure", "buffer", nil, nil, nil, nil, map[string]any{"refreshtoken": "refresh"}, &status)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.db.PutSession(ctx, account.ID, nil, map[string]any{"marker": "preserve"}, time.Now().Add(time.Hour).Unix(), ""); err != nil {
		t.Fatal(err)
	}
	refreshes := 0
	app.refreshCredentials = func(context.Context, protocol.LoginBufferCredentials) (protocol.LoginBufferCredentials, error) {
		refreshes++
		return protocol.LoginBufferCredentials{}, errors.New("unexpected refresh")
	}
	calls := 0
	want := &net.OpError{Op: "read", Net: "tcp", Err: context.DeadlineExceeded}
	_, err = app.invokeWXApp(ctx, account, "wx0000000000000000", nil, func(context.Context, *store.WechatAccount, string, map[string]any, string, bool) (map[string]any, error) {
		calls++
		return nil, fmt.Errorf("LongLink read: %w", want)
	})
	if !errors.Is(err, want) || calls != 1 || refreshes != 0 {
		t.Fatalf("network failure caused credential recovery: calls=%d refreshes=%d err=%v", calls, refreshes, err)
	}
	if _, err := app.db.GetSession(ctx, account.ID, ""); err != nil {
		t.Fatalf("discarded valid session: %v", err)
	}
	fresh, err := app.db.GetAccount(ctx, account.ID)
	if err != nil || accountStatus(fresh) != "alive" {
		t.Fatalf("network failure changed account state: %v", err)
	}
}

func TestAccountOperationWaitCanBeCancelled(t *testing.T) {
	for _, operation := range []string{"refresh", "proxy-lease"} {
		t.Run(operation, func(t *testing.T) {
			app, err := NewApp(Config{ResourceRoot: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			defer app.Close()
			status := "alive"
			account, err := app.db.UpsertAccount(context.Background(), "queue-test", "buffer", nil, nil, nil, nil, nil, &status)
			if err != nil {
				t.Fatal(err)
			}
			lock := app.refreshLockFor(account.ID)
			if operation == "proxy-lease" {
				_, err = app.db.UpsertAccountProxySetting(context.Background(), account.ID, "api", "http", "", "http://proxy.invalid/", nil, "", "", "", 300, nil)
				if err != nil {
					t.Fatal(err)
				}
				lock = app.proxyLeaseLockFor(account.ID)
			}
			lock <- struct{}{}
			defer func() { <-lock }()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if operation == "refresh" {
					_, _, err := app.refreshAccount(ctx, account, true)
					done <- err
				} else {
					_, _, err := app.resolveAccountProxy(ctx, account.ID)
					done <- err
				}
			}()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("queue error = %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("cancelled request remained queued")
			}
		})
	}
}

func TestExpiredAccountRejectsBeforeResolvingProxy(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	proxyCalls := 0
	proxyAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyCalls++
		_, _ = w.Write([]byte("203.0.113.10:8080"))
	}))
	defer proxyAPI.Close()
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), RequestTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()
	status := "expired"
	account, err := app.db.UpsertAccount(context.Background(), "expired-openid", "buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatalf("UpsertAccount() error = %v", err)
	}
	if _, err := app.db.UpsertAccountProxySetting(context.Background(), account.ID, "api", "http", "", proxyAPI.URL, nil, "", "", "", 300, nil); err != nil {
		t.Fatalf("UpsertAccountProxySetting() error = %v", err)
	}
	callCount := 0
	_, err = app.invokeWXApp(context.Background(), account, "wx0000000000000000", nil, func(context.Context, *store.WechatAccount, string, map[string]any, string, bool) (map[string]any, error) {
		callCount++
		return map[string]any{}, nil
	})
	var expired accountExpiredError
	if !errors.As(err, &expired) || proxyCalls != 0 || callCount != 0 {
		t.Fatalf("invokeWXApp() err=%v proxyCalls=%d callCount=%d", err, proxyCalls, callCount)
	}
}

func TestParseIPIPOutput(t *testing.T) {
	// Standard text response
	textSample := "当前 IP：120.231.188.108  来自于：中国 广东 江门  移动\n"
	probe, err := parseIPIPOutput(textSample)
	if err != nil {
		t.Fatalf("parseIPIPOutput(text) error = %v", err)
	}
	if probe.IP != "120.231.188.108" || probe.Country != "中国" || probe.Region != "广东" || probe.City != "江门" {
		t.Fatalf("unexpected probe result: %+v", probe)
	}

	// Municipality text response
	muniSample := "当前 IP：111.198.12.34  来自于：中国 北京  联通"
	probeMuni, err := parseIPIPOutput(muniSample)
	if err != nil {
		t.Fatalf("parseIPIPOutput(muni) error = %v", err)
	}
	if probeMuni.IP != "111.198.12.34" || probeMuni.Region != "北京" || probeMuni.City != "北京" {
		t.Fatalf("unexpected municipality probe result: %+v", probeMuni)
	}

	// JSON response
	jsonSample := `{"ret":"ok","data":{"ip":"120.231.188.108","location":["中国","广东","江门","","移动"]}}`
	probeJSON, err := parseIPIPOutput(jsonSample)
	if err != nil {
		t.Fatalf("parseIPIPOutput(json) error = %v", err)
	}
	if probeJSON.IP != "120.231.188.108" || probeJSON.Country != "中国" || probeJSON.Region != "广东" || probeJSON.City != "江门" {
		t.Fatalf("unexpected json probe result: %+v", probeJSON)
	}
}
