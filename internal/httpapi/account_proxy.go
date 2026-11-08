package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"yyb_go/internal/protocol"
	"yyb_go/internal/proxysource"
	"yyb_go/internal/qr"
	"yyb_go/internal/store"
)

type accountProxyIn struct {
	Product             string  `json:"product"`
	Ref                 string  `json:"ref"`
	Mode                string  `json:"mode"`
	ProxyType           string  `json:"proxy_type"`
	StaticProxy         string  `json:"static_proxy"`
	APIURL              string  `json:"api_url"`
	ProviderProfileID   *int64  `json:"provider_profile_id"`
	RegionCode          string  `json:"region_code"`
	RegionProvince      string  `json:"region_province"`
	RegionCity          string  `json:"region_city"`
	RefreshAheadMinutes int64   `json:"refresh_ahead_minutes"`
	ProtocolProxyMode   *string `json:"protocol_proxy_mode"`
}

const loginProductAppStore = "appstore"

func normalizeLoginProduct(product string) (string, error) {
	product = strings.ToLower(strings.TrimSpace(product))
	if product == "" {
		return loginProductAppStore, nil
	}
	if !qr.IsScanChannel(product) {
		return "", fmt.Errorf("不支持的扫码渠道 %q", product)
	}
	return product, nil
}

type qrLoginSession struct {
	Session   *qr.Session
	Client    *qr.Client
	ProxySpec proxysource.Spec
	ProxyIn   accountProxyIn
	// Optional one-time account-link binding. Zero means a normal console QR.
	AccountLinkID   int64
	AccountLinkHash string
	AccountLinkMode string
	BaseAccountID   int64
	SwitchConfirmed bool
	// A successful multi-channel link confirmation can be retried after a lost response.
	LinkSavedAccount *store.AccountPublic
	// DeferPanelSync postpones the automation panel sync after the scan is
	// confirmed. A multi-channel scan is bound into one fleet by the console right
	// after each confirmation, and the panel lists a fleet by its primary only.
	DeferPanelSync bool
	// Keep the freshly fetched image in memory so the image endpoint does not
	// depend on the QR cache directory being writable in a container.
	ImageBytes []byte
	// mu serializes cancellation with the final account write in confirm.
	mu        sync.Mutex
	cancelled bool
}

type accountProxyLease struct {
	Value            string
	SettingUpdatedAt int64
	LastVerifiedAt   time.Time
}

const (
	proxyProbeInterval = 15 * time.Second
	proxyProbeTimeout  = 3 * time.Second
)

func (body accountProxyIn) spec() proxysource.Spec {
	return proxysource.Spec{Mode: body.Mode, ProxyType: body.ProxyType, StaticProxy: body.StaticProxy, APIURL: body.APIURL}
}

func proxySpecFromSetting(setting *store.AccountProxySetting) proxysource.Spec {
	if setting == nil {
		return proxysource.Spec{Mode: "direct", ProxyType: "http"}
	}
	return proxysource.Spec{
		Mode: setting.Mode, ProxyType: setting.ProxyType,
		StaticProxy: setting.StaticProxy, APIURL: setting.APIURL,
	}
}

func proxySettingPublic(setting *store.AccountProxySetting, account *store.WechatAccount) map[string]any {
	expiresIn := protocol.CredentialsFromMap(account.Credentials).ExpiresIn
	tokenTTLMinutes := (expiresIn + 59) / 60
	dynamic := setting.Mode == "api"
	lifetimeClass := "stable"
	keepaliveSupported := true
	keepaliveNote := "可参与自动保活"
	if dynamic {
		lifetimeClass = "short"
		keepaliveSupported = false
		keepaliveNote = "短效代理，无法用于账号保活；仅用于扫码和临时请求"
	}
	return map[string]any{
		"account_id": setting.AccountID, "mode": setting.Mode, "proxy_type": setting.ProxyType,
		"static_proxy": setting.StaticProxy, "api_url": setting.APIURL,
		"provider_profile_id": setting.ProviderProfileID,
		"region_code":         setting.RegionCode, "region_province": setting.RegionProvince, "region_city": setting.RegionCity,
		"refresh_ahead_minutes": setting.RefreshAheadSeconds / 60,
		"protocol_proxy_mode":   setting.ProtocolProxyMode,
		"token_ttl_minutes":     tokenTTLMinutes,
		"lifetime_class":        lifetimeClass, "keepalive_supported": keepaliveSupported, "keepalive_note": keepaliveNote,
		"proxy_warning": proxyWarning(dynamic),
		"configured":    setting.Mode != "direct", "updated_at": setting.UpdatedAt,
	}
}

func proxyWarning(dynamic bool) string {
	if dynamic {
		return "短效代理每次提取都会产生新的出口，无法稳定维持微信登录会话；后台自动保活已关闭。"
	}
	return ""
}

func (a *App) handleAccountProxy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		acc, ok := a.resolveAccountFromQuery(w, r)
		if !ok {
			return
		}
		setting, err := a.db.AccountProxySettingOrDefault(r.Context(), acc.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, proxySettingPublic(setting, acc))
	case http.MethodPut:
		var body accountProxyIn
		if err := decodeOptionalJSON(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		acc, ok := a.resolveAccountRef(w, r, body.Ref)
		if !ok {
			return
		}
		normalizedBody, normalized, err := a.normalizeAccountProxyInput(r.Context(), body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		setting, err := a.saveAccountProxyInput(r.Context(), acc.ID, normalizedBody, normalized)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := a.db.InvalidateAccountSessions(r.Context(), acc.ID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		a.invalidateProxyLease(acc.ID)
		writeJSON(w, http.StatusOK, proxySettingPublic(setting, acc))
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleAccountProxyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body accountProxyIn
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	_, spec, err := a.normalizeAccountProxyInput(r.Context(), body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(body.Ref) != "" && strings.TrimSpace(body.Mode) == "" {
		acc, ok := a.resolveAccountRef(w, r, body.Ref)
		if !ok {
			return
		}
		setting, err := a.db.AccountProxySettingOrDefault(r.Context(), acc.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		spec, err = a.proxySpecForSetting(r.Context(), setting)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	resolved, err := a.resolveProxySpec(r.Context(), spec)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	result := map[string]any{"resolved": resolved != "", "proxy": proxysource.Mask(resolved)}
	if resolved != "" {
		probe, probeErr := a.probeProxyExit(r.Context(), resolved)
		if probeErr != nil {
			result["probe_error"] = "出口检测请求失败，请重试"
		} else {
			result["exit_ip"] = probe.IP
			result["exit_country"] = probe.Country
			result["exit_region"] = probe.Region
			result["exit_city"] = probe.City
		}
		// An extractable exit is not necessarily able to carry WeChat LongLink.
		// Probe the real MMTLS handshake so a TLS-shape-filtering exit surfaces
		// here instead of failing later on every wx.login call.
		ll := protocol.ProbeLongLink(r.Context(), resolved, 8*time.Second)
		result["longlink_ok"] = ll.OK
		result["longlink_stage"] = string(ll.Stage)
		result["longlink_target"] = ll.Target
		result["longlink_elapsed_ms"] = ll.ElapsedMS
		if ll.Err != "" {
			result["longlink_error"] = ll.Err
		}
		if !ll.OK {
			result["longlink_hint"] = "该出口无法完成微信 LongLink（MMTLS）握手，代理提取正常但微信调用会失败；请更换出口或改用直连/静态代理"
		}
	}
	writeJSON(w, http.StatusOK, result)
}

type proxyExitProbe struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	Region  string `json:"region"`
	City    string `json:"city"`
}

var (
	ipipTextIPRE  = regexp.MustCompile(`当前\s*IP[：:]\s*([0-9a-fA-F.:]+)`)
	ipipTextLocRE = regexp.MustCompile(`来自于[：:]\s*(.+)`)
)

func parseIPIPOutput(text string) (proxyExitProbe, error) {
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "{") {
		var jsonResp struct {
			Ret  string `json:"ret"`
			Data struct {
				IP       string   `json:"ip"`
				Location []string `json:"location"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(text), &jsonResp); err == nil && jsonResp.Data.IP != "" {
			var country, region, city string
			loc := jsonResp.Data.Location
			if len(loc) > 0 {
				country = loc[0]
			}
			if len(loc) > 1 {
				region = loc[1]
			}
			if len(loc) > 2 {
				city = loc[2]
			}
			if city == "" && isMunicipality(region) {
				city = region
			}
			return proxyExitProbe{
				IP:      jsonResp.Data.IP,
				Country: country,
				Region:  region,
				City:    city,
			}, nil
		}
	}

	ipMatch := ipipTextIPRE.FindStringSubmatch(text)
	if len(ipMatch) < 2 {
		return proxyExitProbe{}, fmt.Errorf("myip.ipip.net output missing IP: %s", text)
	}
	ip := strings.TrimSpace(ipMatch[1])

	var country, region, city string
	locMatch := ipipTextLocRE.FindStringSubmatch(text)
	if len(locMatch) >= 2 {
		parts := strings.Fields(locMatch[1])
		if len(parts) >= 1 {
			country = parts[0]
		}
		if len(parts) >= 2 {
			region = parts[1]
		}
		if isMunicipality(region) {
			city = region
		} else if len(parts) >= 3 {
			city = parts[2]
		}
	}
	return proxyExitProbe{
		IP:      ip,
		Country: country,
		Region:  region,
		City:    city,
	}, nil
}

func isMunicipality(region string) bool {
	switch region {
	case "北京", "上海", "天津", "重庆", "北京市", "上海市", "天津市", "重庆市":
		return true
	default:
		return false
	}
}

func (a *App) probeProxyExit(ctx context.Context, proxyValue string) (proxyExitProbe, error) {
	transport, err := protocol.NewHTTPTransport(proxyValue, false)
	if err != nil {
		return proxyExitProbe{}, err
	}
	client := &http.Client{Timeout: a.cfg.RequestTimeout, Transport: transport}
	endpoints := []string{"https://myip.ipip.net", "http://myip.ipip.net"}
	var lastErr error
	for _, ep := range endpoints {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
		if reqErr != nil {
			lastErr = reqErr
			continue
		}
		req.Header.Set("User-Agent", "curl/7.88.1")
		resp, doErr := client.Do(req)
		if doErr != nil {
			lastErr = doErr
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("myip.ipip.net returned HTTP %d", resp.StatusCode)
			continue
		}
		probe, parseErr := parseIPIPOutput(string(body))
		if parseErr != nil {
			lastErr = parseErr
			continue
		}
		return probe, nil
	}
	return proxyExitProbe{}, lastErr
}

func (a *App) resolveProxySpec(ctx context.Context, spec proxysource.Spec) (string, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Timeout: a.cfg.RequestTimeout, Transport: transport}
	return proxysource.Resolve(ctx, client, spec)
}

// Protocol calls can explicitly use direct egress without extracting a proxy.
// QR login, profile queries and credential refresh keep using resolveAccountProxy.
func (a *App) resolveWXAppProxy(ctx context.Context, accountID int64) (string, bool, error) {
	setting, err := a.db.GetAccountProxySetting(ctx, accountID)
	if errors.Is(err, sql.ErrNoRows) {
		// Accounts without a saved policy follow the account connection, which is
		// also the insert default for new accounts.
		return a.resolveAccountProxy(ctx, accountID)
	}
	if err != nil {
		return "", false, err
	}
	if setting.ProtocolProxyMode == store.ProtocolProxyModeDirect {
		return "", false, nil
	}
	return a.resolveAccountProxy(ctx, accountID)
}

func (a *App) resolveAccountProxy(ctx context.Context, accountID int64) (string, bool, error) {
	setting, err := a.db.GetAccountProxySetting(ctx, accountID)
	if errors.Is(err, sql.ErrNoRows) {
		if strings.TrimSpace(a.cfg.TCPProxy) == "" {
			return "", false, nil
		}
		normalized, normalizeErr := proxysource.NormalizeSpec(proxysource.Spec{Mode: "static", StaticProxy: a.cfg.TCPProxy})
		if normalizeErr != nil {
			return "", false, normalizeErr
		}
		return normalized.StaticProxy, true, nil
	}
	if err != nil {
		return "", false, err
	}
	spec, err := a.proxySpecForSetting(ctx, setting)
	if err != nil {
		return "", false, err
	}
	if spec.Mode != "api" {
		proxyValue, err := a.resolveProxySpec(ctx, spec)
		return proxyValue, false, err
	}
	leaseLock := a.proxyLeaseLockFor(accountID)
	select {
	case leaseLock <- struct{}{}:
	case <-ctx.Done():
		return "", false, ctx.Err()
	}
	defer func() { <-leaseLock }()
	a.proxyMu.Lock()
	lease, hasLease := a.proxyLeases[accountID]
	a.proxyMu.Unlock()

	if hasLease && lease.SettingUpdatedAt == setting.UpdatedAt && lease.Value != "" {
		if time.Since(lease.LastVerifiedAt) < proxyProbeInterval {
			return lease.Value, false, nil
		}

		probeCtx, cancelProbe := context.WithTimeout(ctx, proxyProbeTimeout)
		probe, probeErr := a.probeProxyExit(probeCtx, lease.Value)
		cancelProbe()

		if probeErr == nil && probe.IP != "" {
			a.proxyMu.Lock()
			lease.LastVerifiedAt = time.Now()
			a.proxyLeases[accountID] = lease
			a.proxyMu.Unlock()
			return lease.Value, false, nil
		}

		log.Printf("[proxy] 账号 %d 缓存代理已失效 (probeErr=%v)，即将重新提取", accountID, probeErr)
		a.proxyMu.Lock()
		delete(a.proxyLeases, accountID)
		a.proxyMu.Unlock()
	}

	proxyValue, err := a.resolveProxySpec(ctx, spec)
	a.proxyMu.Lock()
	defer a.proxyMu.Unlock()
	if err == nil && proxyValue != "" {
		a.proxyLeases[accountID] = accountProxyLease{
			Value:            proxyValue,
			SettingUpdatedAt: setting.UpdatedAt,
			LastVerifiedAt:   time.Now(),
		}
	} else {
		delete(a.proxyLeases, accountID)
	}
	return proxyValue, false, err
}

func (a *App) proxyLeaseLockFor(accountID int64) chan struct{} {
	a.proxyLeaseLocksMu.Lock()
	defer a.proxyLeaseLocksMu.Unlock()
	if lock := a.proxyLeaseLocks[accountID]; lock != nil {
		return lock
	}
	lock := make(chan struct{}, 1)
	a.proxyLeaseLocks[accountID] = lock
	return lock
}

func (a *App) invalidateProxyLease(accountID int64) {
	a.proxyMu.Lock()
	delete(a.proxyLeases, accountID)
	a.proxyMu.Unlock()
}

func (a *App) qrClientForSpec(ctx context.Context, spec proxysource.Spec) (*qr.Client, string, error) {
	resolved, err := a.resolveProxySpec(ctx, spec)
	if err != nil {
		return nil, "", err
	}
	if resolved == "" {
		return a.qr, "", nil
	}
	client, err := qr.NewClientWithProxy(a.cfg.RequestTimeout, resolved, false)
	if err != nil {
		return nil, "", fmt.Errorf("创建代理客户端失败: %w", err)
	}
	return client, resolved, nil
}

func (a *App) saveAccountProxyInput(ctx context.Context, accountID int64, body accountProxyIn, normalized proxysource.Spec) (*store.AccountProxySetting, error) {
	refreshAheadSeconds := body.RefreshAheadMinutes * 60
	apiURL := normalized.APIURL
	if body.ProviderProfileID != nil {
		apiURL = ""
	}
	return a.db.UpsertAccountProxySetting(ctx, accountID, normalized.Mode, normalized.ProxyType,
		normalized.StaticProxy, apiURL, body.ProviderProfileID,
		strings.TrimSpace(body.RegionCode), strings.TrimSpace(body.RegionProvince), strings.TrimSpace(body.RegionCity),
		refreshAheadSeconds, body.ProtocolProxyMode)
}

func (a *App) accountExistsBeforeScan(ctx context.Context, openID string) (bool, error) {
	_, err := a.db.GetAccountByOpenID(ctx, openID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (a *App) saveNewAccountProxy(ctx context.Context, accountID int64, existed bool, body accountProxyIn, normalized proxysource.Spec) error {
	if existed {
		return nil
	}
	_, err := a.saveAccountProxyInput(ctx, accountID, body, normalized)
	return err
}
