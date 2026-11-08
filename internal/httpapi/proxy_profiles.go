package httpapi

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"yyb_go/internal/proxysource"
	"yyb_go/internal/store"
)

const ipzanHost = "service.ipzan.com"

const (
	juliangProfileScheme   = "juliang"
	juliangAPIEndpoint     = "http://v2.api.juliangip.com/company/dynamic/getips"
	juliangPostpayEndpoint = "http://v2.api.juliangip.com/company/postpay/getips"
)

func juliangEndpointForTradeNo(tradeNo string) string {
	clean := strings.TrimSpace(tradeNo)
	if strings.HasPrefix(clean, "6") {
		return juliangPostpayEndpoint
	}
	return juliangAPIEndpoint
}

func juliangEndpointForTrade(tradeNo, customEndpoint string) string {
	if customEndpoint != "" {
		return customEndpoint
	}
	return juliangEndpointForTradeNo(tradeNo)
}

// parseJuliangExtractionURL pulls the package number and signing key out of a
// pasted extraction link. Juliange has no account/password variant, so a link
// never carries an authentication mode worth preserving.
func parseJuliangExtractionURL(raw string) (tradeNo, apiKey, endpoint string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", ""
	}
	q := u.Query()
	tradeNo = strings.TrimSpace(q.Get("trade_no"))
	apiKey = strings.TrimSpace(q.Get("key"))
	if strings.Contains(u.Host, "juliangip.com") && strings.HasSuffix(u.Path, "/getips") {
		cleanU := &url.URL{Scheme: "http", Host: u.Host, Path: u.Path}
		endpoint = cleanU.String()
	}
	return
}

var (
	ipzanProvinceAreasEndpoint = "https://service.ipzan.com/area-get-province"
	ipzanCityAreasEndpoint     = "https://service.ipzan.com/area-find-citys?province="
)

type proxyProfileIn struct {
	Name              string `json:"name"`
	Provider          string `json:"provider"`
	ProxyType         string `json:"proxy_type"`
	APIURL            string `json:"api_url"`
	AuthorizationMode string `json:"authorization_mode"`
	TradeNo           string `json:"trade_no"`
	APIKey            string `json:"api_key"`
}

type proxyArea struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

func (a *App) handleProxyProfiles(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/proxy-profiles"), "/")
	if path == "providers" {
		a.handleProxyProviders(w, r)
		return
	}
	if path == "areas/provinces" {
		a.handleProxyProvinces(w, r)
		return
	}
	if path == "areas/cities" {
		province := strings.TrimSpace(r.URL.Query().Get("province"))
		if len(province) != 6 || !digitsOnly(province) {
			writeError(w, http.StatusBadRequest, "province must be a 6-digit area code")
			return
		}
		a.handleProxyCities(w, r, province)
		return
	}
	if path == "areas/all" {
		a.handleProxyAreasAll(w, r)
		return
	}
	if path == "" {
		a.handleProxyProfileCollection(w, r)
		return
	}
	id, err := strconv.ParseInt(path, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusNotFound, "proxy profile not found")
		return
	}
	a.handleProxyProfileItem(w, r, id)
}

func (a *App) handleProxyProfileCollection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && a.auth != nil && !requireAdmin(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		profiles, err := a.db.ListProxyProviderProfiles(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, profiles)
	case http.MethodPost:
		body, ok := decodeProxyProfile(w, r)
		if !ok {
			return
		}
		profile, err := a.db.CreateProxyProviderProfile(r.Context(), body.Name, body.Provider, body.ProxyType, body.APIURL)
		if err != nil {
			writeProxyProfileStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, profile)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleProxyProfileItem(w http.ResponseWriter, r *http.Request, id int64) {
	if a.auth != nil && !requireAdmin(w, r) {
		return
	}
	switch r.Method {
	case http.MethodPut:
		body, ok := decodeProxyProfile(w, r)
		if !ok {
			return
		}
		profile, err := a.db.UpdateProxyProviderProfile(r.Context(), id, body.Name, body.Provider, body.ProxyType, body.APIURL)
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "proxy profile not found")
			return
		}
		if err != nil {
			writeProxyProfileStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, profile)
	case http.MethodDelete:
		count, err := a.db.CountAccountsUsingProxyProfile(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if count > 0 {
			writeError(w, http.StatusConflict, fmt.Sprintf("该配置仍被 %d 个账号使用，请先切换这些账号", count))
			return
		}
		if _, err := a.db.GetProxyProviderProfile(r.Context(), id); errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "proxy profile not found")
			return
		} else if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := a.db.DeleteProxyProviderProfile(r.Context(), id); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func decodeProxyProfile(w http.ResponseWriter, r *http.Request) (proxyProfileIn, bool) {
	var body proxyProfileIn
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return proxyProfileIn{}, false
	}
	body.Name = strings.TrimSpace(body.Name)
	body.Provider = strings.ToLower(strings.TrimSpace(body.Provider))
	body.ProxyType = strings.ToLower(strings.TrimSpace(body.ProxyType))
	body.AuthorizationMode = strings.ToLower(strings.TrimSpace(body.AuthorizationMode))
	if body.Provider == "" {
		body.Provider = "ipzan"
	}
	if body.ProxyType == "" {
		body.ProxyType = "http"
	}
	if body.Name == "" || len([]rune(body.Name)) > 50 {
		writeError(w, http.StatusBadRequest, "配置名称不能为空且不能超过 50 个字符")
		return proxyProfileIn{}, false
	}
	spec, ok := lookupProxyProviderSpec(body.Provider)
	if !ok {
		writeError(w, http.StatusBadRequest, "代理配置类型必须为 static、ipzan 或 juliang")
		return proxyProfileIn{}, false
	}
	if !spec.allowsAuthMode(body.AuthorizationMode) {
		writeError(w, http.StatusBadRequest, spec.Label+"不支持该授权方式："+body.AuthorizationMode)
		return proxyProfileIn{}, false
	}
	if body.AuthorizationMode == "" {
		body.AuthorizationMode = spec.defaultAuthMode()
	}
	var apiURL string
	var err error
	switch body.Provider {
	case "ipzan":
		apiURL, err = normalizeIPZanURL(body.APIURL, body.ProxyType, body.AuthorizationMode)
	case "juliang":
		apiURL, err = normalizeJuliangProfile(body.APIURL, body.TradeNo, body.APIKey)
	case "static":
		var normalized proxysource.Spec
		normalized, err = proxysource.NormalizeSpec(proxysource.Spec{
			Mode: "static", ProxyType: body.ProxyType, StaticProxy: body.APIURL,
		})
		if err == nil {
			apiURL = normalized.StaticProxy
		}
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return proxyProfileIn{}, false
	}
	body.APIURL = apiURL
	return body, true
}

func normalizeJuliangProfile(raw, tradeNo, apiKey string) (string, error) {
	tradeNo = strings.TrimSpace(tradeNo)
	apiKey = strings.TrimSpace(apiKey)

	var customEndpoint string

	if parsedTradeNo, parsedKey, parsedEndpoint := parseJuliangExtractionURL(tradeNo); parsedTradeNo != "" {
		tradeNo = parsedTradeNo
		if apiKey == "" && parsedKey != "" {
			apiKey = parsedKey
		}
		if parsedEndpoint != "" {
			customEndpoint = parsedEndpoint
		}
	}

	if tradeNo == "" || apiKey == "" {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err == nil {
			if u.Scheme == juliangProfileScheme && u.Host == "company" && u.Path == "/dynamic" {
				query := u.Query()
				if tradeNo == "" {
					tradeNo = strings.TrimSpace(query.Get("trade_no"))
				}
				if apiKey == "" {
					apiKey = strings.TrimSpace(query.Get("key"))
				}
				if customEndpoint == "" {
					customEndpoint = strings.TrimSpace(query.Get("endpoint"))
				}
			} else if parsedTradeNo, parsedKey, parsedEndpoint := parseJuliangExtractionURL(raw); parsedTradeNo != "" {
				if tradeNo == "" {
					tradeNo = parsedTradeNo
				}
				if apiKey == "" && parsedKey != "" {
					apiKey = parsedKey
				}
				if customEndpoint == "" && parsedEndpoint != "" {
					customEndpoint = parsedEndpoint
				}
			}
		}
	}
	if len(tradeNo) < 8 || len(tradeNo) > 32 || !digitsOnly(tradeNo) {
		return "", fmt.Errorf("巨量业务编号必须为 8 到 32 位数字")
	}
	if len(apiKey) != 32 || !alphaNumOnly(apiKey) {
		return "", fmt.Errorf("巨量 API Key 必须为 32 位字符")
	}
	// Juliange's only authentication mechanism is IP whitelisting: there is no
	// account/password variant, so profiles (including ones stored by older
	// builds) always normalize back to whitelist.
	authorizationMode := "whitelist"
	u := &url.URL{Scheme: juliangProfileScheme, Host: "company", Path: "/dynamic"}
	query := u.Query()
	query.Set("trade_no", tradeNo)
	query.Set("key", strings.ToLower(apiKey))
	query.Set("mode", authorizationMode)
	if customEndpoint != "" {
		query.Set("endpoint", customEndpoint)
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func normalizeIPZanURL(raw, proxyType, authorizationMode string) (string, error) {
	if proxyType != "http" && proxyType != "socks5" {
		return "", fmt.Errorf("代理类型必须为 http 或 socks5")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), ipzanHost) || u.Port() != "" || u.User != nil || u.Path != "/core-extract" {
		return "", fmt.Errorf("请填写 service.ipzan.com/core-extract 的 HTTPS 提取链接")
	}
	query := u.Query()
	if strings.TrimSpace(query.Get("no")) == "" || strings.TrimSpace(query.Get("secret")) == "" {
		return "", fmt.Errorf("品赞提取链接必须包含 no 和 secret")
	}
	query.Del("area")
	query.Set("num", "1")
	if authorizationMode == "" {
		if strings.EqualFold(strings.TrimSpace(query.Get("mode")), "auth") {
			authorizationMode = "auth"
		} else {
			authorizationMode = "whitelist"
		}
	}
	switch authorizationMode {
	case "auth":
		query.Set("mode", "auth")
		query.Set("format", "json")
	case "whitelist":
		query.Del("mode")
	default:
		return "", fmt.Errorf("品赞授权方式必须为 whitelist 或 auth")
	}
	if strings.TrimSpace(query.Get("format")) == "" {
		query.Set("format", "json")
	}
	if proxyType == "socks5" {
		query.Set("protocol", "3")
	} else {
		query.Set("protocol", "1")
	}
	u.RawQuery = query.Encode()
	u.Fragment = ""
	return u.String(), nil
}

func ipzanURLForRegion(profile *store.ProxyProviderProfile, regionCode string) (string, error) {
	base, err := normalizeIPZanURL(profile.APIURL, profile.ProxyType, profile.AuthorizationMode)
	if err != nil {
		return "", err
	}
	u, _ := url.Parse(base)
	query := u.Query()
	regionCode = strings.TrimSpace(regionCode)
	if regionCode != "" && regionCode != "all" {
		if len(regionCode) != 6 || !digitsOnly(regionCode) {
			return "", fmt.Errorf("品赞地区编码必须为 6 位数字")
		}
		query.Set("area", regionCode)
	} else {
		query.Del("area")
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func juliangURLForRegion(profile *store.ProxyProviderProfile, province, city string) (string, error) {
	internalURL, err := normalizeJuliangProfile(profile.APIURL, "", "")
	if err != nil {
		return "", err
	}
	u, _ := url.Parse(internalURL)
	profileQuery := u.Query()
	params := map[string]string{
		"trade_no":    profileQuery.Get("trade_no"),
		"num":         "1",
		"pt":          "1",
		"result_type": "json2",
		"ip_remain":   "1",
		// Juliange offers whitelist authentication only; there is no
		// account/password mode, so every extraction auto-adds the current
		// egress IP instead of requesting temporary credentials.
		"auto_white": "1",
	}
	if strings.EqualFold(profile.ProxyType, "socks5") {
		params["pt"] = "2"
	}
	if province = normalizeRegionName(province); province != "" {
		params["province"] = province
	}
	if city = normalizeRegionName(city); city != "" {
		params["city"] = city
	}
	params["sign"] = juliangSign(params, profileQuery.Get("key"))
	endpoint, _ := url.Parse(juliangEndpointForTrade(params["trade_no"], profileQuery.Get("endpoint")))
	query := endpoint.Query()
	for key, value := range params {
		query.Set(key, value)
	}
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

func proxyProfileURLForRegion(profile *store.ProxyProviderProfile, regionCode, province, city string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(profile.Provider)) {
	case "ipzan", "":
		return ipzanURLForRegion(profile, regionCode)
	case "juliang":
		return juliangURLForRegion(profile, province, city)
	default:
		return "", fmt.Errorf("不支持的代理供应商: %s", profile.Provider)
	}
}

func normalizeRegionName(value string) string {
	value = strings.TrimSpace(value)
	suffixes := []string{
		"哈尼族彝族自治州", "壮族苗族自治州", "苗族侗族自治州", "土家族苗族自治州",
		"布依族苗族自治州", "蒙古族藏族自治州", "藏族羌族自治州", "傣族景颇族自治州",
		"白族自治州", "傣族自治州", "彝族自治州", "藏族自治州", "回族自治州",
		"哈萨克自治州", "蒙古自治州", "柯尔克孜自治州", "傈僳族自治州", "朝鲜族自治州",
		"壮族自治区", "回族自治区", "维吾尔自治区", "特别行政区", "自治区",
		"自治州", "地区", "特区", "林区", "盟", "省", "市",
	}
	for _, suffix := range suffixes {
		if strings.HasSuffix(value, suffix) && len(value) > len(suffix) {
			value = strings.TrimSuffix(value, suffix)
			break
		}
	}
	return value
}

func juliangSign(params map[string]string, apiKey string) string {
	keys := make([]string, 0, len(params))
	for key := range params {
		if key != "sign" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys)+1)
	for _, key := range keys {
		parts = append(parts, key+"="+params[key])
	}
	parts = append(parts, "key="+apiKey)
	sum := md5.Sum([]byte(strings.Join(parts, "&")))
	return fmt.Sprintf("%x", sum)
}

func (a *App) normalizeAccountProxyInput(ctx context.Context, body accountProxyIn) (accountProxyIn, proxysource.Spec, error) {
	if body.ProtocolProxyMode != nil && *body.ProtocolProxyMode != store.ProtocolProxyModeAccount && *body.ProtocolProxyMode != store.ProtocolProxyModeDirect {
		return accountProxyIn{}, proxysource.Spec{}, fmt.Errorf("小程序调用出口必须为 account（跟随账号）或 direct（直连）")
	}
	body.RegionCode = strings.TrimSpace(body.RegionCode)
	body.RegionProvince = strings.TrimSpace(body.RegionProvince)
	body.RegionCity = strings.TrimSpace(body.RegionCity)
	if body.RefreshAheadMinutes == 0 {
		body.RefreshAheadMinutes = store.DefaultProxyRefreshAheadSeconds / 60
	}
	if body.RefreshAheadMinutes < 5 || body.RefreshAheadMinutes > 90 {
		return accountProxyIn{}, proxysource.Spec{}, fmt.Errorf("代理账号提前刷新时间必须在 5 到 90 分钟之间")
	}
	if body.ProviderProfileID != nil {
		profile, err := a.db.GetProxyProviderProfile(ctx, *body.ProviderProfileID)
		if errors.Is(err, sql.ErrNoRows) {
			return accountProxyIn{}, proxysource.Spec{}, fmt.Errorf("品赞代理配置不存在")
		}
		if err != nil {
			return accountProxyIn{}, proxysource.Spec{}, err
		}
		profileMode := "api"
		profileValue := ""
		if strings.EqualFold(profile.Provider, "static") {
			profileMode = "static"
			profileValue = profile.APIURL
		} else {
			apiURL, err := proxyProfileURLForRegion(profile, body.RegionCode, body.RegionProvince, body.RegionCity)
			if err != nil {
				return accountProxyIn{}, proxysource.Spec{}, err
			}
			profileValue = apiURL
		}
		body.Mode = profileMode
		body.ProxyType = profile.ProxyType
		body.StaticProxy = ""
		body.APIURL = ""
		profileSpec := proxysource.Spec{Mode: profileMode, ProxyType: profile.ProxyType}
		if profileMode == "static" {
			profileSpec.StaticProxy = profileValue
		} else {
			profileSpec.APIURL = profileValue
		}
		normalized, err := proxysource.NormalizeSpec(profileSpec)
		return body, normalized, err
	}
	normalized, err := proxysource.NormalizeSpec(body.spec())
	return body, normalized, err
}

func (a *App) proxySpecForSetting(ctx context.Context, setting *store.AccountProxySetting) (proxysource.Spec, error) {
	if setting == nil || setting.ProviderProfileID == nil {
		return proxysource.NormalizeSpec(proxySpecFromSetting(setting))
	}
	profile, err := a.db.GetProxyProviderProfile(ctx, *setting.ProviderProfileID)
	if err != nil {
		return proxysource.Spec{}, err
	}
	if strings.EqualFold(profile.Provider, "static") {
		return proxysource.NormalizeSpec(proxysource.Spec{Mode: "static", ProxyType: profile.ProxyType, StaticProxy: profile.APIURL})
	}
	apiURL, err := proxyProfileURLForRegion(profile, setting.RegionCode, setting.RegionProvince, setting.RegionCity)
	if err != nil {
		return proxysource.Spec{}, err
	}
	return proxysource.NormalizeSpec(proxysource.Spec{Mode: "api", ProxyType: profile.ProxyType, APIURL: apiURL})
}

func (a *App) handleProxyProvinces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if ipzanProvinceAreasEndpoint != "https://service.ipzan.com/area-get-province" {
		a.handleIPZanAreas(w, r, ipzanProvinceAreasEndpoint)
		return
	}
	data, err := a.getPersistedProxyAreas(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取地区数据失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, data.Provinces)
}

func (a *App) handleProxyCities(w http.ResponseWriter, r *http.Request, province string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if ipzanCityAreasEndpoint != "https://service.ipzan.com/area-find-citys?province=" {
		a.handleIPZanAreas(w, r, ipzanCityAreasEndpoint+url.QueryEscape(province))
		return
	}
	data, err := a.getPersistedProxyAreas(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取城市数据失败: "+err.Error())
		return
	}
	cities := data.Cities[province]
	if cities == nil {
		cities = []proxyArea{}
	}
	writeJSON(w, http.StatusOK, cities)
}

func (a *App) handleProxyAreasAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	data, err := a.getPersistedProxyAreas(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取地区数据失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, data)
}

func (a *App) handleIPZanAreas(w http.ResponseWriter, r *http.Request, endpoint string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	areas, err := a.fetchProxyAreas(r.Context(), endpoint)
	if err != nil {
		writeError(w, http.StatusBadGateway, "读取品赞地区失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, areas)
}

func (a *App) fetchProxyAreas(ctx context.Context, endpoint string) ([]proxyArea, error) {
	if endpoint == "https://service.ipzan.com/area-get-province" {
		data, err := a.getPersistedProxyAreas(ctx)
		if err == nil {
			return data.Provinces, nil
		}
	} else if strings.HasPrefix(endpoint, "https://service.ipzan.com/area-find-citys?province=") {
		code := strings.TrimPrefix(endpoint, "https://service.ipzan.com/area-find-citys?province=")
		data, err := a.getPersistedProxyAreas(ctx)
		if err == nil {
			if cities, ok := data.Cities[code]; ok {
				return cities, nil
			}
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: a.cfg.RequestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("品赞地区接口返回 HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Data []proxyArea `json:"data"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("无法解析品赞地区响应")
	}
	return payload.Data, nil
}

func writeProxyProfileStoreError(w http.ResponseWriter, err error) {
	if strings.Contains(strings.ToLower(err.Error()), "unique") {
		writeError(w, http.StatusConflict, "代理配置名称已存在")
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}

func digitsOnly(value string) bool {
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return value != ""
}

func alphaNumOnly(value string) bool {
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') {
			return false
		}
	}
	return len(value) > 0
}
