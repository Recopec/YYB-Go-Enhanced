package httpapi

import (
	"net/http"
	"strings"
)

// The two provider channels look similar in the UI but have different
// contracts: Pinzan is configured by pasting a complete extraction link the
// account already owns (the link carries package parameters such as `minute`),
// while Juliange is configured by a package number plus an API key and the
// server re-signs every extraction. Keeping that contract in one table stops
// the form copy, the validators and the URL builders from drifting apart.
type proxyProviderAuthMode struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Note  string `json:"note"`
}

type proxyCredentialField struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder"`
	Help        string `json:"help"`
}

type proxyProviderSpec struct {
	ID             string                  `json:"id"`
	Label          string                  `json:"label"`
	CredentialKind string                  `json:"credential_kind"` // link | trade_key | address
	Fields         []proxyCredentialField  `json:"fields"`
	AuthModes      []proxyProviderAuthMode `json:"auth_modes"`
	// ManagedParams are query parameters the server rewrites on every
	// extraction. Everything else in a pasted link is preserved verbatim so
	// package-specific switches keep working.
	ManagedParams []string `json:"managed_params"`
}

func proxyProviderSpecs() []proxyProviderSpec {
	return []proxyProviderSpec{
		{
			ID:             "ipzan",
			Label:          "品赞",
			CredentialKind: "link",
			Fields: []proxyCredentialField{{
				Key:         "api_url",
				Label:       "品赞提取链接",
				Placeholder: "https://service.ipzan.com/core-extract?no=…&secret=…&minute=5",
				Help:        "整条粘贴后台给出的提取链接。系统只改写 num/format/protocol/area，minute 等套餐自身参数会原样保留；缺少 minute 的隧道/长效套餐会提取失败。",
			}},
			AuthModes: []proxyProviderAuthMode{
				{Value: "auth", Label: "账号密码（推荐）", Note: "品赞账号密码模式会读取临时代理账号，不依赖本地公网 IP；按账号独立选择省市。"},
				{Value: "whitelist", Label: "出口 IP 白名单", Note: "品赞白名单模式：需在品赞后台将当前机器的公网 IP 加入白名单。"},
			},
			ManagedParams: []string{"num", "format", "protocol", "mode", "area"},
		},
		{
			ID:             "juliang",
			Label:          "巨量",
			CredentialKind: "trade_key",
			Fields: []proxyCredentialField{
				{
					Key:         "trade_no",
					Label:       "巨量业务编号 / 提取链接",
					Placeholder: "业务编号（如 6278393975360688）或整条提取链接",
					Help:        "可直接粘贴后台整条提取链接，系统会解析出业务编号与密钥。",
				},
				{
					Key:         "api_key",
					Label:       "巨量 API Key（32 位）",
					Placeholder: "在业务页面右侧（API 密钥）复制 32 位 API Key",
					Help:        "巨量每次提取都要按参数重新计算 sign，因此必须保存密钥；链接里的 sign 只对当时那组参数有效。",
				},
			},
			AuthModes: []proxyProviderAuthMode{
				{Value: "whitelist", Label: "自动加白（巨量唯一方式）", Note: "巨量只提供白名单鉴权，没有账号密码模式：程序每次提取自动附加 auto_white=1，把本机外网 IP 实时加入白名单，无需手动维护。"},
			},
			ManagedParams: []string{"trade_no", "num", "pt", "result_type", "ip_remain", "auto_white", "province", "city", "sign"},
		},
		{
			ID:             "static",
			Label:          "静态代理预设",
			CredentialKind: "address",
			Fields: []proxyCredentialField{{
				Key:         "api_url",
				Label:       "静态代理地址",
				Placeholder: "user:pass@127.0.0.1:8080",
				Help:        "原样复用固定出口，可用于账号保活；请确认地址长期有效。",
			}},
			AuthModes: []proxyProviderAuthMode{},
		},
	}
}

func lookupProxyProviderSpec(id string) (proxyProviderSpec, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, spec := range proxyProviderSpecs() {
		if spec.ID == id {
			return spec, true
		}
	}
	return proxyProviderSpec{}, false
}

func (s proxyProviderSpec) allowsAuthMode(mode string) bool {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return true
	}
	for _, allowed := range s.AuthModes {
		if allowed.Value == mode {
			return true
		}
	}
	return false
}

func (s proxyProviderSpec) defaultAuthMode() string {
	if len(s.AuthModes) == 0 {
		return ""
	}
	return s.AuthModes[0].Value
}

// handleProxyProviders serves the contract table so the page can render the
// correct fields, auth choices and warnings instead of hardcoding a second,
// drifting copy of the rules in JavaScript.
func (a *App) handleProxyProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, proxyProviderSpecs())
}
