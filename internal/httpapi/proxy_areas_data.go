package httpapi

import (
	"context"
	_ "embed"
	"encoding/json"
	"sync"
)

//go:embed proxy_areas_baseline.json
var defaultProxyAreasJSON string

type proxyAreasData struct {
	Provinces []proxyArea            `json:"provinces"`
	Cities    map[string][]proxyArea `json:"cities"`
}

var (
	cachedAreasLock sync.RWMutex
	cachedAreas     *proxyAreasData
)

func (a *App) getPersistedProxyAreas(ctx context.Context) (*proxyAreasData, error) {
	cachedAreasLock.RLock()
	if cachedAreas != nil {
		defer cachedAreasLock.RUnlock()
		return cachedAreas, nil
	}
	cachedAreasLock.RUnlock()

	cachedAreasLock.Lock()
	defer cachedAreasLock.Unlock()
	if cachedAreas != nil {
		return cachedAreas, nil
	}

	// 1. Try reading from SQLite app_settings
	if a.db != nil {
		if raw, err := a.db.GetSetting(ctx, "proxy_areas_cache"); err == nil && raw != "" {
			var data proxyAreasData
			if err := json.Unmarshal([]byte(raw), &data); err == nil && len(data.Provinces) > 0 {
				cachedAreas = &data
				return cachedAreas, nil
			}
		}
	}

	// 2. Fall back to embedded baseline data
	var data proxyAreasData
	if err := json.Unmarshal([]byte(defaultProxyAreasJSON), &data); err != nil {
		return nil, err
	}
	cachedAreas = &data

	// Save to SQLite for persistence
	if a.db != nil {
		_ = a.db.SetSetting(ctx, "proxy_areas_cache", defaultProxyAreasJSON)
	}

	return cachedAreas, nil
}
