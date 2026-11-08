package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"yyb_go/internal/qr"
	"yyb_go/internal/store"
)

func TestAccountRepairPreviewAndCleanup(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	app, err := NewApp(Config{ResourceRoot: t.TempDir()})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	defer app.Close()
	unknown := "unknown"
	if _, err = app.db.UpsertAccount(context.Background(), "incomplete-openid", "", nil, nil, nil, nil, nil, &unknown); err != nil {
		t.Fatalf("seed incomplete account: %v", err)
	}
	alive := "alive"
	if _, err = app.db.UpsertAccount(context.Background(), "valid-openid", "buffer", nil, nil, nil, nil, nil, &alive); err != nil {
		t.Fatalf("seed valid account: %v", err)
	}
	handler := app.Handler()

	preview := httptest.NewRecorder()
	previewReq := httptest.NewRequest(http.MethodPost, "/accounts/repair", bytes.NewReader([]byte(`{"confirm":false}`)))
	previewReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(preview, previewReq)
	if preview.Code != http.StatusOK || !bytes.Contains(preview.Body.Bytes(), []byte(`"confirm_required":true`)) {
		t.Fatalf("preview = %d %s", preview.Code, preview.Body.String())
	}

	cleanup := httptest.NewRecorder()
	cleanupReq := httptest.NewRequest(http.MethodPost, "/accounts/repair", bytes.NewReader([]byte(`{"confirm":true}`)))
	cleanupReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(cleanup, cleanupReq)
	if cleanup.Code != http.StatusOK {
		t.Fatalf("cleanup = %d %s", cleanup.Code, cleanup.Body.String())
	}
	var envelope struct {
		Code int `json:"code"`
		Data struct {
			RemovedCount int     `json:"removed_count"`
			RemovedIDs   []int64 `json:"removed_ids"`
		} `json:"data"`
	}
	if err := json.Unmarshal(cleanup.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode cleanup: %v", err)
	}
	if envelope.Code != 0 || envelope.Data.RemovedCount != 1 || len(envelope.Data.RemovedIDs) != 1 {
		t.Fatalf("cleanup body = %#v", envelope)
	}
	if _, err := app.db.GetAccountByOpenID(context.Background(), "valid-openid"); err != nil {
		t.Fatalf("valid account missing after cleanup: %v", err)
	}
}

func TestAccountRepairDoesNotDeleteAccountChangedAfterPreview(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	unknown := "unknown"
	account, err := db.UpsertAccount(ctx, "race-openid", "", nil, nil, nil, nil, nil, &unknown)
	if err != nil {
		t.Fatalf("seed account: %v", err)
	}
	alive := "alive"
	if _, err = db.UpsertAccount(ctx, "race-openid", "new-buffer", nil, nil, nil, nil, nil, &alive); err != nil {
		t.Fatalf("update account: %v", err)
	}
	removed, err := db.DeleteIncompleteAccounts(ctx, []int64{account.ID})
	if err != nil || len(removed) != 0 {
		t.Fatalf("removed changed account = %#v, err = %v", removed, err)
	}
}

func TestDropQRSessionMarksCancelled(t *testing.T) {
	app := &App{qrSessions: map[string]*qrLoginSession{}}
	login := &qrLoginSession{}
	app.qrSessions["old-session"] = login

	app.dropQRSession("old-session")

	login.mu.Lock()
	cancelled := login.cancelled
	login.mu.Unlock()
	if !cancelled {
		t.Fatal("dropQRSession() did not mark the session cancelled")
	}
	if app.getQRSession("old-session") != nil {
		t.Fatal("dropQRSession() left the session in the active map")
	}
}

func TestPollQRSessionExpiredReturnsExpired(t *testing.T) {
	t.Setenv("GIN_MODE", "test")
	app, err := NewApp(Config{
		ResourceRoot: t.TempDir(),
		QRSessionTTL: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	sess := &qr.Session{
		ID:        "expired-session",
		CreatedAt: time.Now().Add(-10 * time.Minute),
	}
	app.qrSessions["expired-session"] = &qrLoginSession{
		Session: sess,
	}

	handler := app.Handler()
	req := httptest.NewRequest(http.MethodGet, "/qr/expired-session/poll", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}
	var res map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	data, ok := res["data"].(map[string]any)
	if !ok || data["status"] != "expired" {
		t.Fatalf("expected data.status expired, got %v", res)
	}
	if app.getQRSession("expired-session") != nil {
		t.Fatal("expected expired session to be dropped from qrSessions")
	}
}
