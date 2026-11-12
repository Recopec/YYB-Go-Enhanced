package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"yyb_go/internal/auth"
)

func TestAccountOwnersListsClaimsForAdminsOnly(t *testing.T) {
	root := t.TempDir()
	app, err := NewApp(Config{
		ResourceRoot:   root,
		RequestTimeout: time.Second,
		SessionTTL:     time.Minute,
		AuthDriver:     "sqlite",
		AuthDSN:        filepath.Join(root, "auth.db"),
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	t.Cleanup(func() { _ = app.Close() })
	ctx := context.Background()
	admin, err := app.auth.CreateUser(ctx, "admin_yyb", "Admin", "Passw0rd!!xx", "admin")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := app.auth.CreateUser(ctx, "gy_yyb", "gy", "Passw0rd!!xx", "user")
	if err != nil {
		t.Fatal(err)
	}
	status := "alive"
	account, err := app.db.UpsertAccount(ctx, "owner-openid", "buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.auth.ClaimAccount(ctx, account.ID, owner.ID); err != nil {
		t.Fatal(err)
	}

	get := func(user *auth.User) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/accounts/owners", nil)
		req = req.WithContext(context.WithValue(req.Context(), authUserKey, user))
		w := httptest.NewRecorder()
		app.handleAccountOwners(w, req)
		return w
	}

	w := get(admin)
	if w.Code != http.StatusOK {
		t.Fatalf("admin status = %d, body = %s", w.Code, w.Body.String())
	}
	var envelope struct {
		Data struct {
			Owners []struct {
				AccountID   int64  `json:"account_id"`
				UserID      int64  `json:"user_id"`
				Username    string `json:"username"`
				DisplayName string `json:"display_name"`
			} `json:"owners"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(envelope.Data.Owners) != 1 {
		t.Fatalf("owners = %+v", envelope.Data.Owners)
	}
	got := envelope.Data.Owners[0]
	if got.AccountID != account.ID || got.UserID != owner.ID || got.Username != "gy_yyb" || got.DisplayName != "gy" {
		t.Fatalf("owner row = %+v", got)
	}

	if w := get(owner); w.Code != http.StatusForbidden {
		t.Fatalf("regular user status = %d, want 403", w.Code)
	}
}

func TestAccountOwnerUpdateMovesTheClaim(t *testing.T) {
	root := t.TempDir()
	app, err := NewApp(Config{
		ResourceRoot:   root,
		RequestTimeout: time.Second,
		SessionTTL:     time.Minute,
		AuthDriver:     "sqlite",
		AuthDSN:        filepath.Join(root, "auth.db"),
	})
	if err != nil {
		t.Fatalf("NewApp() error = %v", err)
	}
	t.Cleanup(func() { _ = app.Close() })
	ctx := context.Background()
	admin, _ := app.auth.CreateUser(ctx, "admin_yyb", "Admin", "Passw0rd!!xx", "admin")
	first, _ := app.auth.CreateUser(ctx, "ppx_yyb", "ppx", "Passw0rd!!xx", "user")
	second, _ := app.auth.CreateUser(ctx, "wang_yyb", "wang", "Passw0rd!!xx", "user")
	status := "alive"
	account, err := app.db.UpsertAccount(ctx, "ga-openid", "buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.auth.ClaimAccount(ctx, account.ID, first.ID); err != nil {
		t.Fatal(err)
	}
	post := func(user *auth.User, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/accounts/owner", strings.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), authUserKey, user))
		w := httptest.NewRecorder()
		app.handleAccountOwnerUpdate(w, req)
		return w
	}
	move := `{"ref":"` + strconv.FormatInt(account.ID, 10) + `","user_id":` + strconv.FormatInt(second.ID, 10) + `}`

	if w := post(first, move); w.Code != http.StatusForbidden {
		t.Fatalf("a regular user moved a claim: %d %s", w.Code, w.Body.String())
	}
	if owner, _ := app.auth.AccountOwner(ctx, account.ID); owner != first.ID {
		t.Fatalf("refused request changed the claim to %d", owner)
	}
	if w := post(admin, move); w.Code != http.StatusOK {
		t.Fatalf("admin transfer answered %d: %s", w.Code, w.Body.String())
	}
	if owner, err := app.auth.AccountOwner(ctx, account.ID); err != nil || owner != second.ID {
		t.Fatalf("claim did not move: owner=%d err=%v", owner, err)
	}
	// Repeating the same transfer is a no-op, not an error.
	if w := post(admin, move); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"changed":false`) {
		t.Fatalf("repeated transfer answered %d: %s", w.Code, w.Body.String())
	}
	if w := post(admin, `{"ref":"`+strconv.FormatInt(account.ID, 10)+`","user_id":9999}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown target user answered %d: %s", w.Code, w.Body.String())
	}
	// An unowned account can be claimed the same way.
	bare, err := app.db.UpsertAccount(ctx, "ga-bare", "buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatal(err)
	}
	if w := post(admin, `{"ref":"`+strconv.FormatInt(bare.ID, 10)+`","user_id":`+strconv.FormatInt(first.ID, 10)+`}`); w.Code != http.StatusOK {
		t.Fatalf("unowned account transfer answered %d: %s", w.Code, w.Body.String())
	}
	if owner, err := app.auth.AccountOwner(ctx, bare.ID); err != nil || owner != first.ID {
		t.Fatalf("unowned account was not claimed: owner=%d err=%v", owner, err)
	}
	// A fleet member keeps one owner: moving it would split the fleet across users.
	if err := app.db.SetAccountFleet(ctx, account.ID, account.ID); err != nil {
		t.Fatal(err)
	}
	if w := post(admin, `{"ref":"`+strconv.FormatInt(account.ID, 10)+`","user_id":`+strconv.FormatInt(first.ID, 10)+`}`); w.Code != http.StatusConflict {
		t.Fatalf("fleet account transfer answered %d: %s", w.Code, w.Body.String())
	}
	if owner, _ := app.auth.AccountOwner(ctx, account.ID); owner != second.ID {
		t.Fatalf("refused fleet transfer changed the claim to %d", owner)
	}
}
