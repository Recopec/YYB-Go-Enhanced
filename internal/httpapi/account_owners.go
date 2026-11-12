package httpapi

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"yyb_go/internal/auth"
	"yyb_go/internal/eventlog"
)

// handleAccountOwners maps claimed accounts to console users. Ownership lives in
// the auth database, so the account list cannot join it directly; the console
// fetches this map once per account reload. Admin-only: a regular user only ever
// sees their own accounts and has no use for other members' identities.
func (a *App) handleAccountOwners(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !requireAdmin(w, r) {
		return
	}
	if a.auth == nil {
		writeJSON(w, http.StatusOK, map[string]any{"owners": []any{}})
		return
	}
	rows, err := a.auth.AccountOwners(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	users, err := a.auth.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	byID := make(map[int64]auth.User, len(users))
	for _, user := range users {
		byID[user.ID] = user
	}
	owners := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		user, ok := byID[row.UserID]
		if !ok {
			continue
		}
		owners = append(owners, map[string]any{
			"account_id":   row.AccountID,
			"user_id":      user.ID,
			"username":     user.Username,
			"display_name": user.DisplayName,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"owners": owners})
}

// handleAccountOwnerUpdate moves one account's claim to another console user.
// Ownership decides who sees an account, so this is administrator-only, and an
// account that already sits in a fleet is refused: moving one member would leave
// that fleet answering to two users, which is exactly what binding prevents.
func (a *App) handleAccountOwnerUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !requireAdmin(w, r) {
		return
	}
	if a.auth == nil {
		writeError(w, http.StatusConflict, "未启用 Web 用户认证，账号没有归属")
		return
	}
	var body struct {
		Ref    string `json:"ref"`
		UserID int64  `json:"user_id"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	acc, ok := a.resolveAccountRef(w, r, body.Ref)
	if !ok {
		return
	}
	if acc.FleetPrimaryID != nil {
		writeError(w, http.StatusConflict, fmt.Sprintf("账号 %d 在多渠道账号里，请先移出或拆分，再改归属", acc.ID))
		return
	}
	user, err := a.auth.GetUser(r.Context(), body.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusBadRequest, "目标用户不存在")
		return
	}
	if !user.Enabled {
		writeError(w, http.StatusBadRequest, "目标用户已停用")
		return
	}
	current, err := a.auth.AccountOwner(r.Context(), acc.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "读取账号归属失败")
		return
	}
	owner := map[string]any{"user_id": user.ID, "username": user.Username, "display_name": user.DisplayName}
	if current == user.ID {
		writeJSON(w, http.StatusOK, map[string]any{"changed": false, "account_id": acc.ID, "owner": owner})
		return
	}
	if err := a.auth.SetAccountOwner(r.Context(), acc.ID, user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "写入账号归属失败: "+err.Error())
		return
	}
	a.events.Emit("account.owner_changed", eventlog.ForAccount(acc))
	writeJSON(w, http.StatusOK, map[string]any{"changed": true, "account_id": acc.ID, "previous_owner": current, "owner": owner})
}
