package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/degovan/degoploy/internal/audit"
	"github.com/degovan/degoploy/internal/auth"
	"github.com/degovan/degoploy/internal/config"
	"github.com/degovan/degoploy/internal/httpx"
	"github.com/degovan/degoploy/internal/store"
)

// inviteTTL is how long an invite link stays valid; renewing starts it over.
const inviteTTL = 7 * 24 * time.Hour

// maxInvites caps the addresses in one request.
const maxInvites = 50

func (a *API) registerInvites(mux *http.ServeMux) {
	need := func(fn http.HandlerFunc) http.Handler {
		return auth.RequireAuth(a.authz.Require(auth.ActionUserManage, fn))
	}
	mux.Handle("GET /api/v1/invites", need(a.listInvites))
	mux.Handle("POST /api/v1/invites", need(a.createInvites))
	mux.Handle("POST /api/v1/invites/{iid}/renew", need(a.renewInvite))
	mux.Handle("DELETE /api/v1/invites/{iid}", need(a.revokeInvite))
	// Public: the token in the link is the credential.
	mux.HandleFunc("GET /api/v1/auth/invite/{token}", a.previewInvite)
	mux.HandleFunc("POST /api/v1/auth/invite/{token}", a.acceptInvite)
}

func toInvite(inv *store.Invite) Invite {
	return Invite{
		ID: inv.ID, Email: inv.Email, Role: string(inv.Role), InvitedBy: inv.InvitedByName,
		CreatedAt: inv.CreatedAt.UTC().Format(time.RFC3339),
		ExpiresAt: inv.ExpiresAt.UTC().Format(time.RFC3339),
		Expired:   !time.Now().Before(inv.ExpiresAt),
	}
}

// invitesAllowed rejects invites while local login is off: they create password accounts.
func (a *API) invitesAllowed(w http.ResponseWriter) bool {
	if local, _, _ := a.signIn(); !local {
		httpx.Error(w, http.StatusConflict, "local_login_disabled",
			"local login is disabled, so invited users could not sign in")
		return false
	}
	return true
}

// inviteMailer returns the SMTP settings invitations go out with, or answers
// 409 while email is not set up and tested.
func (a *API) inviteMailer(w http.ResponseWriter, r *http.Request) (config.SMTP, bool) {
	ready, s, err := a.emailReady(r)
	if err != nil {
		httpx.InternalError(w, r, err)
		return s, false
	}
	if !ready {
		httpx.Error(w, http.StatusConflict, "email_not_ready",
			"invitations are sent by email: configure SMTP and send a successful test email first")
		return s, false
	}
	return s, true
}

func (a *API) listInvites(w http.ResponseWriter, r *http.Request) {
	invites, err := a.store.ListInvites(r.Context())
	if err != nil {
		httpx.InternalError(w, r, err)
		return
	}
	out := make([]Invite, 0, len(invites))
	for _, inv := range invites {
		out = append(out, toInvite(inv))
	}
	httpx.JSON(w, http.StatusOK, out)
}

func (a *API) createInvites(w http.ResponseWriter, r *http.Request) {
	ident := auth.FromContext(r.Context())
	if !a.invitesAllowed(w) {
		return
	}
	smtp, ok := a.inviteMailer(w, r)
	if !ok {
		return
	}
	var req CreateInvitesRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if !store.Role(req.Role).Valid() {
		validationError(w, "role", "must be admin, deployer or viewer")
		return
	}

	users, err := a.store.ListUsers(r.Context())
	if err != nil {
		httpx.InternalError(w, r, err)
		return
	}
	pending, err := a.store.ListInvites(r.Context())
	if err != nil {
		httpx.InternalError(w, r, err)
		return
	}
	taken := map[string]string{}
	for _, u := range users {
		if u.Email != "" {
			taken[strings.ToLower(u.Email)] = "already has an account"
		}
	}
	for _, inv := range pending {
		taken[strings.ToLower(inv.Email)] = "already has a pending invite"
	}

	// Validate every address before creating any invite.
	var emails []string
	seen := map[string]bool{}
	for _, e := range req.Emails {
		e = strings.TrimSpace(e)
		key := strings.ToLower(e)
		if e == "" || seen[key] {
			continue
		}
		seen[key] = true
		if !validEmail(e) {
			validationError(w, "emails", fmt.Sprintf("%s is not a valid email address", e))
			return
		}
		if why, ok := taken[key]; ok {
			validationError(w, "emails", fmt.Sprintf("%s %s", e, why))
			return
		}
		emails = append(emails, e)
	}
	switch {
	case len(emails) == 0:
		validationError(w, "emails", "add at least one email address")
		return
	case len(emails) > maxInvites:
		validationError(w, "emails", fmt.Sprintf("invite at most %d people at once", maxInvites))
		return
	}

	out := make([]InviteLink, 0, len(emails))
	for _, e := range emails {
		token, hash := auth.NewToken()
		inv := &store.Invite{
			Email: e, Role: store.Role(req.Role), TokenHash: hash, InvitedBy: &ident.User.ID,
			ExpiresAt: time.Now().Add(inviteTTL), InvitedByName: ident.User.Username,
		}
		if err := a.store.CreateInvite(r.Context(), inv); err != nil {
			if errors.Is(err, store.ErrDuplicate) {
				validationError(w, "emails", fmt.Sprintf("%s already has a pending invite", e))
				return
			}
			httpx.InternalError(w, r, err)
			return
		}
		a.recordInvite(r, ident.User.ID, audit.InviteCreate, inv)
		out = append(out, InviteLink{Invite: toInvite(inv), Token: token,
			EmailError: a.sendInvite(r, smtp, ident.User, inv, token)})
	}
	httpx.JSON(w, http.StatusCreated, out)
}

func (a *API) renewInvite(w http.ResponseWriter, r *http.Request) {
	ident := auth.FromContext(r.Context())
	if !a.invitesAllowed(w) {
		return
	}
	smtp, ok := a.inviteMailer(w, r)
	if !ok {
		return
	}
	inv, found := a.loadInvite(w, r)
	if !found {
		return
	}
	token, hash := auth.NewToken()
	inv.TokenHash, inv.ExpiresAt = hash, time.Now().Add(inviteTTL)
	if err := a.store.RenewInvite(r.Context(), inv); err != nil {
		httpx.InternalError(w, r, err)
		return
	}
	a.recordInvite(r, ident.User.ID, audit.InviteRenew, inv)
	httpx.JSON(w, http.StatusOK, InviteLink{Invite: toInvite(inv), Token: token,
		EmailError: a.sendInvite(r, smtp, ident.User, inv, token)})
}

func (a *API) revokeInvite(w http.ResponseWriter, r *http.Request) {
	ident := auth.FromContext(r.Context())
	inv, ok := a.loadInvite(w, r)
	if !ok {
		return
	}
	if err := a.store.DeleteInvite(r.Context(), inv.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		httpx.InternalError(w, r, err)
		return
	}
	a.recordInvite(r, ident.User.ID, audit.InviteRevoke, inv)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) previewInvite(w http.ResponseWriter, r *http.Request) {
	inv, ok := a.inviteByToken(w, r)
	if !ok {
		return
	}
	httpx.JSON(w, http.StatusOK, InvitePreview{
		Email: inv.Email, Role: string(inv.Role), InvitedBy: inv.InvitedByName,
		ExpiresAt: inv.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// acceptInvite creates the invited account and signs it in.
func (a *API) acceptInvite(w http.ResponseWriter, r *http.Request) {
	ip := a.clientIP(r)
	if !a.loginLimiter.Allow(ip) {
		httpx.Error(w, http.StatusTooManyRequests, "rate_limited", "too many attempts, try again later")
		return
	}
	if !a.invitesAllowed(w) {
		return
	}
	inv, ok := a.inviteByToken(w, r)
	if !ok {
		return
	}
	var req AcceptInviteRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if !auth.ValidUsername(req.Username) {
		validationError(w, "username", auth.UsernameRule)
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		validationError(w, "password", err.Error())
		return
	}
	u := &store.User{
		Username: req.Username, Email: inv.Email, DisplayName: firstNonEmpty(req.DisplayName, req.Username),
		AuthProvider: store.ProviderLocal, PasswordHash: hash, Role: inv.Role,
	}
	switch err := a.store.AcceptInvite(r.Context(), inv.ID, u); {
	case errors.Is(err, store.ErrDuplicate):
		validationError(w, "username", "is already taken")
		return
	case errors.Is(err, store.ErrNotFound):
		httpx.Error(w, http.StatusNotFound, "invite_not_found", "this invite link is invalid or was already used")
		return
	case err != nil:
		httpx.InternalError(w, r, err)
		return
	}
	a.audit.Record(r.Context(), audit.Entry{
		UserID: u.ID, Action: audit.InviteAccept, TargetType: "user", TargetID: strconv.FormatInt(u.ID, 10),
		Detail: map[string]any{"username": u.Username, "email": u.Email, "role": u.Role}, IP: ip,
	})

	// Same as a password login from here on.
	if prev := auth.FromContext(r.Context()); prev != nil {
		a.sessions.End(r.Context(), w, prev.Session)
	}
	sess, err := a.sessions.Start(r.Context(), w, r, u, ip)
	if err != nil {
		httpx.InternalError(w, r, err)
		return
	}
	if err := a.store.TouchUserLogin(r.Context(), u.ID); err != nil {
		httpx.InternalError(w, r, err)
		return
	}
	loginAt := time.Now().UTC()
	u.LastLoginAt = &loginAt
	httpx.JSON(w, http.StatusCreated, Me{
		User:        toUser(u),
		CSRFToken:   sess.CSRFToken,
		Permissions: a.permissions(r, u),
		ProjectsDir: a.projects.ProjectsDir(),
	})
}

func (a *API) loadInvite(w http.ResponseWriter, r *http.Request) (*store.Invite, bool) {
	id, err := strconv.ParseInt(r.PathValue("iid"), 10, 64)
	if err != nil {
		httpx.Error(w, http.StatusNotFound, "not_found", "invite not found")
		return nil, false
	}
	inv, err := a.store.InviteByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, "not_found", "invite not found")
		return nil, false
	}
	if err != nil {
		httpx.InternalError(w, r, err)
		return nil, false
	}
	return inv, true
}

// inviteByToken resolves the link token to a pending, unexpired invite.
func (a *API) inviteByToken(w http.ResponseWriter, r *http.Request) (*store.Invite, bool) {
	inv, err := a.store.InviteByTokenHash(r.Context(), auth.HashToken(r.PathValue("token")))
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, "invite_not_found", "this invite link is invalid or was already used")
		return nil, false
	}
	if err != nil {
		httpx.InternalError(w, r, err)
		return nil, false
	}
	if !time.Now().Before(inv.ExpiresAt) {
		httpx.Error(w, http.StatusGone, "invite_expired", "this invite link has expired; ask an admin for a new one")
		return nil, false
	}
	return inv, true
}

func (a *API) recordInvite(r *http.Request, actorID int64, action string, inv *store.Invite) {
	a.audit.Record(r.Context(), audit.Entry{
		UserID: actorID, Action: action, TargetType: "invite", TargetID: strconv.FormatInt(inv.ID, 10),
		Detail: map[string]any{"email": inv.Email, "role": inv.Role}, IP: a.clientIP(r),
	})
}

// inviterName is how invitation emails name the admin who sent them.
func inviterName(u *store.User) string { return firstNonEmpty(u.DisplayName, u.Username) }

// validEmail is a sanity check, not RFC 5322: one @ with text on both sides and no spaces.
func validEmail(e string) bool {
	local, domain, ok := strings.Cut(e, "@")
	return ok && local != "" && domain != "" && !strings.ContainsAny(e, " \t\r\n<>,;") &&
		!strings.Contains(domain, "@")
}
