package api_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/degovan/degoploy/internal/api"
	"github.com/degovan/degoploy/internal/config"
	"github.com/degovan/degoploy/internal/httpx"
	"github.com/degovan/degoploy/internal/mail/smtptest"
	"github.com/degovan/degoploy/internal/store"
)

func TestInvites(t *testing.T) {
	mailbox := smtptest.New(t)
	srv, st := newTestServerWith(t, func(cfg *config.Config, _ string) {
		cfg.SMTP = config.SMTP{Host: mailbox.Host, Port: mailbox.Port, Encryption: "none",
			FromName: "Degoploy", FromAddress: "no-reply@example.com"}
	})
	createUser(t, st, "admin", "admin-password-1", store.RoleAdmin)
	createUser(t, st, "dep", "deployer-password", store.RoleDeployer)
	admin := login(t, srv.URL, "admin", "admin-password-1")
	dep := login(t, srv.URL, "dep", "deployer-password")
	admin.do("PATCH", "/api/v1/users/1", `{"email":"admin@example.com"}`, nil)

	if code := dep.do("POST", "/api/v1/invites", `{"emails":["x@example.com"],"role":"viewer"}`, nil); code != 403 {
		t.Fatalf("deployer invite: %d", code)
	}

	// Invitations go out by email, so they wait for a delivered test email.
	var e httpx.ErrorBody
	if code := admin.do("POST", "/api/v1/invites", `{"emails":["x@example.com"],"role":"viewer"}`, &e); code != 409 || e.Code != "email_not_ready" {
		t.Fatalf("invite before email test: %d %+v", code, e)
	}
	var es api.EmailStatus
	if code := admin.do("POST", "/api/v1/email/test", `{"to":"admin@example.com"}`, &es); code != 200 || !es.Ready {
		t.Fatalf("test email: %d %+v", code, es)
	}

	for _, c := range []struct{ body, field string }{
		{`{"emails":[],"role":"viewer"}`, "emails"},
		{`{"emails":["nope"],"role":"viewer"}`, "emails"},
		{`{"emails":["ADMIN@example.com"],"role":"viewer"}`, "emails"},
		{`{"emails":["x@example.com"],"role":"owner"}`, "role"},
	} {
		if code := admin.do("POST", "/api/v1/invites", c.body, &e); code != 422 || e.Field != c.field {
			t.Fatalf("invite %s: %d %+v, want 422 on %s", c.body, code, e, c.field)
		}
	}

	// Duplicates within one request collapse; a second invite to the same address is refused.
	var links []api.InviteLink
	if code := admin.do("POST", "/api/v1/invites",
		`{"emails":["fajar@example.com"," sinta@example.com","Fajar@example.com"],"role":"deployer"}`, &links); code != 201 || len(links) != 2 {
		t.Fatalf("create invites: %d %+v", code, links)
	}
	if links[0].Token == "" || links[0].Invite.InvitedBy != "admin" || links[0].Invite.Role != "deployer" || links[0].EmailError != "" {
		t.Fatalf("invite link = %+v", links[0])
	}
	// The test email plus one invitation per person, each with its own link.
	if msgs := mailbox.Messages(); len(msgs) != 3 || msgs[1].To[0] != "fajar@example.com" ||
		!strings.Contains(strings.ReplaceAll(msgs[1].Data, "=\r\n", ""), "/invite/"+links[0].Token) {
		t.Fatalf("invitation emails = %+v", msgs)
	}
	// The invitation says where it comes from, who sent it and why.
	if msgs := mailbox.Messages(); len(msgs) == 3 {
		body := strings.ReplaceAll(msgs[1].Data, "=\r\n", "")
		for _, want := range []string{"admin (admin@example.com) invited you to degoploy on", "<title>Join degoploy on",
			"no account is created until the link is used"} {
			if !strings.Contains(body, want) {
				t.Errorf("invitation lacks %q:\n%s", want, body)
			}
		}
	}
	if code := admin.do("POST", "/api/v1/invites", `{"emails":["sinta@example.com"],"role":"viewer"}`, &e); code != 422 {
		t.Fatalf("re-invite: %d", code)
	}
	var list []api.Invite
	if code := admin.do("GET", "/api/v1/invites", "", &list); code != 200 || len(list) != 2 {
		t.Fatalf("list: %d %+v", code, list)
	}

	// Renewing invalidates the old link.
	fajar := links[0]
	var renewed api.InviteLink
	if code := admin.do("POST", fmt.Sprintf("/api/v1/invites/%d/renew", fajar.Invite.ID), "", &renewed); code != 200 || renewed.Token == fajar.Token {
		t.Fatalf("renew: %d %+v", code, renewed)
	}
	guest := anonymous(t, srv.URL)
	if code := guest.do("GET", "/api/v1/auth/invite/"+fajar.Token, "", nil); code != 404 {
		t.Fatalf("old link: %d", code)
	}
	var preview api.InvitePreview
	if code := guest.do("GET", "/api/v1/auth/invite/"+renewed.Token, "", &preview); code != 200 || preview.Email != "fajar@example.com" {
		t.Fatalf("preview: %d %+v", code, preview)
	}

	// Accepting creates the user, signs them in and uses the link up.
	acceptPath := "/api/v1/auth/invite/" + renewed.Token
	if code := guest.do("POST", acceptPath, `{"username":"dep","password":"fajar-password-1"}`, &e); code != 422 || e.Field != "username" {
		t.Fatalf("taken username: %d %+v", code, e)
	}
	if code := guest.do("POST", acceptPath, `{"username":"fajar","password":"short"}`, &e); code != 422 || e.Field != "password" {
		t.Fatalf("short password: %d %+v", code, e)
	}
	var me api.Me
	if code := guest.do("POST", acceptPath, `{"username":"fajar","display_name":"Fajar","password":"fajar-password-1"}`, &me); code != 201 {
		t.Fatalf("accept: %d", code)
	}
	if me.User.Role != "deployer" || me.User.Email != "fajar@example.com" || me.User.LastLoginAt == nil {
		t.Fatalf("accepted user = %+v", me.User)
	}
	guest.csrf = me.CSRFToken
	if code := guest.do("GET", "/api/v1/me", "", nil); code != 200 {
		t.Fatalf("signed in after accept: %d", code)
	}
	if code := anonymous(t, srv.URL).do("POST", acceptPath, `{"username":"fajar2","password":"fajar-password-1"}`, nil); code != 404 {
		t.Fatalf("reuse link: %d", code)
	}
	login(t, srv.URL, "fajar", "fajar-password-1")

	// An expired link is refused but stays listed, so it can be renewed.
	sinta, _ := st.InviteByID(context.Background(), links[1].Invite.ID)
	sinta.ExpiresAt = time.Now().Add(-time.Minute)
	if err := st.RenewInvite(context.Background(), sinta); err != nil {
		t.Fatal(err)
	}
	if code := guest.do("GET", "/api/v1/auth/invite/"+links[1].Token, "", &e); code != 410 || e.Code != "invite_expired" {
		t.Fatalf("expired link: %d %+v", code, e)
	}
	if admin.do("GET", "/api/v1/invites", "", &list); len(list) != 1 || !list[0].Expired {
		t.Fatalf("expired invite listing = %+v", list)
	}

	if code := admin.do("DELETE", fmt.Sprintf("/api/v1/invites/%d", links[1].Invite.ID), "", nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if code := guest.do("GET", "/api/v1/auth/invite/"+links[1].Token, "", nil); code != 404 {
		t.Fatalf("revoked link: %d", code)
	}
	if code := admin.do("GET", "/api/v1/invites", "", &list); code != 200 || len(list) != 0 {
		t.Fatalf("after accept and revoke: %d %+v", code, list)
	}
}

func anonymous(t *testing.T, base string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: base, http: &http.Client{Jar: jar}}
}
