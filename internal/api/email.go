package api

import (
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"

	"github.com/degovan/degoploy/internal/audit"
	"github.com/degovan/degoploy/internal/auth"
	"github.com/degovan/degoploy/internal/config"
	"github.com/degovan/degoploy/internal/httpx"
	mailer "github.com/degovan/degoploy/internal/mail"
	"github.com/degovan/degoploy/internal/store"
)

func (a *API) registerEmail(mux *http.ServeMux) {
	need := func(fn http.HandlerFunc) http.Handler {
		return auth.RequireAuth(a.authz.Require(auth.ActionUserManage, fn))
	}
	mux.Handle("GET /api/v1/email", need(a.emailStatus))
	mux.Handle("PATCH /api/v1/email", need(a.updateEmail))
	mux.Handle("POST /api/v1/email/test", need(a.testEmail))
}

// smtp returns the current SMTP settings; the Email page changes them at runtime.
func (a *API) smtp() config.SMTP {
	a.mailMu.RLock()
	defer a.mailMu.RUnlock()
	return a.cfg.SMTP
}

// smtpMAC fingerprints the settings a test email proves, password included.
func (a *API) smtpMAC(s config.SMTP) string {
	return a.secrets.MAC("smtp", s.Host, strconv.Itoa(s.Port), s.Encryption, s.Username, s.Password,
		s.FromName, s.FromAddress)
}

// emailReady reports whether invites can be emailed: SMTP is configured and a
// test email was delivered with exactly these settings.
func (a *API) emailReady(r *http.Request) (bool, config.SMTP, error) {
	s := a.smtp()
	if !s.Configured() {
		return false, s, nil
	}
	t, err := a.store.LastEmailTest(r.Context(), true)
	if errors.Is(err, store.ErrNotFound) {
		return false, s, nil
	}
	if err != nil {
		return false, s, err
	}
	return t.SettingsMAC == a.smtpMAC(s), s, nil
}

func (a *API) emailStatusBody(r *http.Request) (EmailStatus, error) {
	s := a.smtp()
	out := EmailStatus{
		Host: s.Host, Port: s.Port, Encryption: s.Encryption, Username: s.Username, PasswordSet: s.Password != "",
		FromName: s.FromName, FromAddress: s.FromAddress, Locked: map[string]string{}, ConfigPath: a.cfg.Path,
		Configured: s.Configured(),
	}
	for k, v := range a.cfg.Locked {
		if strings.HasPrefix(k, "smtp.") {
			out.Locked[k] = v
		}
	}
	ready, _, err := a.emailReady(r)
	if err != nil {
		return out, err
	}
	out.Ready = ready
	t, err := a.store.LastEmailTest(r.Context(), false)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return out, err
	}
	if t != nil {
		out.LastTest = &EmailTest{
			To: t.Recipient, OK: t.OK, Detail: t.Detail, At: msTime(t.CreatedAt),
			Current: t.SettingsMAC == a.smtpMAC(s),
		}
	}
	return out, nil
}

func (a *API) emailStatus(w http.ResponseWriter, r *http.Request) {
	out, err := a.emailStatusBody(r)
	if err != nil {
		httpx.InternalError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, out)
}

// updateEmail saves the SMTP settings to the config file and applies them at
// once. Any change pauses invites until a new test email is delivered.
func (a *API) updateEmail(w http.ResponseWriter, r *http.Request) {
	ident := auth.FromContext(r.Context())
	var req UpdateEmailRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	changed, field, err := a.applyEmail(&req)
	switch {
	case field != "":
		validationError(w, field, err.Error())
		return
	case errors.Is(err, errNoConfigFile):
		httpx.Error(w, http.StatusConflict, "no_config_file", err.Error())
		return
	case err != nil:
		httpx.InternalError(w, r, err)
		return
	}
	if len(changed) > 0 {
		a.audit.Record(r.Context(), audit.Entry{
			UserID: ident.User.ID, Action: audit.EmailUpdate, TargetType: "email",
			Detail: map[string]any{"changed": changed}, IP: a.clientIP(r),
		})
	}
	a.emailStatus(w, r)
}

func (a *API) applyEmail(req *UpdateEmailRequest) (changed []string, field string, err error) {
	a.mailMu.Lock()
	defer a.mailMu.Unlock()
	m := a.cfg.SMTP
	locked := a.cfg.Locked

	set := func(key string, differs bool, apply func()) bool {
		if !differs {
			return true
		}
		if src, ok := locked[key]; ok {
			field, err = key, fmt.Errorf("is set by %s on the server and cannot be changed here", src)
			return false
		}
		apply()
		changed = append(changed, key)
		return true
	}
	str := func(key string, p *string, dst *string) bool {
		if p == nil {
			return true
		}
		v := strings.TrimSpace(*p)
		return set(key, v != *dst, func() { *dst = v })
	}
	ok := str("smtp.host", req.Host, &m.Host) &&
		str("smtp.encryption", req.Encryption, &m.Encryption) &&
		str("smtp.username", req.Username, &m.Username) &&
		str("smtp.from_name", req.FromName, &m.FromName) &&
		str("smtp.from_address", req.FromAddress, &m.FromAddress) &&
		(req.Port == nil || set("smtp.port", *req.Port != m.Port, func() { m.Port = *req.Port }))
	if !ok {
		return nil, field, err
	}
	var sealed *string
	if req.Password != nil && *req.Password != "" {
		pw := *req.Password
		if !set("smtp.password", pw != m.Password, func() { m.Password = pw }) {
			return nil, field, err
		}
		if m.Password == pw {
			v := config.SealedPrefix + a.secrets.Seal(pw, config.SMTPPasswordScope)
			sealed = &v
		}
	}
	if len(changed) == 0 {
		return nil, "", nil
	}

	switch {
	case m.Host != "" && (m.Port < 1 || m.Port > 65535):
		return nil, "smtp.port", errors.New("must be between 1 and 65535")
	case m.Encryption != "starttls" && m.Encryption != "tls" && m.Encryption != "none":
		return nil, "smtp.encryption", errors.New("must be starttls, tls or none")
	case m.FromAddress != "":
		if _, perr := mail.ParseAddress(m.FromAddress); perr != nil || !validEmail(m.FromAddress) {
			return nil, "smtp.from_address", errors.New("is not a valid email address")
		}
	case m.Host != "":
		return nil, "smtp.from_address", errors.New("is required to send mail")
	}
	if a.cfg.Path == "" {
		return nil, "", errNoConfigFile
	}
	if serr := config.SaveSMTP(a.cfg.Path, m, sealed, locked); serr != nil {
		return nil, "", serr
	}
	a.cfg.SMTP = m
	return changed, "", nil
}

// testEmail sends a test email with the current settings and records the
// result; a delivered test enables invites.
func (a *API) testEmail(w http.ResponseWriter, r *http.Request) {
	ident := auth.FromContext(r.Context())
	var req TestEmailRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	to := strings.TrimSpace(req.To)
	if _, err := mail.ParseAddress(to); err != nil || !validEmail(to) {
		validationError(w, "to", "is not a valid email address")
		return
	}
	s := a.smtp()
	if !s.Configured() {
		httpx.Error(w, http.StatusConflict, "email_not_configured", "set the SMTP host, port and from address first")
		return
	}
	host := hostOf(a.publicURL(r))
	reply, err := mailer.Send(r.Context(), s, mailer.Message{
		To:      to,
		Subject: "degoploy test email from " + host,
		Text: fmt.Sprintf("This is a test email from degoploy at %s, sent by %s.\n\n"+
			"It arrived, so invitations can be emailed with these settings:\n%s:%d (%s), from %s.\n\n"+
			"-- \nYou received this because %s sent a test email to %s from the Email page.\n",
			host, ident.User.Username, s.Host, s.Port, s.Encryption, s.FromAddress, ident.User.Username, to),
		HTML: emailHTML(emailLayout{
			Preview: "Email from degoploy works with these settings.",
			Title:   "Test email",
			Lead: fmt.Sprintf("This is a test email from degoploy at %s, sent by <b>%s</b>.",
				html.EscapeString(host), html.EscapeString(ident.User.Username)),
			Note: fmt.Sprintf("It arrived, so invitations can be emailed with these settings: %s:%d (%s), from %s.",
				html.EscapeString(s.Host), s.Port, html.EscapeString(s.Encryption), html.EscapeString(s.FromAddress)),
			Footer: fmt.Sprintf("You received this because %s sent a test email to %s from the Email page.",
				html.EscapeString(ident.User.Username), html.EscapeString(to)),
		}),
	})
	t := &store.EmailTest{Recipient: to, OK: err == nil, Detail: reply, SettingsMAC: a.smtpMAC(s), SentBy: &ident.User.ID}
	if err != nil {
		t.Detail = err.Error()
	}
	if ierr := a.store.InsertEmailTest(r.Context(), t); ierr != nil {
		httpx.InternalError(w, r, ierr)
		return
	}
	a.audit.Record(r.Context(), audit.Entry{
		UserID: ident.User.ID, Action: audit.EmailTest, TargetType: "email",
		Detail: map[string]any{"to": to, "delivered": t.OK}, IP: a.clientIP(r),
	})
	a.emailStatus(w, r)
}

// sendInvite emails an invitation link; the returned string is the error, if any.
func (a *API) sendInvite(r *http.Request, s config.SMTP, inviter *store.User, inv *store.Invite, token string) string {
	base := a.publicURL(r)
	host := hostOf(base)
	link := base + "/invite/" + url.PathEscape(token)
	role := strings.ToUpper(string(inv.Role[:1])) + string(inv.Role[1:])
	expires := inv.ExpiresAt.UTC().Format("2 January 2006")
	// Naming the inviter with their address lets the recipient tell a real
	// invitation from a lookalike.
	who := inviterName(inviter)
	if inviter.Email != "" {
		who += " (" + inviter.Email + ")"
	}
	_, err := mailer.Send(r.Context(), s, mailer.Message{
		To:      inv.Email,
		Subject: fmt.Sprintf("%s invited you to degoploy on %s", inviterName(inviter), host),
		Text: fmt.Sprintf("Hi,\n\n%s invited you to degoploy on %s as %s. degoploy is where your team "+
			"deploys its projects from Git.\n\nTo join, open this link and choose a username and password:\n%s\n\n"+
			"The link works once and expires on %s (UTC).\n\n"+
			"-- \nYou received this because %s invited %s. If you were not expecting it, "+
			"ignore this email: no account is created until the link is used.\n",
			who, host, role, link, expires, who, inv.Email),
		HTML: emailHTML(emailLayout{
			Preview: fmt.Sprintf("Join degoploy on %s as %s. The link expires on %s.", host, role, expires),
			Title:   "Join degoploy on " + host,
			Lead: fmt.Sprintf("<b>%s</b> invited you to degoploy on %s as <b>%s</b>. degoploy is where your team "+
				"deploys its projects from Git.", html.EscapeString(who), html.EscapeString(host), role),
			Note:      fmt.Sprintf("The link works once and expires on %s (UTC).", expires),
			ButtonURL: link,
			Button:    "Set up your account",
			Footer: fmt.Sprintf("You received this because %s invited %s. If you were not expecting it, "+
				"ignore this email: no account is created until the link is used.",
				html.EscapeString(who), html.EscapeString(inv.Email)),
		}),
	})
	if err != nil {
		return err.Error()
	}
	return ""
}

// publicURL is where people reach this server: base_url, or else the address
// the admin's browser used.
func (a *API) publicURL(r *http.Request) string {
	if a.cfg.BaseURL != "" {
		return a.cfg.BaseURL
	}
	if o := r.Header.Get("Origin"); o != "" {
		if u, err := url.Parse(o); err == nil && u.Host != "" && (u.Scheme == "https" || u.Scheme == "http") {
			return u.Scheme + "://" + u.Host
		}
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// hostOf is the host of a public URL, as people know the server.
func hostOf(base string) string {
	if u, err := url.Parse(base); err == nil && u.Host != "" {
		return u.Host
	}
	return base
}

// emailLayout fills emailHTML. Lead is HTML; the others are escaped by the caller
// where they hold user input. ButtonURL may be empty.
type emailLayout struct {
	Preview, Title, Lead, Note, ButtonURL, Button, Footer string
}

// emailHTML is the shared layout of degoploy emails: a complete document with
// preview text and a footer saying why it was sent. The fallback link is plain
// text, so it still matches the button if a relay rewrites links for tracking.
func emailHTML(l emailLayout) string {
	var cta string
	if l.ButtonURL != "" {
		u := html.EscapeString(l.ButtonURL)
		cta = fmt.Sprintf(`<p style="margin:24px 0"><a href="%s" style="display:inline-block;background:#111111;`+
			`color:#ffffff;padding:10px 16px;border-radius:6px;text-decoration:none;font-weight:500">%s</a></p>`+
			`<p style="margin:0 0 16px;color:#555555;font-size:13px;line-height:1.5">If the button does not work, `+
			`copy this address into your browser:<br><span style="word-break:break-all;color:#111111">%s</span></p>`,
			u, html.EscapeString(l.Button), u)
	}
	return fmt.Sprintf(`<!doctype html><html lang="en"><head><meta charset="utf-8">`+
		`<meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title></head>`+
		`<body style="margin:0;padding:24px;background:#f6f6f6;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#111111">`+
		`<div style="display:none;max-height:0;overflow:hidden">%s</div>`+
		`<div style="max-width:520px;margin:0 auto;background:#ffffff;border:1px solid #e5e5e5;border-radius:12px;padding:28px">`+
		`<p style="margin:0 0 16px;font-weight:600">degoploy</p><h1 style="font-size:20px;margin:0 0 12px">%s</h1>`+
		`<p style="font-size:15px;line-height:1.5">%s</p>%s<p style="margin:0;color:#555555;font-size:13px;line-height:1.5">%s</p>`+
		`</div><p style="max-width:520px;margin:16px auto 0;text-align:center;color:#888888;font-size:12px;line-height:1.5">%s</p>`+
		`</body></html>`,
		html.EscapeString(l.Title), html.EscapeString(l.Preview), html.EscapeString(l.Title), l.Lead, cta, l.Note, l.Footer)
}
