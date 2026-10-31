// Package mail sends email through the SMTP server from the config.
package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/degovan/degoploy/internal/config"
)

// timeout bounds a whole send: connect, TLS, auth and data.
const timeout = 30 * time.Second

// Message is one email with a plain-text and an HTML body.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// Send delivers msg and returns the server's final reply ("250 2.0.0 OK …").
func Send(ctx context.Context, cfg config.SMTP, msg Message) (string, error) {
	if !cfg.Configured() {
		return "", errors.New("SMTP is not configured")
	}
	if _, err := mail.ParseAddress(msg.To); err != nil {
		return "", fmt.Errorf("invalid recipient %q", msg.To)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	tlsConf := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
	var conn net.Conn
	var err error
	if cfg.Encryption == "tls" {
		conn, err = (&tls.Dialer{Config: tlsConf}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return "", fmt.Errorf("connect to %s: %w", addr, err)
	}
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	// Close the connection if the context ends first.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return "", fmt.Errorf("SMTP greeting: %w", err)
	}
	defer c.Close()

	if err := c.Hello(helloName()); err != nil {
		return "", fmt.Errorf("EHLO: %w", err)
	}
	if cfg.Encryption == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return "", errors.New("the server does not offer STARTTLS; choose SSL/TLS or None")
		}
		if err := c.StartTLS(tlsConf); err != nil {
			return "", fmt.Errorf("STARTTLS: %w", err)
		}
	}
	if cfg.Username != "" {
		if ok, _ := c.Extension("AUTH"); !ok {
			return "", errors.New("the server does not accept a login (no AUTH)")
		}
		if err := c.Auth(plainAuth{cfg.Username, cfg.Password}); err != nil {
			return "", fmt.Errorf("login as %s: %w", cfg.Username, err)
		}
	}

	from := cfg.FromAddress
	if err := c.Mail(from); err != nil {
		return "", fmt.Errorf("MAIL FROM %s: %w", from, err)
	}
	if err := c.Rcpt(msg.To); err != nil {
		return "", fmt.Errorf("RCPT TO %s: %w", msg.To, err)
	}
	body, err := build(cfg, msg)
	if err != nil {
		return "", err
	}
	// DATA by hand, to keep the server's final reply for the test result.
	id, err := c.Text.Cmd("DATA")
	if err != nil {
		return "", fmt.Errorf("DATA: %w", err)
	}
	c.Text.StartResponse(id)
	_, _, err = c.Text.ReadResponse(354)
	c.Text.EndResponse(id)
	if err != nil {
		return "", fmt.Errorf("DATA: %w", err)
	}
	w := c.Text.DotWriter()
	if _, err := w.Write(body); err != nil {
		return "", fmt.Errorf("send message: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("send message: %w", err)
	}
	code, reply, err := c.Text.ReadResponse(250)
	if err != nil {
		return "", fmt.Errorf("message refused: %w", err)
	}
	c.Quit()
	return strings.TrimSpace(fmt.Sprintf("%d %s", code, firstLine(reply))), nil
}

// plainAuth is SMTP AUTH PLAIN. Unlike smtp.PlainAuth it also works without
// TLS, which the admin chose explicitly with encryption "none".
type plainAuth struct{ username, password string }

func (a plainAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00" + a.username + "\x00" + a.password), nil
}

func (a plainAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("unexpected server challenge")
	}
	return nil, nil
}

// build renders msg as a multipart/alternative MIME message.
func build(cfg config.SMTP, msg Message) ([]byte, error) {
	from := (&mail.Address{Name: cfg.FromName, Address: cfg.FromAddress}).String()
	boundary := "degoploy-" + randomHex(12)
	domain := cfg.FromAddress[strings.LastIndex(cfg.FromAddress, "@")+1:]

	var b bytes.Buffer
	header := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	header("From", from)
	header("To", msg.To)
	header("Subject", mime.QEncoding.Encode("utf-8", msg.Subject))
	header("Date", time.Now().Format(time.RFC1123Z))
	header("Message-ID", fmt.Sprintf("<%s@%s>", randomHex(16), domain))
	// Marks the message as automated: no out-of-office replies to it.
	header("Auto-Submitted", "auto-generated")
	header("X-Auto-Response-Suppress", "All")
	header("MIME-Version", "1.0")
	header("Content-Type", fmt.Sprintf(`multipart/alternative; boundary="%s"`, boundary))
	b.WriteString("\r\n")

	for _, part := range []struct{ kind, body string }{{"text/plain", msg.Text}, {"text/html", msg.HTML}} {
		if part.body == "" {
			continue
		}
		fmt.Fprintf(&b, "--%s\r\nContent-Type: %s; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n",
			boundary, part.kind)
		qp := quotedprintable.NewWriter(&b)
		if _, err := qp.Write([]byte(part.body)); err != nil {
			return nil, err
		}
		qp.Close()
		b.WriteString("\r\n")
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes(), nil
}

func helloName() string {
	if h, err := osHostname(); err == nil && h != "" && !strings.ContainsAny(h, " \t") {
		return h
	}
	return "localhost"
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
