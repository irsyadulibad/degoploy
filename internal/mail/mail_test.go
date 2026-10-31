package mail

import (
	"context"
	"strings"
	"testing"

	"github.com/degovan/degoploy/internal/config"
	"github.com/degovan/degoploy/internal/mail/smtptest"
)

func TestSend(t *testing.T) {
	srv := smtptest.New(t)
	cfg := config.SMTP{Host: srv.Host, Port: srv.Port, Encryption: "none", Username: "bot", Password: "pw",
		FromName: "Degoploy", FromAddress: "no-reply@degovan.id"}
	reply, err := Send(context.Background(), cfg, Message{
		To: "rina@degovan.id", Subject: "Kamu diundang ✓", Text: "Hello\n.leading dot", HTML: "<p>Hello</p>",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(reply, "250 2.0.0 OK") {
		t.Fatalf("reply = %q", reply)
	}
	msgs := srv.Messages()
	if len(msgs) != 1 || msgs[0].To[0] != "rina@degovan.id" || msgs[0].Username != "bot" || msgs[0].Password != "pw" {
		t.Fatalf("messages = %+v", msgs)
	}
	data := msgs[0].Data
	for _, want := range []string{`From: "Degoploy" <no-reply@degovan.id>`, "Subject: =?utf-8?q?", "multipart/alternative",
		"text/html", ".leading dot", "Auto-Submitted: auto-generated"} {
		if !strings.Contains(data, want) {
			t.Errorf("message lacks %q:\n%s", want, data)
		}
	}

	srv.RejectRcpt = true
	if _, err := Send(context.Background(), cfg, Message{To: "nobody@degovan.id", Subject: "x", Text: "x"}); err == nil ||
		!strings.Contains(err.Error(), "No such user") {
		t.Fatalf("rejected recipient: %v", err)
	}
	cfg.Encryption = "starttls"
	if _, err := Send(context.Background(), cfg, Message{To: "a@b.c", Subject: "x", Text: "x"}); err == nil ||
		!strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("missing STARTTLS: %v", err)
	}
}
