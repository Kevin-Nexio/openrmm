package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/p1ngu/rmm/internal/store"
)

func TestIsPasswordRefused(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"invalid password", fmt.Errorf("connect: %w", &pgconn.PgError{Code: "28P01"}), true},
		{"insufficient privilege", fmt.Errorf("connect: %w", &pgconn.PgError{Code: "42501"}), false},
		{"database does not exist", &pgconn.PgError{Code: "3D000"}, false},
		{"text only", errors.New(`password authentication failed for user "rmm"`), false},
	}
	for _, tc := range cases {
		if got := isPasswordRefused(tc.err); got != tc.want {
			t.Errorf("%s: isPasswordRefused = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The hint has to recognise the error exactly as the server meets it: through
// store.New, pgxpool and pgconn's connect errors. A stand-in PostgreSQL asks
// for a password and refuses it, over SCRAM (PostgreSQL 14+'s default, and what
// a refused deploy logs as "failed SASL auth") and over a plain password.
func TestStoreNewRefusedPasswordIsRecognised(t *testing.T) {
	for _, scram := range []bool{true, false} {
		t.Run(fmt.Sprintf("scram=%v", scram), func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					go refusePassword(conn, scram)
				}
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			dsn := fmt.Sprintf("postgres://rmm:not-the-password@%s/rmm?sslmode=disable&connect_timeout=5", ln.Addr())
			st, err := store.New(ctx, dsn)
			if err == nil {
				st.Close()
				t.Fatal("store.New succeeded against a server that refuses the password")
			}
			if !isPasswordRefused(err) {
				t.Fatalf("isPasswordRefused(%v) = false, want true", err)
			}
			if scram && !strings.Contains(err.Error(), "SASL") {
				t.Fatalf("expected the SCRAM path, got %v", err)
			}
			if strings.Contains(err.Error(), "not-the-password") {
				t.Fatal("the connection error repeats the password")
			}
		})
	}
}

func refusePassword(conn net.Conn, scram bool) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	backend := pgproto3.NewBackend(conn, conn)
	if _, err := backend.ReceiveStartupMessage(); err != nil {
		return
	}
	if scram {
		backend.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}})
		if backend.Flush() != nil || backend.SetAuthType(pgproto3.AuthTypeSASL) != nil {
			return
		}
		msg, err := backend.Receive()
		if err != nil {
			return
		}
		first, ok := msg.(*pgproto3.SASLInitialResponse)
		if !ok {
			return
		}
		_, nonce, found := strings.Cut(string(first.Data), ",r=")
		if !found {
			return
		}
		salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
		backend.Send(&pgproto3.AuthenticationSASLContinue{Data: []byte("r=" + nonce + "server-nonce,s=" + salt + ",i=4096")})
		if backend.Flush() != nil || backend.SetAuthType(pgproto3.AuthTypeSASLContinue) != nil {
			return
		}
	} else {
		backend.Send(&pgproto3.AuthenticationCleartextPassword{})
		if backend.Flush() != nil || backend.SetAuthType(pgproto3.AuthTypeCleartextPassword) != nil {
			return
		}
	}
	if _, err := backend.Receive(); err != nil {
		return
	}
	backend.Send(&pgproto3.ErrorResponse{
		Severity:            "FATAL",
		SeverityUnlocalized: "FATAL",
		Code:                "28P01",
		Message:             `password authentication failed for user "rmm"`,
	})
	_ = backend.Flush()
}

// The hint sends the operator to a section of the quick start; it has to exist
// and cover the same error.
func TestPasswordRefusedHintPointsAtQuickstart(t *testing.T) {
	if !strings.Contains(passwordRefusedHint, `"Troubleshooting" in deploy/QUICKSTART.md`) {
		t.Fatal("the hint no longer names the quick start's Troubleshooting section")
	}
	if !strings.Contains(passwordRefusedHint, "openrmm_app") {
		t.Fatal("the hint must say the volume advice does not apply to a role created by hand")
	}
	guide, err := os.ReadFile("../../deploy/QUICKSTART.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, found := strings.Cut(string(guide), "\n## Troubleshooting\n")
	if !found {
		t.Fatal("deploy/QUICKSTART.md has no Troubleshooting section")
	}
	section, _, _ = strings.Cut(section, "\n## ")
	for _, want := range []string{"28P01", "secrets/postgres_password", "openrmm_rmm_pgdata"} {
		if !strings.Contains(section, want) {
			t.Errorf("the Troubleshooting section does not mention %q", want)
		}
	}
}
