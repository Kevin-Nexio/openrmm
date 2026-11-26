package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// The console's actual Web Crypto code handshakes with the Go endpoint over
// a relay. Standalone Go builds can run without the console dependencies.
func TestBrowserWebCryptoInteroperability(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is unavailable")
	}
	if _, err := os.Stat("../../openrmm/node_modules/ws/package.json"); err != nil {
		t.Skip("console dependencies are unavailable")
	}
	wsURL, recorded := startPipeServer(t)
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "../../openrmm/tests/fixtures/remote-crypto-viewer.mjs", wsURL, pub)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		if cmd.ProcessState == nil {
			_ = cmd.Wait()
		}
	}()
	lines := bufio.NewScanner(stdout)
	if !lines.Scan() {
		_ = cmd.Wait()
		t.Fatalf("browser fixture did not send its public key: %s", stderr.String())
	}
	opts, err := NewAgentHandshakeFromIdentity("interop-session", "interop-device", "files", "", lines.Text(), priv, pub, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	conn, err := HandshakeAgent(raw, opts)
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	for _, message := range []struct {
		kind int
		data []byte
	}{
		{websocket.TextMessage, []byte(`{"t":"fget","path":"interop.txt"}`)},
		{websocket.BinaryMessage, []byte{2, 7, 42}},
	} {
		kind, data, err := conn.ReadMessage()
		if err != nil || kind != message.kind || !bytes.Equal(data, message.data) {
			t.Fatalf("Go endpoint got (%d, %q, %v), want (%d, %q)", kind, data, err, message.kind, message.data)
		}
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"t":"fbegin","id":7}`)); err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte{2, 7, 12, 34}); err != nil {
		t.Fatal(err)
	}
	if !lines.Scan() || lines.Text() != "received text and binary" {
		t.Fatal("browser fixture did not confirm receipt")
	}
	frames := recorded()
	for _, f := range frames {
		if bytes.Contains(f, []byte("interop.txt")) || bytes.Contains(f, []byte("fbegin")) {
			t.Fatal("relay observed unencrypted application data")
		}
	}
	if err := raw.WriteMessage(websocket.BinaryMessage, frames[len(frames)-1][1:]); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("browser fixture: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
}

func TestBrowserRemoteChatInteroperability(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is unavailable")
	}
	if _, err := os.Stat("../../openrmm/node_modules/ws/package.json"); err != nil {
		t.Skip("console dependencies are unavailable")
	}
	wsURL, recorded := startPipeServer(t)
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "../../openrmm/tests/fixtures/remote-chat-interop.mjs", wsURL, pub)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		if cmd.ProcessState == nil {
			_ = cmd.Wait()
		}
	}()
	lines := bufio.NewScanner(stdout)
	if !lines.Scan() {
		_ = cmd.Wait()
		t.Fatalf("chat interop fixture did not emit viewer public key: %s", stderr.String())
	}
	opts, err := NewAgentHandshakeFromIdentity("interop-chat-session", "interop-chat-device", "desktop", "", lines.Text(), priv, pub, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	conn, err := HandshakeAgent(raw, opts)
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))

	// First application frame surfaced must be Alice's authenticated guest chat
	// (chat_init, chat_user_cert, and the forged tech envelope are filtered/handled internally).
	mt, data, err := conn.ReadMessage()
	if err != nil || mt != websocket.TextMessage {
		t.Fatalf("sidecar ReadMessage(guest chat) = (%d, %q, %v)", mt, data, err)
	}
	var guestLine struct{ T, From, Name, Text string }
	if err := json.Unmarshal(data, &guestLine); err != nil {
		t.Fatalf("guest chat JSON: %v (%q)", err, data)
	}
	if guestLine.T != "chat" || guestLine.From != "guest" || guestLine.Name != "Alice" || guestLine.Text != "Olá from Alice" {
		t.Fatalf("unexpected guest chat delivered to sidecar: %+v", guestLine)
	}

	// Next frame must be the marker "kf", proving the replayed guest envelope was dropped.
	mt, marker, err := conn.ReadMessage()
	if err != nil || mt != websocket.TextMessage || string(marker) != `{"t":"kf"}` {
		t.Fatalf("sidecar ReadMessage(marker) = (%d, %q, %v), want kf", mt, marker, err)
	}

	// Endpoint user replies: Go emits direct chat + signed chat_group verified by JS RemoteChat.
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"t":"chat","from":"user","text":"Hi from endpoint"}`)); err != nil {
		t.Fatal(err)
	}
	if !lines.Scan() || lines.Text() != "chat interop ok" {
		_ = cmd.Wait()
		t.Fatalf("chat interop fixture did not confirm completion: got %q, stderr=%s", lines.Text(), strings.TrimSpace(stderr.String()))
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("chat interop fixture failed: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	for _, f := range recorded() {
		if bytes.Contains(f, []byte("from Alice")) || bytes.Contains(f, []byte("Hi from endpoint")) {
			t.Fatal("relay observed unencrypted chat plaintext")
		}
	}
}
