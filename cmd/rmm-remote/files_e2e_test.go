//go:build !windows

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/p1ngu/rmm/internal/e2e"
)

func TestRunFilesOnlyOverE2EConn(t *testing.T) {
	workDir := t.TempDir()
	const downloadName = "secret-doc.txt"
	const downloadBody = "CONFIDENTIAL-DOWNLOAD-CONTENT-9876"
	const uploadName = "uploaded-secret.bin"
	const uploadBody = "CONFIDENTIAL-UPLOAD-CONTENT-4321"
	if err := os.WriteFile(filepath.Join(workDir, downloadName), []byte(downloadBody), 0o600); err != nil {
		t.Fatal(err)
	}

	// Recording blind WebSocket pipe to prove zero file names/bytes leak on relay.
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	peers := make(chan *websocket.Conn, 2)
	var wireMu sync.Mutex
	var wireFrames [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		peers <- c
	}))
	defer srv.Close()
	go func() {
		a, b := <-peers, <-peers
		if a == nil || b == nil {
			return
		}
		pipe := func(src, dst *websocket.Conn) {
			defer dst.Close()
			for {
				mt, data, err := src.ReadMessage()
				if err != nil {
					return
				}
				wireMu.Lock()
				wireFrames = append(wireFrames, append([]byte(nil), data...))
				wireMu.Unlock()
				if err := dst.WriteMessage(mt, data); err != nil {
					return
				}
			}
		}
		go pipe(a, b)
		pipe(b, a)
	}()

	ikPriv, ikPub, _ := e2e.GenerateKeyPair()
	viewPriv, viewPub, _ := e2e.GenerateKeyPair()
	agentOpts, err := e2e.NewAgentHandshakeFromIdentity("sess-files-e2e", "agent-1", "files", "", viewPub, ikPriv, ikPub, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	rawAgent, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rawAgent.Close()
	rawViewer, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rawViewer.Close()

	agentCh := make(chan *e2e.Conn, 1)
	go func() {
		c, err := e2e.HandshakeAgent(rawAgent, agentOpts)
		if err != nil {
			agentCh <- nil
			return
		}
		agentCh <- c
	}()

	viewerConn, err := e2e.HandshakeViewer(rawViewer, e2e.ViewerHandshakeOpts{
		SessionID:       "sess-files-e2e",
		EKPriv:          viewPriv,
		ExpectedAgentID: "agent-1",
		ExpectedKind:    "files",
		ExpectedIKPub:   ikPub,
	})
	if err != nil {
		t.Fatalf("HandshakeViewer: %v", err)
	}
	defer viewerConn.Close()
	agentConn := <-agentCh
	if agentConn == nil {
		t.Fatal("HandshakeAgent failed")
	}

	filesDone := make(chan error, 1)
	go func() {
		filesDone <- runFilesOnly(agentConn, sessionOptions{allowFiles: true})
	}()

	_ = rawViewer.SetReadDeadline(time.Now().Add(10 * time.Second))
	// 1. Expect encrypted hello with mode="files".
	mt, helloRaw, err := viewerConn.ReadMessage()
	if err != nil || mt != websocket.TextMessage || !strings.Contains(string(helloRaw), `"mode":"files"`) {
		t.Fatalf("hello = (%d, %q, %v)", mt, helloRaw, err)
	}

	// 2. List temp dir over E2E and confirm secret-doc.txt appears.
	flsReq, _ := json.Marshal(map[string]any{"t": "fls", "id": 1, "path": workDir})
	if err := viewerConn.WriteMessage(websocket.TextMessage, flsReq); err != nil {
		t.Fatal(err)
	}
	mt, flistRaw, err := viewerConn.ReadMessage()
	if err != nil || mt != websocket.TextMessage || !strings.Contains(string(flistRaw), downloadName) {
		t.Fatalf("flist = (%d, %q, %v)", mt, flistRaw, err)
	}

	// 3. Download secret-doc.txt over E2E: fmeta -> 0x02 binary chunk -> fend.
	fgetReq, _ := json.Marshal(map[string]any{"t": "fget", "id": 2, "path": filepath.Join(workDir, downloadName)})
	if err := viewerConn.WriteMessage(websocket.TextMessage, fgetReq); err != nil {
		t.Fatal(err)
	}
	var gotMeta bool
	var gotBytes bytes.Buffer
	var gotEnd bool
	for !gotEnd {
		mt, data, err := viewerConn.ReadMessage()
		if err != nil {
			t.Fatalf("read during fget: %v", err)
		}
		if mt == websocket.BinaryMessage && len(data) >= 2 && data[0] == chFile && data[1] == 2 {
			gotBytes.Write(data[2:])
		} else if mt == websocket.TextMessage {
			if strings.Contains(string(data), `"fmeta"`) && strings.Contains(string(data), downloadName) {
				gotMeta = true
			} else if strings.Contains(string(data), `"fend"`) {
				gotEnd = true
			}
		}
	}
	if !gotMeta || gotBytes.String() != downloadBody {
		t.Fatalf("fget result: meta=%v body=%q, want %q", gotMeta, gotBytes.String(), downloadBody)
	}

	// 4. Upload uploaded-secret.bin over E2E: fput -> 0x02 binary chunk -> fend.
	uploadPath := filepath.Join(workDir, uploadName)
	fputReq, _ := json.Marshal(map[string]any{"t": "fput", "id": 3, "path": uploadPath, "size": len(uploadBody)})
	if err := viewerConn.WriteMessage(websocket.TextMessage, fputReq); err != nil {
		t.Fatal(err)
	}
	chunk := append([]byte{chFile, 3}, []byte(uploadBody)...)
	if err := viewerConn.WriteMessage(websocket.BinaryMessage, chunk); err != nil {
		t.Fatal(err)
	}
	if err := viewerConn.WriteMessage(websocket.TextMessage, []byte(`{"t":"fend","id":3}`)); err != nil {
		t.Fatal(err)
	}
	// Sidecar acknowledges the completed upload with {"t":"fend","id":3,"ok":true}.
	mt, fendAck, err := viewerConn.ReadMessage()
	if err != nil || mt != websocket.TextMessage || !strings.Contains(string(fendAck), `"t":"fend"`) || !strings.Contains(string(fendAck), `"ok":true`) {
		t.Fatalf("upload fend ack = (%d, %q, %v)", mt, fendAck, err)
	}
	// List again so we confirm the uploaded file is visible over E2E too.
	flsReq2, _ := json.Marshal(map[string]any{"t": "fls", "id": 4, "path": workDir})
	if err := viewerConn.WriteMessage(websocket.TextMessage, flsReq2); err != nil {
		t.Fatal(err)
	}
	mt, flistRaw2, err := viewerConn.ReadMessage()
	if err != nil || mt != websocket.TextMessage || !strings.Contains(string(flistRaw2), uploadName) {
		t.Fatalf("flist after upload = (%d, %q, %v)", mt, flistRaw2, err)
	}
	onDisk, err := os.ReadFile(uploadPath)
	if err != nil || string(onDisk) != uploadBody {
		t.Fatalf("uploaded file on disk = (%q, %v), want %q", string(onDisk), err, uploadBody)
	}

	_ = viewerConn.Close()
	<-filesDone

	wireMu.Lock()
	defer wireMu.Unlock()
	for _, f := range wireFrames {
		for _, secret := range []string{downloadName, downloadBody, uploadName, uploadBody} {
			if bytes.Contains(f, []byte(secret)) {
				t.Fatalf("relay saw plaintext %q on the wire", secret)
			}
		}
	}
}
