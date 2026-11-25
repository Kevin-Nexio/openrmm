package api

import (
	"encoding/json"
	"maps"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/p1ngu/rmm/internal/e2e"
	"github.com/p1ngu/rmm/internal/models"
	"github.com/p1ngu/rmm/internal/remote"
)

const remoteChatBacklog = 64

// Shared-key envelopes travel over the authenticated application channel. The
// WebSocket relay sees group traffic only inside a peer-to-peer encrypted frame.
type remoteChatRequest struct {
	Session    string          `json:"session_id"`
	Kid        string          `json:"kid"`
	Cursor     uint64          `json:"cursor"`
	Generation uint64          `json:"generation,omitempty"`
	Source     string          `json:"source,omitempty"`
	Envelope   json.RawMessage `json:"envelope,omitempty"`
}

type remoteChatLine struct {
	Cursor   uint64          `json:"cursor"`
	From     string          `json:"from"`
	ShareID  string          `json:"share_id,omitempty"`
	Envelope json.RawMessage `json:"envelope"`
}

type remoteChatRoom struct {
	kid        string
	generation uint64
	members    map[string]int
	suspended  bool
	cursor     uint64
	lines      []remoteChatLine
}

func readRemoteChat(w http.ResponseWriter, r *http.Request) (remoteChatRequest, bool) {
	var in remoteChatRequest
	r.Body = http.MaxBytesReader(w, r.Body, 12<<10)
	if decode(r, &in) != nil || in.Session == "" || in.Kid == "" || len(in.Kid) > 64 {
		writeErr(w, http.StatusBadRequest, "invalid encrypted chat request")
		return in, false
	}
	if len(in.Envelope) > 0 {
		var env e2e.ChatEnvelope
		if !e2e.IsChatEnvelope(in.Envelope) || json.Unmarshal(in.Envelope, &env) != nil || env.Kid != in.Kid {
			writeErr(w, http.StatusBadRequest, "invalid encrypted chat envelope")
			return in, false
		}
	}
	return in, true
}

func (s *Server) technicianRemoteChat(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	if !s.requireAgent(w, r, agentID) {
		return
	}
	in, ok := readRemoteChat(w, r)
	if !ok {
		return
	}
	principal, ok := s.sharePrincipal(w, r)
	if !ok {
		return
	}
	viewer, live := s.presence.Session(agentID, in.Session)
	if !live || !viewer.E2E || viewer.Kind != "native" || viewer.User != principal {
		writeErr(w, http.StatusForbidden, "an active encrypted desktop session is required")
		return
	}
	from := "tech"
	switch in.Source {
	case "", "tech":
		from = "tech"
	case "user":
		from = "user"
	default:
		writeErr(w, http.StatusBadRequest, "invalid encrypted chat source")
		return
	}
	s.exchangeRemoteChat(w, r, viewer, in, from, "")
}

func (s *Server) guestRemoteChat(w http.ResponseWriter, r *http.Request) {
	in, ok := readRemoteChat(w, r)
	if !ok {
		return
	}
	share, err := s.guestRelayShare(r.Context(), in.Session, guestCredential(r))
	if err != nil || !s.guests.owns(share.ID, in.Session) {
		writeErr(w, http.StatusForbidden, "an active encrypted guest session is required")
		return
	}
	present := s.presence.ForUser(share.AgentID, share.CreatedBy, "native")
	if len(present) != 1 || !present[0].E2E || share.ChatKeyID != in.Kid {
		writeCodedErr(w, http.StatusConflict, "chat_room_changed", "the encrypted chat room changed")
		return
	}
	in.Generation = 0 // Guests can only join an epoch activated by the technician.
	s.exchangeRemoteChat(w, r, present[0], in, "guest", share.ID)
}

// Room membership is determined from live grants, including approved guests
// that can reconnect. A stale epoch remains suspended even if the same members
// later return. Generation ordering prevents stale requests reactivating it.
func (g *guestSessions) exchangeChat(viewer remote.Viewer, in remoteChatRequest, from, shareID string, members map[string]int, wrapped bool, attached func() bool) ([]remoteChatLine, bool) {
	g.roomMu.Lock()
	defer g.roomMu.Unlock()

	if !attached() {
		return nil, false
	}
	if g.rooms == nil {
		g.rooms = make(map[string]*remoteChatRoom)
	}
	room := g.rooms[viewer.SessionID]
	if room != nil && room.kid == in.Kid && (!wrapped || !maps.Equal(room.members, members)) {
		room.suspended = true
		room.lines = nil
	}
	if from == "guest" {
		if _, member := members[shareID]; !member {
			return nil, false
		}
	}
	if !wrapped || len(members) == 0 {
		return nil, false
	}
	if room == nil || room.kid != in.Kid {
		if from == "guest" || in.Generation == 0 || (room != nil && in.Generation <= room.generation) {
			return nil, false
		}
		room = &remoteChatRoom{kid: in.Kid, generation: in.Generation, members: members}
		g.rooms[viewer.SessionID] = room
	}
	if room.suspended {
		return nil, false
	}

	if len(in.Envelope) > 0 {
		room.cursor++
		if len(room.lines) == remoteChatBacklog {
			copy(room.lines, room.lines[1:])
			room.lines = room.lines[:len(room.lines)-1]
		}
		room.lines = append(room.lines, remoteChatLine{Cursor: room.cursor, From: from, ShareID: shareID, Envelope: in.Envelope})
	}
	lines := make([]remoteChatLine, 0)
	for _, line := range room.lines {
		if line.Cursor > in.Cursor {
			lines = append(lines, line)
		}
	}
	return lines, true
}

func (g *guestSessions) suspendChat(sessionID string) {
	if g == nil || sessionID == "" {
		return
	}
	g.roomMu.Lock()
	defer g.roomMu.Unlock()
	if room := g.rooms[sessionID]; room != nil {
		room.suspended = true
		room.lines = nil
	}
}

func (s *Server) suspendRemoteChat(agentID, sponsor string) {
	if s.presence == nil || s.guests == nil {
		return
	}
	for _, viewer := range s.presence.ForUser(agentID, sponsor, "native") {
		if viewer.E2E {
			s.guests.suspendChat(viewer.SessionID)
		}
	}
}

func (g *guestSessions) forgetChat(sessionID string) {
	g.roomMu.Lock()
	defer g.roomMu.Unlock()
	delete(g.rooms, sessionID)
}

func (s *Server) exchangeRemoteChat(w http.ResponseWriter, r *http.Request, viewer remote.Viewer, in remoteChatRequest, from, shareID string) {
	if len(in.Envelope) > 0 && from == "guest" && !s.guests.allowChat(shareID, time.Now()) {
		writeCodedErr(w, http.StatusTooManyRequests, "too_soon", "wait a moment before sending another message")
		return
	}
	shares, err := s.store.RemoteSharesForCreator(r.Context(), viewer.AgentID, viewer.User)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not read chat membership")
		return
	}
	wrapped := true
	members := make(map[string]int)
	for _, share := range shares {
		if share.Status != models.RemoteShareAccepted {
			continue
		}
		members[share.ID] = share.RedeemCount
		wrapped = wrapped && share.ChatKeyID == in.Kid && share.WrappedChatKey != ""
	}
	lines, ok := s.guests.exchangeChat(viewer, in, from, shareID, members, wrapped, func() bool {
		current, live := s.presence.Session(viewer.AgentID, viewer.SessionID)
		return live && current == viewer && (from != "guest" || s.guests.owns(shareID, in.Session))
	})
	if !ok {
		writeCodedErr(w, http.StatusConflict, "chat_room_changed", "the encrypted chat room changed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"lines": lines})
}
