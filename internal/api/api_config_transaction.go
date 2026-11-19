package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/p1ngu/rmm/internal/store"
)

// errConfigResponse rolls back the transaction while retaining a handler's
// response. A successful response is sent only after the commit succeeds.
var errConfigResponse = errors.New("configuration write refused")

func (s *Server) configWrite(w http.ResponseWriter, r *http.Request, fn func(*Server, *stepRecorder, *http.Request) error) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	rec := &stepRecorder{header: make(http.Header), code: http.StatusOK}
	err := s.store.InConfigTransaction(ctx, func(tx *store.Store) error {
		// Configuration handlers only need the store and config. They must not
		// dispatch jobs or touch other services before the transaction commits.
		return fn(&Server{cfg: s.cfg, store: tx}, rec, r)
	})
	if err != nil && !errors.Is(err, errConfigResponse) {
		status := httpStatusFor(err)
		switch status {
		case http.StatusConflict, http.StatusNotFound:
			writeErr(w, status, err.Error())
		default:
			log.Printf("configuration write failed: %v", err)
			writeErr(w, http.StatusInternalServerError, "configuration changes could not be saved")
		}
		return
	}
	if err == nil && rec.afterCommit != nil {
		rec.afterCommit(s)
	}
	for k, values := range rec.header {
		w.Header()[k] = values
	}
	w.WriteHeader(rec.code)
	_, _ = w.Write(rec.body.Bytes())
}

// lockedMonitoringWrite takes the same locks as a proposal before the handler
// reads the current attachments and checks its permissions. Buffer the request
// before opening a transaction so slow clients do not hold configuration locks.
func (s *Server) lockedMonitoringWrite(kind string, handler func(*Server, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if _, err := uuid.Parse(id); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid configuration id")
			return
		}
		if r.Body != nil {
			defer r.Body.Close()
			body, err := io.ReadAll(r.Body)
			if err != nil {
				writeErr(w, http.StatusBadRequest, "invalid body")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		s.configWrite(w, r, func(tx *Server, rec *stepRecorder, r *http.Request) error {
			if err := tx.store.LockConfigTarget(r.Context(), kind, id, tx.scopeUserID(r) != ""); err != nil {
				return err
			}
			handler(tx, rec, r)
			if rec.code >= 300 {
				return errConfigResponse
			}
			return nil
		})
	}
}
