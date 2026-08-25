// Package server wraps net/http.Server with the timeouts and shutdown
// behavior BeeBase needs, independent of routing concerns.
package server

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Server is a thin wrapper around http.Server that exposes a blocking
// Run and a context-aware Shutdown, so callers don't reach into the
// stdlib server directly.
type Server struct {
	httpServer *http.Server
}

// Config holds the timeouts used to construct a Server.
type Config struct {
	Addr         string
	Handler      http.Handler
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// New constructs a Server from cfg.
func New(cfg Config) *Server {
	return &Server{
		httpServer: &http.Server{
			Addr:         cfg.Addr,
			Handler:      cfg.Handler,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout:  cfg.IdleTimeout,
		},
	}
}

// Run starts the server and blocks until it stops. It returns nil when the
// server is stopped via Shutdown, and a non-nil error for any other failure.
func (s *Server) Run() error {
	if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown gracefully stops the server, waiting for in-flight requests to
// finish until ctx is done.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
