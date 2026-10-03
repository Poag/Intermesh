package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Poag/Intermesh/server/internal/ap"
	"github.com/Poag/Intermesh/server/internal/broker"
	"github.com/Poag/Intermesh/server/internal/core"
	"github.com/Poag/Intermesh/server/internal/state"
)

// App is a running community server.
type App struct {
	Cfg    FileConfig
	State  *state.State
	Engine *core.Engine
	Broker *broker.Broker
	AP     *ap.Server
	Client *ap.Client
	Out    *ap.Outbox
	Log    *slog.Logger

	AdminToken string

	httpSrv  *http.Server
	adminSrv *http.Server
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// Start brings the server up. Listeners are opened before it returns.
func Start(ctx context.Context, f FileConfig, log *slog.Logger) (*App, error) {
	if log == nil {
		log = slog.Default()
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(f.DataDir, 0o700); err != nil {
		return nil, err
	}
	st, err := state.Open(filepath.Join(f.DataDir, "state.json"), time.Now)
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(f.BaseURL, "/")
	if err := core.EnsureIdentity(st, base); err != nil {
		return nil, err
	}
	id := st.Identity()
	self := ap.Self{ActorURL: base + "/actor", InboxURL: base + "/inbox", KeyID: id.APKeyID, Priv: ed25519.NewKeyFromSeed(id.APPriv)}
	client := ap.NewClient(self, f.AllowPrivate, f.AllowHTTP)
	client.Log = log
	srv := &ap.Server{State: st, Client: client, Self: self, Name: f.Name, Published: id.Created,
		HomeTag: func() string { return st.Identity().HomeTag }, PeerCap: f.PeerCap, Log: log,
		MaxBody: int64(f.MaxActivityBytes), MaxAge: time.Duration(f.ActivityMaxAgeSeconds) * time.Second}
	out := ap.NewOutbox(client)

	a := &App{Cfg: f, State: st, AP: srv, Client: client, Out: out, Log: log}
	// The engine needs the broker (to downlink) and the broker needs the engine (for uplink),
	// so the broker is created with a forwarding callback.
	var eng *core.Engine
	br, err := broker.New(st, f.MQTTRoot, serverID(st), func(u broker.Uplink) {
		if eng != nil {
			eng.HandleUplink(u)
		}
	}, log)
	if err != nil {
		return nil, err
	}
	eng, err = core.New(f.Core(), st, br, core.NewFederation(out, srv), self, log, time.Now)
	if err != nil {
		return nil, err
	}
	a.Engine, a.Broker = eng, br
	srv.Handle, srv.OnNewPeer, srv.OnPeer = eng.HandleActivity, eng.OnNewPeer, eng.OnPeer

	var tlsCfg *tls.Config
	if f.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(f.TLSCert, f.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("tls: %w", err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	} else if !strings.HasPrefix(base, "http://") {
		log.Warn("no TLS certificate configured: run behind a TLS-terminating reverse proxy, and put TLS on the MQTT listener before exposing it to the internet")
	}
	if err := br.Listen(f.MQTTListen, tlsCfg); err != nil {
		return nil, err
	}
	if err := br.Serve(); err != nil {
		return nil, err
	}

	ln, err := net.Listen("tcp", f.HTTPListen)
	if err != nil {
		br.Close()
		return nil, err
	}
	a.httpSrv = &http.Server{Handler: srv.Routes(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, TLSConfig: tlsCfg}
	a.serve(a.httpSrv, ln, tlsCfg != nil)

	a.AdminToken, err = adminToken(f.DataDir)
	if err != nil {
		return nil, err
	}
	if f.AdminListen != "" {
		aln, err := net.Listen("tcp", f.AdminListen)
		if err != nil {
			return nil, err
		}
		a.adminSrv = &http.Server{Handler: a.adminHandler(), ReadHeaderTimeout: 10 * time.Second}
		a.serve(a.adminSrv, aln, false)
	}

	rctx, cancel := context.WithCancel(ctx)
	a.cancel = cancel
	a.wg.Add(1)
	go func() { defer a.wg.Done(); eng.Run(rctx) }()
	return a, nil
}

func (a *App) serve(s *http.Server, ln net.Listener, useTLS bool) {
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		var err error
		if useTLS {
			err = s.ServeTLS(ln, "", "")
		} else {
			err = s.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.Log.Error("http server stopped", "addr", ln.Addr().String(), "err", err)
		}
	}()
}

// Close shuts the server down, giving queued deliveries a few seconds to finish.
func (a *App) Close() {
	if a.cancel != nil {
		a.cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if a.httpSrv != nil {
		a.httpSrv.Shutdown(ctx)
	}
	if a.adminSrv != nil {
		a.adminSrv.Shutdown(ctx)
	}
	a.Broker.Close()
	done := make(chan struct{})
	go func() { a.Out.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	a.wg.Wait()
}

func serverID(st *state.State) string {
	// the engine derives the node number from the mesh key; the broker needs the same id
	// before the engine exists, so it is derived here the same way
	e, err := core.NodeIDFromIdentity(st.Identity())
	if err != nil {
		panic(err)
	}
	return e
}

// adminToken reads or creates the bearer token for the admin API.
func adminToken(dir string) (string, error) {
	p := filepath.Join(dir, "admin-token")
	if b, err := os.ReadFile(p); err == nil {
		return strings.TrimSpace(string(b)), nil
	}
	raw := make([]byte, 24)
	rand.Read(raw)
	tok := hex.EncodeToString(raw)
	return tok, os.WriteFile(p, []byte(tok+"\n"), 0o600)
}

func r0() context.Context { return context.Background() }
