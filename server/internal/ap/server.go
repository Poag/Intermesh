package ap

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Poag/Intermesh/server/internal/state"
)

// Defaults suggested on 3 Oct 2026 (admin-changeable).
const (
	DefaultMaxBody = 64 << 10
	DefaultMaxAge  = 5 * time.Minute
	DefaultSkew    = time.Minute
)

// Server is the federation HTTP surface: the actor document and the inbox.
type Server struct {
	State  *state.State
	Client *Client
	Self   Self
	Name   string
	// Published is when this server's identity was created, published on the actor so two
	// servers with the same tag can tell which is newer.
	Published time.Time
	// HomeTag returns the current community tag.
	HomeTag func() string

	// Handle receives each authenticated, fresh, non-repeated activity from an unblocked peer.
	Handle func(ctx context.Context, from state.Peer, act *Activity) error
	// OnNewPeer is called the first time a server is learned, so the admin console can show it.
	OnNewPeer func(p state.Peer)
	// OnPeer is called whenever a peer's actor was fetched, with its document.
	OnPeer func(p state.Peer, doc *ActorDoc)

	fetchMu  sync.Mutex
	perActor *state.RateLimiter
	global   *state.RateLimiter

	MaxBody int64
	MaxAge  time.Duration
	Skew    time.Duration
	PeerCap int
	Now     func() time.Time
	Log     *slog.Logger
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Routes returns the HTTP handler serving the actor and inbox paths of Self.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	if u, err := url.Parse(s.Self.ActorURL); err == nil {
		mux.HandleFunc("GET "+u.Path, s.serveActor)
	}
	if u, err := url.Parse(s.Self.InboxURL); err == nil {
		mux.HandleFunc("POST "+u.Path, s.serveInbox)
	}
	return mux
}

// ActorDocument builds this server's actor document, including the previous key while a
// rotation overlap is running.
func (s *Server) ActorDocument() ActorDoc {
	id := s.State.Identity()
	pub := ed25519.NewKeyFromSeed(id.APPriv).Public().(ed25519.PublicKey)
	d := ActorDoc{
		Context: []string{ASContext, ContextURL},
		ID:      s.Self.ActorURL, Type: "Service", Name: s.Name, Inbox: s.Self.InboxURL,
		HomeTag:   s.HomeTag(),
		Published: s.Published.UTC().Format(time.RFC3339),
		PublicKey: PublicKeyDoc{ID: id.APKeyID, Owner: s.Self.ActorURL, PublicKeyMultibase: EncodeEd25519Multikey(pub)},
	}
	if len(id.OldAPPub) == ed25519.PublicKeySize && id.OldAPUntil.After(s.now()) {
		d.PreviousPublicKey = &PublicKeyDoc{ID: id.OldAPKeyID, Owner: s.Self.ActorURL,
			PublicKeyMultibase: EncodeEd25519Multikey(ed25519.PublicKey(id.OldAPPub)), ValidUntil: id.OldAPUntil.UTC().Format(time.RFC3339)}
	}
	return d
}

func (s *Server) serveActor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", ContentType)
	json.NewEncoder(w).Encode(s.ActorDocument())
}

var errNoKey = errors.New("ap: no known key for the key id")

// allowFetch limits how often actor documents are fetched on behalf of unauthenticated
// requests: once per actor per ten seconds, and sixty per minute overall.
func (s *Server) allowFetch(actor string) bool {
	s.fetchMu.Lock()
	defer s.fetchMu.Unlock()
	if s.perActor == nil {
		s.perActor = state.NewRateLimiter(1, 10*time.Second)
		s.global = state.NewRateLimiter(60, time.Minute)
	}
	now := s.now()
	return s.perActor.Allow(actor, now) && s.global.Allow("all", now)
}

func actorOfKeyID(keyID string) string {
	a, _, _ := strings.Cut(keyID, "#")
	return a
}

// keyFor returns the public key a peer signs with for keyID. A peer's previous key counts
// until its overlap ends.
func (s *Server) keyFor(p *state.Peer, keyID string) (ed25519.PublicKey, bool) {
	if p == nil {
		return nil, false
	}
	if keyID == p.KeyID && len(p.PublicKey) == ed25519.PublicKeySize {
		return ed25519.PublicKey(p.PublicKey), true
	}
	if keyID == p.OldKeyID && len(p.OldKey) == ed25519.PublicKeySize && p.OldUntil.After(s.now()) {
		return ed25519.PublicKey(p.OldKey), true
	}
	return nil, false
}

// refresh fetches a peer's actor document and stores it.
func (s *Server) refresh(ctx context.Context, actor string) (*state.Peer, error) {
	doc, err := s.Client.FetchActor(ctx, actor)
	if err != nil {
		return nil, err
	}
	return s.storePeer(doc, false)
}

func (s *Server) storePeer(doc *ActorDoc, manual bool) (*state.Peer, error) {
	pub, _ := DecodeEd25519Multikey(doc.PublicKey.PublicKeyMultibase)
	p := state.Peer{Actor: doc.ID, HomeTag: doc.HomeTag, Inbox: doc.Inbox, KeyID: doc.PublicKey.ID, PublicKey: pub, Manual: manual}
	if t, err := time.Parse(time.RFC3339, doc.Published); err == nil {
		p.Created = t
	}
	if pk := doc.PreviousPublicKey; pk != nil {
		if old, err := DecodeEd25519Multikey(pk.PublicKeyMultibase); err == nil {
			p.OldKeyID, p.OldKey = pk.ID, old
			p.OldUntil, _ = time.Parse(time.RFC3339, pk.ValidUntil)
		}
	}
	_, known := s.State.Peer(doc.ID)
	if err := s.State.UpsertPeer(p, s.PeerCap); err != nil {
		return nil, err
	}
	got, _ := s.State.Peer(doc.ID)
	if !known && s.OnNewPeer != nil && got != nil {
		s.OnNewPeer(*got)
	}
	if s.OnPeer != nil && got != nil {
		s.OnPeer(*got, doc)
	}
	return got, nil
}

// Learn fetches an actor and records it as a peer (used by Introduce and the admin link-up).
func (s *Server) Learn(ctx context.Context, actor string, manual bool) (*state.Peer, error) {
	doc, err := s.Client.FetchActor(ctx, actor)
	if err != nil {
		return nil, err
	}
	return s.storePeer(doc, manual)
}

func (s *Server) serveInbox(w http.ResponseWriter, r *http.Request) {
	max := s.MaxBody
	if max <= 0 {
		max = DefaultMaxBody
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if int64(len(body)) > max {
		http.Error(w, "activity too large", http.StatusRequestEntityTooLarge)
		return
	}
	keyID, err := ParseKeyID(r)
	if err != nil {
		http.Error(w, "unsigned", http.StatusUnauthorized)
		return
	}
	actor := actorOfKeyID(keyID)
	if s.State.IsBlocked(actor) {
		// Blocking is silent: the sender is not answered in any useful way (suggested 3 Oct 2026).
		w.WriteHeader(http.StatusAccepted)
		return
	}
	maxAge, skew := s.MaxAge, s.Skew
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	if skew <= 0 {
		skew = DefaultSkew
	}
	ctx := r.Context()
	verify := func(p *state.Peer) error {
		pub, ok := s.keyFor(p, keyID)
		if !ok {
			return errNoKey
		}
		_, err := VerifyRequest(r, body, pub, s.now(), maxAge, skew)
		return err
	}
	peer, _ := s.State.Peer(actor)
	verr := verify(peer)
	if verr != nil {
		// Unknown peer, unknown key (a rotation we have not seen), or a signature that does not
		// verify under the cached key: fetch the actor once, subject to rate limits, and try again.
		if !s.allowFetch(actor) {
			http.Error(w, "too many lookups", http.StatusTooManyRequests)
			return
		}
		var ferr error
		if peer, ferr = s.refresh(ctx, actor); ferr != nil {
			s.log().Info("inbox: cannot learn sender", "actor", actor, "err", ferr)
			http.Error(w, "unknown sender", http.StatusUnauthorized)
			return
		}
		verr = verify(peer)
	}
	if verr != nil {
		s.log().Info("inbox: signature refused", "actor", actor, "err", verr)
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	var act Activity
	if err := json.Unmarshal(body, &act); err != nil || act.ID == "" || act.Type == "" {
		http.Error(w, "bad activity", http.StatusBadRequest)
		return
	}
	if act.Actor != actor {
		http.Error(w, "actor does not match the signing key", http.StatusForbidden)
		return
	}
	if act.Published != "" {
		if t, err := time.Parse(time.RFC3339, act.Published); err != nil || s.now().Sub(t) > maxAge || t.Sub(s.now()) > skew {
			http.Error(w, "stale or future published time", http.StatusBadRequest)
			return
		}
	}
	if s.State.SeenActivity(act.ID) {
		w.WriteHeader(http.StatusAccepted) // a repeat inside the window: acknowledged, not reprocessed
		return
	}
	// Learned servers are trusted by default; touching the peer refreshes its last-heard time
	// (the shared list drops the least recently heard when full).
	_ = s.State.UpsertPeer(state.Peer{Actor: peer.Actor}, s.PeerCap)
	if s.Handle != nil {
		if err := s.Handle(ctx, *peer, &act); err != nil {
			var bad *BadActivity
			if errors.As(err, &bad) {
				http.Error(w, bad.Error(), http.StatusBadRequest)
				return
			}
			s.log().Error("inbox: handler failed", "type", act.Type, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusAccepted)
}

// BadActivity is returned by a handler for an activity that is well signed but invalid.
type BadActivity struct{ Reason string }

func (e *BadActivity) Error() string { return e.Reason }
