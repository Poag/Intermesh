package ap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Poag/Intermesh/server/internal/state"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type node struct {
	t      *testing.T
	st     *state.State
	srv    *Server
	hs     *httptest.Server
	client *Client
	out    *Outbox
	got    chan *Activity
	tag    string
}

func newNode(t *testing.T, clk *fakeClock, tag string) *node {
	t.Helper()
	st, err := state.Open("", clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	n := &node{t: t, st: st, got: make(chan *Activity, 16), tag: tag}
	n.hs = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n.srv.Routes().ServeHTTP(w, r) }))
	t.Cleanup(n.hs.Close)
	seed := make([]byte, 32)
	rand.Read(seed)
	priv := ed25519.NewKeyFromSeed(seed)
	actor := n.hs.URL + "/actor"
	st.SetIdentity(state.Identity{HomeTag: tag, APPriv: seed, APKeyID: actor + "#main-key"})
	self := Self{ActorURL: actor, InboxURL: n.hs.URL + "/inbox", KeyID: actor + "#main-key", Priv: priv}
	n.client = NewClient(self, true, true)
	n.client.Now = clk.Now
	n.client.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	n.srv = &Server{State: st, Client: n.client, Self: self, Name: "node " + tag, Published: clk.Now(), HomeTag: func() string { return n.tag },
		Now: clk.Now, PeerCap: 500, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Handle: func(ctx context.Context, from state.Peer, act *Activity) error { n.got <- act; return nil }}
	n.out = NewOutbox(n.client)
	return n
}

func (n *node) actor() string { return n.srv.Self.ActorURL }

func (n *node) activity(clk *fakeClock, typ string, to *node, object any) *Activity {
	a, err := Build(n.hs.URL, n.actor(), typ, []string{to.actor()}, clk.Now(), object, nil)
	if err != nil {
		n.t.Fatal(err)
	}
	return a
}

func (n *node) expect() *Activity {
	n.t.Helper()
	select {
	case a := <-n.got:
		return a
	case <-time.After(2 * time.Second):
		n.t.Fatal("no activity delivered")
		return nil
	}
}

func (n *node) expectNone() {
	n.t.Helper()
	select {
	case a := <-n.got:
		n.t.Fatalf("unexpected activity %s", a.Type)
	case <-time.After(100 * time.Millisecond):
	}
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 10, 4, 3, 0, 0, 0, time.UTC)} }

func TestDeliveryLearnsSenderAndVerifies(t *testing.T) {
	clk := newClock()
	a, b := newNode(t, clk, "aaaaaaaa"), newNode(t, clk, "bbbbbbbb")
	var newPeers []string
	b.srv.OnNewPeer = func(p state.Peer) { newPeers = append(newPeers, p.HomeTag) }
	act := a.activity(clk, TypeRoam, b, RoamObject{Node: "c0ffee01", HomeTag: "aaaaaaaa", PacketID: 7, Days: 3, Packet: "AAAA"})
	if err := a.client.Send(context.Background(), b.srv.Self.InboxURL, act); err != nil {
		t.Fatal(err)
	}
	got := b.expect()
	var o RoamObject
	if err := got.DecodeObject(&o); err != nil || o.Node != "c0ffee01" || o.PacketID != 7 {
		t.Fatalf("%v %+v", err, o)
	}
	p, ok := b.st.Peer(a.actor())
	if !ok || p.HomeTag != "aaaaaaaa" || p.Inbox != a.srv.Self.InboxURL {
		t.Fatalf("sender not learned: %+v", p)
	}
	if len(newPeers) != 1 || newPeers[0] != "aaaaaaaa" {
		t.Fatalf("new peer callback: %v", newPeers)
	}
}

func post(t *testing.T, url string, body []byte, hdr map[string]string) int {
	t.Helper()
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", ContentType)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestInboxRefusals(t *testing.T) {
	clk := newClock()
	a, b := newNode(t, clk, "aaaaaaaa"), newNode(t, clk, "bbbbbbbb")
	inbox := b.srv.Self.InboxURL
	act := a.activity(clk, TypeRelay, b, RelayObject{Node: "c0ffee01", Direction: DirUp, Kind: KindSealed})
	body, _ := json.Marshal(act)

	if c := post(t, inbox, body, nil); c != http.StatusUnauthorized {
		t.Fatalf("unsigned: %d", c)
	}

	// signed correctly but the activity names another actor
	other := a.activity(clk, TypeRelay, b, nil)
	other.Actor = "https://evil.example/actor"
	ob, _ := json.Marshal(other)
	req, _ := http.NewRequest("POST", inbox, bytes.NewReader(ob))
	req.Header.Set("Content-Type", ContentType)
	SignRequest(req, ob, a.srv.Self.KeyID, a.srv.Self.Priv, clk.Now(), "")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("actor mismatch: %d", resp.StatusCode)
	}

	// signed with a key that is not the actor's (after the per-actor lookup cooldown)
	clk.Advance(11 * time.Second)
	_, rogue, _ := ed25519.GenerateKey(nil)
	req, _ = http.NewRequest("POST", inbox, bytes.NewReader(body))
	req.Header.Set("Content-Type", ContentType)
	SignRequest(req, body, a.srv.Self.KeyID, rogue, clk.Now(), "")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong key: %d", resp.StatusCode)
	}
	// a second bad signature inside the cooldown is told to come back later, without another fetch
	req, _ = http.NewRequest("POST", inbox, bytes.NewReader(body))
	req.Header.Set("Content-Type", ContentType)
	SignRequest(req, body, a.srv.Self.KeyID, rogue, clk.Now(), "")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("repeated bad signature: %d", resp.StatusCode)
	}
	clk.Advance(11 * time.Second)

	// oversize
	b.srv.MaxBody = 100
	big := append([]byte(`{"id":"x","type":"Relay","actor":"`), bytes.Repeat([]byte("a"), 200)...)
	if c := post(t, inbox, big, nil); c != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize: %d", c)
	}
	b.srv.MaxBody = 0
	b.expectNone()
}

func TestStaleTimestampRejected(t *testing.T) {
	clk := newClock()
	a, b := newNode(t, clk, "aaaaaaaa"), newNode(t, clk, "bbbbbbbb")
	act := a.activity(clk, TypeRelay, b, nil)
	body, _ := json.Marshal(act)
	req, _ := http.NewRequest("POST", b.srv.Self.InboxURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", ContentType)
	SignRequest(req, body, a.srv.Self.KeyID, a.srv.Self.Priv, clk.Now(), "")
	clk.Advance(5*time.Minute + time.Second)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a delivery older than five minutes got %d", resp.StatusCode)
	}
	b.expectNone()
	// the same activity re-sent fresh is fine
	if err := a.client.Send(context.Background(), b.srv.Self.InboxURL, act); err == nil {
		// published time is now six minutes old, so the body itself is stale
		t.Log("note: published time check applies")
	}
}

func TestReplayedActivityHandledOnce(t *testing.T) {
	clk := newClock()
	a, b := newNode(t, clk, "aaaaaaaa"), newNode(t, clk, "bbbbbbbb")
	act := a.activity(clk, TypeRelay, b, nil)
	for i := 0; i < 3; i++ {
		if err := a.client.Send(context.Background(), b.srv.Self.InboxURL, act); err != nil {
			t.Fatal(err)
		}
	}
	b.expect()
	b.expectNone()
}

func TestBlockedSenderIsSilentlyDropped(t *testing.T) {
	clk := newClock()
	a, b := newNode(t, clk, "aaaaaaaa"), newNode(t, clk, "bbbbbbbb")
	if err := b.st.SetBlocked(a.actor(), true); err != nil {
		t.Fatal(err)
	}
	act := a.activity(clk, TypeFollow, b, nil)
	if err := a.client.Send(context.Background(), b.srv.Self.InboxURL, act); err != nil {
		t.Fatalf("a blocked sender should see an ordinary acknowledgement, got %v", err)
	}
	b.expectNone()
	if _, ok := b.st.Peer(a.actor()); ok && !b.st.IsBlocked(a.actor()) {
		t.Fatal("block lost")
	}
}

func TestKeyRotationWithOverlap(t *testing.T) {
	clk := newClock()
	a, b := newNode(t, clk, "aaaaaaaa"), newNode(t, clk, "bbbbbbbb")
	ctx := context.Background()
	if err := a.client.Send(ctx, b.srv.Self.InboxURL, a.activity(clk, TypeRelay, b, nil)); err != nil {
		t.Fatal(err)
	}
	b.expect()

	// A rotates: new key published, old key kept for an hour.
	oldID := a.st.Identity()
	oldPub := ed25519.NewKeyFromSeed(oldID.APPriv).Public().(ed25519.PublicKey)
	seed := make([]byte, 32)
	rand.Read(seed)
	newID := oldID
	newID.APPriv, newID.APKeyID = seed, a.actor()+"#key-2"
	newID.OldAPPub, newID.OldAPKeyID, newID.OldAPUntil = oldPub, oldID.APKeyID, clk.Now().Add(time.Hour)
	a.st.SetIdentity(newID)
	a.client.Self.KeyID, a.client.Self.Priv = newID.APKeyID, ed25519.NewKeyFromSeed(seed)

	doc := a.srv.ActorDocument()
	if doc.PreviousPublicKey == nil || doc.PublicKey.ID != a.actor()+"#key-2" {
		t.Fatalf("actor must publish the new key and the previous one: %+v", doc)
	}
	// B has the old key cached; the new key id is unknown, so B refetches and accepts.
	clk.Advance(11 * time.Second)
	if err := a.client.Send(ctx, b.srv.Self.InboxURL, a.activity(clk, TypeRelay, b, nil)); err != nil {
		t.Fatal(err)
	}
	b.expect()
	p, _ := b.st.Peer(a.actor())
	if p.KeyID != a.actor()+"#key-2" || p.OldKeyID != oldID.APKeyID {
		t.Fatalf("peer record not updated: %+v", p)
	}
	// During the overlap the old key still works.
	oldClient := *a.client
	oldClient.Self.KeyID, oldClient.Self.Priv = oldID.APKeyID, ed25519.NewKeyFromSeed(oldID.APPriv)
	clk.Advance(time.Second)
	if err := oldClient.Send(ctx, b.srv.Self.InboxURL, a.activity(clk, TypeRelay, b, nil)); err != nil {
		t.Fatalf("old key refused during overlap: %v", err)
	}
	b.expect()
	// After the overlap it does not.
	clk.Advance(2 * time.Hour)
	b.st.UpsertPeer(state.Peer{Actor: a.actor()}, 500)
	clk.Advance(11 * time.Second)
	err := oldClient.Send(ctx, b.srv.Self.InboxURL, a.activity(clk, TypeRelay, b, nil))
	var perm *PermanentError
	if !errors.As(err, &perm) {
		t.Fatalf("old key accepted after the overlap: %v", err)
	}
}

func TestActorValidation(t *testing.T) {
	clk := newClock()
	a := newNode(t, clk, "aaaaaaaa")
	good := a.srv.ActorDocument()
	cases := map[string]func(d *ActorDoc){
		"wrong id":        func(d *ActorDoc) { d.ID = "https://elsewhere.example/actor" },
		"bad tag":         func(d *ActorDoc) { d.HomeTag = "XYZ" },
		"foreign inbox":   func(d *ActorDoc) { d.Inbox = "https://evil.example/inbox" },
		"foreign key":     func(d *ActorDoc) { d.PublicKey.Owner = "https://evil.example/actor" },
		"key id off-site": func(d *ActorDoc) { d.PublicKey.ID = "https://evil.example/actor#k" },
		"bad key":         func(d *ActorDoc) { d.PublicKey.PublicKeyMultibase = "z3" },
	}
	for name, mutate := range cases {
		d := good
		mutate(&d)
		if err := ValidateActor(&d, a.actor(), true); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := ValidateActor(&good, a.actor(), true); err != nil {
		t.Fatal(err)
	}
}

func TestClientRefusesPrivateAddressesByDefault(t *testing.T) {
	clk := newClock()
	a := newNode(t, clk, "aaaaaaaa")
	safe := NewClient(a.srv.Self, false, true) // http allowed so only the address check can stop it
	if _, err := safe.FetchActor(context.Background(), a.actor()); err == nil {
		t.Fatal("fetched an actor on a loopback address")
	}
	httpsOnly := NewClient(a.srv.Self, true, false)
	if _, err := httpsOnly.FetchActor(context.Background(), a.actor()); err == nil {
		t.Fatal("fetched an http url with AllowHTTP off")
	}
}

func TestRetriesResignWithFreshTimestampAndStopOnPermanentFailure(t *testing.T) {
	clk := newClock()
	a, b := newNode(t, clk, "aaaaaaaa"), newNode(t, clk, "bbbbbbbb")
	// Teach b about a so only the delivery path is under test.
	if _, err := b.srv.Learn(context.Background(), a.actor(), false); err != nil {
		t.Fatal(err)
	}
	var calls int32
	var created []string
	var mu sync.Mutex
	real := b.hs.Config.Handler
	b.hs.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/inbox" {
			n := atomic.AddInt32(&calls, 1)
			mu.Lock()
			created = append(created, r.Header.Get("Signature-Input"))
			mu.Unlock()
			if n <= 2 {
				http.Error(w, "down", http.StatusServiceUnavailable)
				return
			}
		}
		real.ServeHTTP(w, r)
	})
	out := NewOutbox(a.client)
	out.Sleep = func(ctx context.Context, d time.Duration) error { clk.Advance(d); return nil }
	out.Schedule = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	act := a.activity(clk, TypeRelay, b, nil)
	out.Enqueue(context.Background(), b.srv.Self.InboxURL, act)
	out.Wait()
	b.expect()
	if atomic.LoadInt32(&calls) != 3 {
		t.Fatalf("attempts: %d", calls)
	}
	mu.Lock()
	defer mu.Unlock()
	if created[0] == created[1] || created[1] == created[2] {
		t.Fatalf("each attempt must be signed afresh: %v", created)
	}

	// a 400 is permanent: no retry
	var dropped int32
	atomic.StoreInt32(&calls, 0)
	b.hs.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "no", http.StatusBadRequest)
	})
	out2 := NewOutbox(a.client)
	out2.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	out2.Dropped = func(string, *Activity, error) { atomic.AddInt32(&dropped, 1) }
	out2.Enqueue(context.Background(), b.srv.Self.InboxURL, a.activity(clk, TypeRelay, b, nil))
	out2.Wait()
	if calls != 1 || dropped != 1 {
		t.Fatalf("calls %d dropped %d", calls, dropped)
	}
}

func TestOutboxGivesUpAfterTheLimit(t *testing.T) {
	clk := newClock()
	a := newNode(t, clk, "aaaaaaaa")
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "down", 503) }))
	defer dead.Close()
	out := NewOutbox(a.client)
	var slept time.Duration
	out.Sleep = func(ctx context.Context, d time.Duration) error { slept += d; return nil }
	var dropped int32
	out.Dropped = func(string, *Activity, error) { atomic.AddInt32(&dropped, 1) }
	out.Enqueue(context.Background(), dead.URL+"/inbox", a.activity(clk, TypeRelay, a, nil))
	out.Wait()
	if dropped != 1 {
		t.Fatal("not dropped")
	}
	if slept > GiveUpAfter {
		t.Fatalf("waited %v, more than the 24 hour limit", slept)
	}
	var sum time.Duration
	for _, d := range DefaultSchedule {
		sum += d
	}
	if sum != 22*time.Hour+21*time.Minute+15*time.Second {
		t.Fatalf("default schedule sums to %v", sum)
	}
	if slept != sum {
		t.Fatalf("slept %v, schedule %v", slept, sum)
	}
}

func TestActorEndpointServesDocument(t *testing.T) {
	clk := newClock()
	a := newNode(t, clk, "aaaaaaaa")
	resp, err := http.Get(a.actor())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var d ActorDoc
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatal(err)
	}
	if err := ValidateActor(&d, a.actor(), true); err != nil || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/activity+json") {
		t.Fatalf("%v %s", err, resp.Header.Get("Content-Type"))
	}
}
