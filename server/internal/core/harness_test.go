package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Poag/Intermesh/server/internal/ap"
	"github.com/Poag/Intermesh/server/internal/broker"
	"github.com/Poag/Intermesh/server/internal/meshcrypto"
	"github.com/Poag/Intermesh/server/internal/meshwire"
	"github.com/Poag/Intermesh/server/internal/mfb"
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

// ---- fake gateways ---------------------------------------------------------------------

type pub struct {
	Channel, Target string
	Payload         []byte
}

type fakeGW struct {
	mu  sync.Mutex
	out []pub
}

func (f *fakeGW) Publish(channel, target string, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.out = append(f.out, pub{channel, target, append([]byte(nil), payload...)})
	return nil
}

func (f *fakeGW) all() []pub {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]pub(nil), f.out...)
}

func (f *fakeGW) clear() { f.mu.Lock(); f.out = nil; f.mu.Unlock() }

// ---- simulated mesh node (firmware-faithful packet building) ------------------------------------

type simNode struct {
	priv, pub []byte
	num       uint32
}

func newSimNode() *simNode {
	priv := make([]byte, 32)
	rand.Read(priv)
	pub, _ := meshcrypto.PublicKey(priv)
	return &simNode{priv: priv, pub: pub, num: meshcrypto.NodeNumFromKey(pub)}
}

func (n *simNode) id() string { return meshcrypto.NodeID(n.num) }

// channelUplink builds the ServiceEnvelope a gateway publishes for a broadcast this node sent
// on a channel: signed (as firmware 2.8 does when it fits) and encrypted with the channel key.
func (n *simNode) channelUplink(t *testing.T, chName string, key []byte, gatewayID string, port uint32, payload []byte, to uint32, signed bool, packetID uint32) []byte {
	t.Helper()
	if packetID == 0 {
		packetID = randomID()
	}
	d := &meshwire.Data{Portnum: port, Payload: payload, HasBitfield: true, Bitfield: meshwire.BitfieldOKToMQTT}
	if signed {
		z := make([]byte, 32)
		rand.Read(z)
		sig, err := meshcrypto.SignXEdDSA(n.priv, n.num, packetID, to, d, z)
		if err != nil {
			t.Fatal(err)
		}
		d.Signature = sig
	}
	enc, err := meshcrypto.CTR(key, n.num, packetID, d.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	env := &meshwire.ServiceEnvelope{
		Packet: &meshwire.MeshPacket{From: n.num, To: to, Channel: uint32(meshcrypto.ChannelHash(chName, key, false)), ID: packetID,
			Encrypted: enc, HopLimit: 3, HopStart: 3},
		ChannelID: chName, GatewayID: gatewayID,
	}
	return env.Marshal()
}

// nodeInfoUplink is the NodeInfo broadcast every node sends, carrying its public key.
func (n *simNode) nodeInfoUplink(t *testing.T, chName string, key []byte, gatewayID string) []byte {
	u := &meshwire.User{ID: n.id(), LongName: "sim " + n.id(), ShortName: "SIM", PublicKey: n.pub}
	return n.channelUplink(t, chName, key, gatewayID, meshwire.PortNodeInfo, u.Marshal(), meshwire.BroadcastNum, true, 0)
}

// dmUplink is a PKI direct message to another node, uplinked raw (still encrypted) on the PKI topic.
func (n *simNode) dmUplink(t *testing.T, toNum uint32, toPub []byte, text, gatewayID string) []byte {
	t.Helper()
	id := randomID()
	d := &meshwire.Data{Portnum: meshwire.PortText, Payload: []byte(text), HasBitfield: true}
	var x [4]byte
	rand.Read(x[:])
	extra := binary.LittleEndian.Uint32(x[:]) | 1
	ct, err := meshcrypto.PKIEncrypt(n.priv, toPub, n.num, id, extra, d.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	env := &meshwire.ServiceEnvelope{
		Packet:    &meshwire.MeshPacket{From: n.num, To: toNum, ID: id, Encrypted: ct, PKIEncrypted: true, HopLimit: 3, HopStart: 3},
		ChannelID: meshwire.PKIChannelID, GatewayID: gatewayID,
	}
	return env.Marshal()
}

type heard struct {
	From, To uint32
	Text     string
	Port     uint32
	Signed   bool
	Target   string
	Channel  string
}

// decodeChannel decodes every downlink on chName that the key opens.
func decodeChannel(t *testing.T, pubs []pub, chName string, key []byte) []heard {
	t.Helper()
	var out []heard
	for _, p := range pubs {
		if p.Channel == meshwire.PKIChannelID || !strings.EqualFold(p.Channel, chName) {
			continue
		}
		env, err := meshwire.UnmarshalServiceEnvelope(p.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if want := meshcrypto.ChannelHash(env.ChannelID, key, false); byte(env.Packet.Channel) != want {
			continue
		}
		plain, _ := meshcrypto.CTR(key, env.Packet.From, env.Packet.ID, env.Packet.Encrypted)
		d, err := meshwire.UnmarshalData(plain)
		if err != nil {
			continue
		}
		out = append(out, heard{From: env.Packet.From, To: env.Packet.To, Text: string(d.Payload), Port: d.Portnum,
			Signed: len(d.Signature) == 64, Target: p.Target, Channel: env.ChannelID})
	}
	return out
}

// decodePKI decodes downlinked PKI direct messages addressed to node, as its firmware would.
func decodePKI(t *testing.T, pubs []pub, node *simNode, serverNum uint32, serverPub []byte) []heard {
	t.Helper()
	var out []heard
	for _, p := range pubs {
		if p.Channel != meshwire.PKIChannelID {
			continue
		}
		env, err := meshwire.UnmarshalServiceEnvelope(p.Payload)
		if err != nil {
			t.Fatal(err)
		}
		pk := env.Packet
		if pk.To != node.num || !pk.PKIEncrypted {
			continue
		}
		plain, err := meshcrypto.PKIDecrypt(node.priv, serverPub, pk.From, pk.ID, pk.Encrypted)
		if err != nil {
			t.Fatalf("node cannot decrypt a PKI downlink: %v", err)
		}
		d, _ := meshwire.UnmarshalData(plain)
		out = append(out, heard{From: pk.From, To: pk.To, Text: string(d.Payload), Target: p.Target})
	}
	return out
}

// ---- a community site -------------------------------------------------------------------------

type site struct {
	t    *testing.T
	st   *state.State
	gw   *fakeGW
	eng  *Engine
	srv  *ap.Server
	out  *ap.Outbox
	hs   *httptest.Server
	cfg  Config
	gwID string
	home *state.Channel
	// override lets a test replace the federation handler without racing the HTTP goroutines.
	override atomic.Pointer[func(ctx context.Context, from state.Peer, act *ap.Activity) error]
}

func newSite(t *testing.T, clk *fakeClock, name string, mod func(*Config)) *site {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Name = name
	cfg.RoamingOpen = true
	cfg.AnnounceInterval = 0
	if mod != nil {
		mod(&cfg)
	}
	st, err := state.Open("", clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	s := &site{t: t, st: st, gw: &fakeGW{}, cfg: cfg}
	s.hs = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.srv.Routes().ServeHTTP(w, r) }))
	t.Cleanup(s.hs.Close)
	base := s.hs.URL
	if err := EnsureIdentity(st, base); err != nil {
		t.Fatal(err)
	}
	id := st.Identity()
	id.Created = clk.Now()
	st.SetIdentity(id)
	priv := ed25519.NewKeyFromSeed(id.APPriv)
	self := ap.Self{ActorURL: base + "/actor", InboxURL: base + "/inbox", KeyID: id.APKeyID, Priv: priv}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := ap.NewClient(self, true, true)
	client.Now, client.Log = clk.Now, quiet
	s.srv = &ap.Server{State: st, Client: client, Self: self, Name: name, Published: id.Created,
		HomeTag: func() string { return st.Identity().HomeTag }, Now: clk.Now, PeerCap: cfg.PeerCap, Log: quiet}
	s.out = ap.NewOutbox(client)
	s.out.Sleep = func(ctx context.Context, d time.Duration) error { clk.Advance(d); return nil }
	eng, err := New(cfg, st, s.gw, NewFederation(s.out, s.srv), self, quiet, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	s.eng = eng
	s.srv.Handle = func(ctx context.Context, from state.Peer, act *ap.Activity) error {
		if f := s.override.Load(); f != nil {
			return (*f)(ctx, from, act)
		}
		return eng.HandleActivity(ctx, from, act)
	}
	s.srv.OnNewPeer = eng.OnNewPeer
	s.srv.OnPeer = eng.OnPeer

	// a home channel for community traffic and roaming, and one connected gateway
	key := make([]byte, 16)
	rand.Read(key)
	home := state.Channel{Name: "Home", Number: 1, Roaming: true, Key: key, Scope: ScopeCommunity, Uplink: true, Downlink: true}
	st.SetChannel(home)
	s.home = &home
	s.gwID = "!aabbcc01"
	st.SetGateway(state.Gateway{Username: "gw", Channels: []string{"Home", cfg.RoamChannel}, NodeID: s.gwID, Created: clk.Now()})
	return s
}

func (s *site) actor() string     { return s.srv.Self.ActorURL }
func (s *site) roamKey() []byte   { return s.eng.roamChannel().Key }
func (s *site) serverPub() []byte { return s.eng.ServerPublicKey() }
func (s *site) serverNum() uint32 { n, _ := s.eng.ServerNode(); return n }
func (s *site) uplink(chName string, payload []byte) {
	s.eng.HandleUplink(broker.Uplink{Username: "gw", GatewayID: s.gwID, Channel: chName, Payload: payload})
}

func (s *site) wait() {
	s.t.Helper()
	// let every queued delivery finish, including those queued by handlers while waiting
	for i := 0; i < 50; i++ {
		s.out.Wait()
		time.Sleep(10 * time.Millisecond)
		if s.out.Pending() == 0 {
			return
		}
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 10, 4, 3, 0, 0, 0, time.UTC)} }

var _ = mfb.Tag
