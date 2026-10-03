package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Poag/Intermesh/server/internal/ap"
	"github.com/Poag/Intermesh/server/internal/meshcrypto"
	"github.com/Poag/Intermesh/server/internal/meshwire"
	"github.com/Poag/Intermesh/server/internal/mfb"
	"github.com/Poag/Intermesh/server/internal/state"
)

// Gateways publishes downlink packets to border nodes (the MQTT broker).
type Gateways interface {
	// Publish sends a ServiceEnvelope on a channel topic. target is a gateway node id, or
	// empty for every gateway subscribed to the channel.
	Publish(channel, target string, payload []byte) error
}

// Federation delivers activities to other servers and learns about them.
type Federation interface {
	// Enqueue delivers act to inbox in the background. onDrop, if not nil, is called when the
	// delivery is abandoned.
	Enqueue(ctx context.Context, inbox string, act *ap.Activity, onDrop func(error))
	// Learn fetches an actor and records it as a peer.
	Learn(ctx context.Context, actor string, manual bool) (*state.Peer, error)
}

// Event is something the admin console shows.
type Event struct {
	Time    time.Time
	Kind    string // new-server, warning, registration, enrolment
	Message string
}

// Engine is the community server.
type Engine struct {
	cfg  Config
	st   *state.State
	gw   Gateways
	fed  Federation
	log  *slog.Logger
	now  func() time.Time
	self ap.Self // actor URL, inbox URL and key id

	serverNum uint32
	serverID  string // "!a1b2c3d4"
	meshPriv  []byte
	meshPub   []byte

	mu           sync.Mutex
	dedupe       map[uint64]time.Time
	seenNodes    map[uint32]bool
	warned       map[string]bool
	events       []Event
	lastBeacon   time.Time
	lastAnnounce time.Time
	up           *mfb.Reassembler // sealed traffic from roamers, home side
	nodeLimit    *state.RateLimiter
	tagLimit     *state.RateLimiter
	relayLimit   *state.RateLimiter
	learnLimit   *state.RateLimiter
	pending      map[uint32]string // roamer node -> roam activity id, for matching answers
	outbound     map[string]bool   // follow activity ids we sent
}

// New creates an engine. The identity (home tag, mesh key, ActivityPub key) must already
// exist in the state; see EnsureIdentity.
func New(cfg Config, st *state.State, gw Gateways, fed Federation, self ap.Self, log *slog.Logger, now func() time.Time) (*Engine, error) {
	if log == nil {
		log = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	id := st.Identity()
	if len(id.MeshPriv) != 32 || len(id.APPriv) != ed25519.SeedSize || id.HomeTag == "" {
		return nil, errors.New("core: state has no identity; call EnsureIdentity first")
	}
	pub, err := meshcrypto.PublicKey(id.MeshPriv)
	if err != nil {
		return nil, err
	}
	if len(mfb.Tag) == 0 || len(cfg.Name) > mfb.MaxNameLen {
		return nil, fmt.Errorf("core: community name must be 1 to %d characters", mfb.MaxNameLen)
	}
	e := &Engine{
		cfg: cfg, st: st, gw: gw, fed: fed, log: log, now: now, self: self,
		serverNum: meshcrypto.NodeNumFromKey(pub), meshPriv: id.MeshPriv, meshPub: pub,
		dedupe: map[uint64]time.Time{}, seenNodes: map[uint32]bool{}, warned: map[string]bool{},
		up:         mfb.NewReassembler(cfg.MaxParts),
		nodeLimit:  state.NewRateLimiter(cfg.RatePerNode, cfg.RateWindow),
		tagLimit:   state.NewRateLimiter(cfg.RatePerTag, cfg.RateWindow),
		relayLimit: state.NewRateLimiter(cfg.RelayPerMinute, time.Minute),
		learnLimit: state.NewRateLimiter(200, time.Hour),
		pending:    map[uint32]string{}, outbound: map[string]bool{},
	}
	e.serverID = meshcrypto.NodeID(e.serverNum)
	if err := e.ensureRoamChannel(); err != nil {
		return nil, err
	}
	return e, nil
}

// EnsureIdentity creates this server's identity on first run: a random 32-bit home tag, a
// Curve25519 mesh key (the node number is the CRC-32 of its public key, so nodes can trust
// the server's signed NodeInfo) and an Ed25519 key for ActivityPub signatures.
func EnsureIdentity(st *state.State, baseURL string) error {
	id := st.Identity()
	changed := false
	if id.Created.IsZero() {
		id.Created = time.Now().UTC().Truncate(time.Second)
		changed = true
	}
	if id.HomeTag == "" {
		b := make([]byte, 4)
		rand.Read(b)
		id.HomeTag = hex.EncodeToString(b)
		changed = true
	}
	if len(id.MeshPriv) != 32 {
		id.MeshPriv = make([]byte, 32)
		rand.Read(id.MeshPriv)
		changed = true
	}
	if len(id.APPriv) != ed25519.SeedSize {
		id.APPriv = make([]byte, ed25519.SeedSize)
		rand.Read(id.APPriv)
		id.APKeyID = strings.TrimRight(baseURL, "/") + "/actor#main-key"
		changed = true
	}
	if !changed {
		return nil
	}
	return st.SetIdentity(id)
}

// ServerNode returns the node number and id of this server's mesh identity.
func (e *Engine) ServerNode() (uint32, string) { return e.serverNum, e.serverID }

// ServerPublicKey returns the server's Curve25519 public key, which the admin hands out as
// part of the server contact (with the node id).
func (e *Engine) ServerPublicKey() []byte { return append([]byte(nil), e.meshPub...) }

// HomeTag returns the community's current home tag.
func (e *Engine) HomeTag() string { return e.st.Identity().HomeTag }

func (e *Engine) ownTag(tag string) bool {
	if tag == e.HomeTag() {
		return true
	}
	for _, t := range e.st.Identity().Renamed {
		if t == tag {
			return true
		}
	}
	return false
}

// ---- events and warnings ------------------------------------------------------------

func (e *Engine) event(kind, msg string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, Event{Time: e.now(), Kind: kind, Message: msg})
	if len(e.events) > 200 {
		e.events = e.events[len(e.events)-200:]
	}
	e.log.Info(msg, "kind", kind)
}

// warnOnce records an admin console warning the first time key is seen.
func (e *Engine) warnOnce(key, msg string) {
	e.mu.Lock()
	if e.warned[key] {
		e.mu.Unlock()
		return
	}
	e.warned[key] = true
	e.mu.Unlock()
	e.event("warning", msg)
}

// Events returns the console events, oldest first.
func (e *Engine) Events() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Event(nil), e.events...)
}

// ---- channels ------------------------------------------------------------------------

func (e *Engine) ensureRoamChannel() error {
	if _, ok := e.st.Channel(e.cfg.RoamChannel); ok {
		return nil
	}
	key, _ := meshcrypto.ExpandPSK([]byte{1}) // the firmware's well-known default key
	return e.st.SetChannel(state.Channel{Name: e.cfg.RoamChannel, Key: key, Scope: ScopePublic, Uplink: true, Downlink: true})
}

func (e *Engine) roamChannel() *state.Channel {
	c, _ := e.st.Channel(e.cfg.RoamChannel)
	return c
}

func (e *Engine) isRoamChannel(name string) bool { return strings.EqualFold(name, e.cfg.RoamChannel) }

// ---- building packets ------------------------------------------------------------------

func randomID() uint32 {
	var b [4]byte
	for {
		rand.Read(b[:])
		if v := binary.LittleEndian.Uint32(b[:]); v != 0 {
			return v
		}
	}
}

// sign adds an XEdDSA signature to d when the signed encoding would still fit a LoRa frame
// (the same rule the firmware applies before signing). Receivers on the balanced policy drop
// an unsigned broadcast from a node they know signs, so server broadcasts are signed.
func (e *Engine) sign(from, id, to uint32, d *meshwire.Data) {
	probe := *d
	probe.Signature = make([]byte, meshcrypto.SignatureSize)
	if len(probe.Marshal()) > meshcrypto.MaxSignedDataBytes {
		return
	}
	z := make([]byte, 32)
	rand.Read(z)
	if sig, err := meshcrypto.SignXEdDSA(e.meshPriv, from, id, to, d, z); err == nil {
		d.Signature = sig
	}
}

// gatewaysFor returns gateways granted a channel that have connected (so their node id is
// known), optionally only the one named by only, or excluding a gateway.
func (e *Engine) gatewaysFor(channel string, only, except string) []state.Gateway {
	var out []state.Gateway
	for _, g := range e.st.Gateways() {
		if g.NodeID == "" || g.NodeID == except {
			continue
		}
		if only != "" && g.NodeID != only {
			continue
		}
		if spell(g, channel) == "" {
			continue
		}
		out = append(out, g)
	}
	return out
}

// spell returns the name a gateway has the channel under (as granted by the admin), which is
// what the topic and the packet's channel hash must use for that gateway.
func spell(g state.Gateway, channel string) string {
	for _, c := range g.Channels {
		if strings.EqualFold(c, channel) {
			return c
		}
	}
	return ""
}

// sendChannel downlinks one packet on a channel to the given gateways. Each gateway gets the
// packet with the channel hash computed from its own spelling of the channel name.
func (e *Engine) sendChannel(ch *state.Channel, to, port uint32, payload []byte, signed bool, targets []state.Gateway) {
	if !ch.Downlink {
		return
	}
	id := randomID()
	d := &meshwire.Data{Portnum: port, Payload: payload, HasBitfield: true}
	if signed {
		e.sign(e.serverNum, id, to, d)
	}
	enc, err := meshcrypto.CTR(ch.Key, e.serverNum, id, d.Marshal())
	if err != nil {
		e.log.Error("downlink encrypt failed", "channel", ch.Name, "err", err)
		return
	}
	for _, g := range targets {
		name := spell(g, ch.Name)
		env := &meshwire.ServiceEnvelope{
			Packet: &meshwire.MeshPacket{From: e.serverNum, To: to, Channel: uint32(meshcrypto.ChannelHash(name, ch.Key, false)), ID: id,
				Encrypted: enc, HopLimit: e.cfg.HopLimit, HopStart: e.cfg.HopLimit},
			ChannelID: name, GatewayID: e.serverID,
		}
		if err := e.gw.Publish(name, g.NodeID, env.Marshal()); err != nil {
			e.log.Warn("downlink publish failed", "gateway", g.Username, "channel", name, "err", err)
		}
	}
}

// keyFor returns a node's public key from the member registry or learned NodeInfo.
func (e *Engine) keyFor(node uint32) ([]byte, bool) {
	if m, ok := e.st.AnyMember(node); ok {
		return m.PublicKey, true
	}
	return e.st.NodeKey(node)
}

// sendPKI sends a text direct message encrypted to the node's public key, which keeps it
// private from gateways. It returns false if the node's key is unknown. The firmware only
// decrypts such a message if the receiving node already holds the server's public key, so it
// is used where both sides hold each other's keys (enrolment replies). via is the gateway the
// node was last heard through ("" for every connected gateway).
func (e *Engine) sendPKI(node uint32, text, via string) bool {
	key, ok := e.keyFor(node)
	if !ok {
		return false
	}
	id := randomID()
	d := &meshwire.Data{Portnum: meshwire.PortText, Payload: []byte(text), HasBitfield: true}
	var extra [4]byte
	rand.Read(extra[:])
	x := binary.LittleEndian.Uint32(extra[:])
	if x == 0 {
		x = 1
	}
	ct, err := meshcrypto.PKIEncrypt(e.meshPriv, key, e.serverNum, id, x, d.Marshal())
	if err != nil {
		e.log.Warn("pki encrypt failed", "node", meshcrypto.NodeID(node), "err", err)
		return false
	}
	env := &meshwire.ServiceEnvelope{
		Packet: &meshwire.MeshPacket{From: e.serverNum, To: node, ID: id, Encrypted: ct, PKIEncrypted: true,
			HopLimit: e.cfg.HopLimit, HopStart: e.cfg.HopLimit},
		ChannelID: meshwire.PKIChannelID, GatewayID: e.serverID,
	}
	e.publishTo(meshwire.PKIChannelID, via, env.Marshal())
	return true
}

// broadcastText downlinks a text as a broadcast on a channel through the gateway named by
// via, or through every gateway granted the channel if via is empty. It is signed when the
// signed packet would fit, which is the rule the firmware applies when sending and when
// deciding whether an unsigned broadcast from a known signer is a downgrade.
//
// Roaming status and sealed traffic travel this way and not as a text addressed to the node:
// the firmware refuses a channel-encrypted text message addressed to it ("Rejecting legacy
// DM", Router.cpp perhapsDecode), so a unicast would never reach the roamer's app. The
// roamer is named inside the text instead.
func (e *Engine) broadcastText(ch *state.Channel, text, via string) {
	if ch == nil {
		return
	}
	var targets []state.Gateway
	if via != "" {
		targets = e.gatewaysFor(ch.Name, via, "")
	}
	if len(targets) == 0 {
		targets = e.gatewaysFor(ch.Name, "", "")
	}
	e.sendChannel(ch, meshwire.BroadcastNum, meshwire.PortText, []byte(text), true, targets)
}

// publishTo publishes a pre-built envelope on the PKI topic to one gateway, or to every
// connected gateway when via is empty.
func (e *Engine) publishTo(channel, via string, payload []byte) {
	if via != "" {
		if err := e.gw.Publish(channel, via, payload); err != nil {
			e.log.Warn("downlink publish failed", "channel", channel, "gateway", via, "err", err)
		}
		return
	}
	for _, g := range e.st.Gateways() {
		if g.NodeID == "" {
			continue
		}
		if err := e.gw.Publish(channel, g.NodeID, payload); err != nil {
			e.log.Warn("downlink publish failed", "channel", channel, "gateway", g.Username, "err", err)
		}
	}
}

// refuse sends a refusal notice stating the reason. Enrolment refusals go as PKI direct
// messages; roaming refusals as a broadcast on the roaming channel naming the node (see
// broadcastText).
func (e *Engine) refuse(node uint32, code, text, via string, pki bool) {
	if !mfb.ValidCode(code) {
		code = mfb.CodeBadFormat
	}
	line := (&mfb.Refusal{Node: node, Code: code, Text: text}).String()
	if len(line) > mfb.DMLineBudget {
		line = line[:mfb.DMLineBudget]
	}
	if pki && e.sendPKI(node, line, via) {
		return
	}
	e.broadcastText(e.roamChannel(), line, via)
}

func (e *Engine) baseURL() string { return strings.TrimSuffix(e.self.ActorURL, "/actor") }

func nodeHex(n uint32) string { return fmt.Sprintf("%08x", n) }

func backgroundCtx() context.Context { return context.Background() }

// NodeIDFromIdentity returns the server's mesh node id for an identity, so the MQTT broker can
// be built before the engine.
func NodeIDFromIdentity(id state.Identity) (string, error) {
	if len(id.MeshPriv) != 32 {
		return "", errors.New("core: identity has no mesh key")
	}
	pub, err := meshcrypto.PublicKey(id.MeshPriv)
	if err != nil {
		return "", err
	}
	return meshcrypto.NodeID(meshcrypto.NodeNumFromKey(pub)), nil
}
