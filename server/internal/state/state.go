// Package state holds the community server's durable state: enrolled members,
// enrolment PSKs, roaming registrations (as home and as visited server), known
// peer servers, replay memory, channels and gateways. It is one mutex-guarded
// struct persisted as JSON; a reference server for a community of a few hundred
// nodes does not need more.
package state

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// PSKKind is the type of an enrolment PSK (SPEC.md section 3, enrolment DM).
type PSKKind string

const (
	PSKNonExpiring PSKKind = "non-expiring"
	PSKRotating    PSKKind = "rotating"
	PSKSingleUse   PSKKind = "single-use"
	PSKMultiUse    PSKKind = "multi-use" // multi-use with an expiry
)

// PSK is an enrolment pre-shared key the admin hands out of band.
type PSK struct {
	ID           string        `json:"id"`
	Kind         PSKKind       `json:"kind"`
	Secret       string        `json:"secret"`
	Label        string        `json:"label,omitempty"`
	Created      time.Time     `json:"created"`
	Expires      time.Time     `json:"expires,omitempty"`
	Period       time.Duration `json:"period,omitempty"`
	NextRotation time.Time     `json:"nextRotation,omitempty"`
	Uses         int           `json:"uses"`
	Revoked      bool          `json:"revoked,omitempty"`
}

// DefaultRotation is the default period of a rotating PSK (decided 3 Oct 2026).
const DefaultRotation = 7 * 24 * time.Hour

// Member is a node enrolled with this server as its home.
type Member struct {
	Node      uint32    `json:"node"`
	PublicKey []byte    `json:"publicKey"`
	Enrolled  time.Time `json:"enrolled"`
	Pending   bool      `json:"pending,omitempty"` // waiting for manual admin approval
	Via       string    `json:"via,omitempty"`     // "public", a PSK id, or "admin"
}

// Peer is another community server.
type Peer struct {
	Actor     string    `json:"actor"`
	HomeTag   string    `json:"homeTag"`
	Inbox     string    `json:"inbox"`
	KeyID     string    `json:"keyId"`
	PublicKey []byte    `json:"publicKey"`          // Ed25519, from the actor document
	OldKeyID  string    `json:"oldKeyId,omitempty"` // previous key, accepted until OldUntil
	OldKey    []byte    `json:"oldKey,omitempty"`
	OldUntil  time.Time `json:"oldUntil,omitempty"`
	Created   time.Time `json:"created,omitempty"` // when the peer's identity was created (published on its actor)
	FirstSeen time.Time `json:"firstSeen"`
	LastHeard time.Time `json:"lastHeard"`
	Blocked   bool      `json:"blocked,omitempty"`
	Manual    bool      `json:"manual,omitempty"` // linked by hand rather than learned by Introduce
	Aliases   []string  `json:"aliases,omitempty"`
}

// Visit is a roamer registered with this server as the visited community.
type Visit struct {
	Node        uint32    `json:"node"`
	HomeActor   string    `json:"homeActor"`
	HomeTag     string    `json:"homeTag"`
	RegPacketID uint32    `json:"regPacketId"`
	PublicKey   []byte    `json:"publicKey,omitempty"`
	Expires     time.Time `json:"expires"`
	Via         string    `json:"via,omitempty"` // gateway node id the registration came through
	Name        string    `json:"-"`
	Accepted    bool      `json:"accepted"` // false while waiting for the home server's answer
	Started     time.Time `json:"started"`
}

// Registration is a roamer of ours registered with a visited server.
type Registration struct {
	Node         uint32    `json:"node"`
	Visitor      string    `json:"visitor"` // visited server actor
	PacketID     uint32    `json:"packetId"`
	Expires      time.Time `json:"expires"`
	LastRelayed  time.Time `json:"lastRelayed"`
	Accepted     time.Time `json:"accepted"`
	UpCounter    uint64    `json:"upCounter"`
	DownCounter  uint64    `json:"downCounter"`
	ChannelNames []string  `json:"channels,omitempty"`
}

// Channel is a mesh channel the server holds the key for.
type Channel struct {
	Name           string `json:"name"`
	Key            []byte `json:"key"`   // expanded key; empty means no encryption
	Scope          string `json:"scope"` // mesh, community, federated or public
	Uplink         bool   `json:"uplink"`
	Downlink       bool   `json:"downlink"`
	RetentionHours int    `json:"retentionHours,omitempty"`
}

// Gateway is a border node's MQTT credential, limited to named channels.
type Gateway struct {
	Username string    `json:"username"`
	PassHash []byte    `json:"passHash"`
	Salt     []byte    `json:"salt"`
	Channels []string  `json:"channels"`
	NodeID   string    `json:"nodeId,omitempty"` // learned from its first message
	Created  time.Time `json:"created"`
}

// Identity is this server's key material.
type Identity struct {
	HomeTag    string    `json:"homeTag"`
	MeshPriv   []byte    `json:"meshPriv"` // Curve25519
	APPriv     []byte    `json:"apPriv"`   // Ed25519 seed
	APKeyID    string    `json:"apKeyId"`
	OldAPPub   []byte    `json:"oldApPub,omitempty"` // accepted until OldAPUntil during rotation
	OldAPKeyID string    `json:"oldApKeyId,omitempty"`
	OldAPUntil time.Time `json:"oldApUntil,omitempty"`
	Renamed    []string  `json:"formerTags,omitempty"`
}

type snapshot struct {
	Identity       Identity                 `json:"identity"`
	Members        map[uint32]*Member       `json:"members"`
	PSKs           map[string]*PSK          `json:"psks"`
	Peers          map[string]*Peer         `json:"peers"`
	Visits         map[uint32]*Visit        `json:"visits"`
	Registrations  map[string]*Registration `json:"registrations"` // key: node/visitor
	SeenPackets    map[string]time.Time     `json:"seenPackets"`   // accepted registration packet ids
	SeenActivities map[string]time.Time     `json:"seenActivities"`
	Channels       map[string]*Channel      `json:"channels"`
	Gateways       map[string]*Gateway      `json:"gateways"`
	NodeKeys       map[uint32][]byte        `json:"nodeKeys"` // public keys learned from NodeInfo
}

// State is the server's durable state.
type State struct {
	mu   sync.Mutex
	path string
	s    snapshot
	now  func() time.Time
}

// Open loads state from path, or starts empty if the file does not exist. An empty path
// keeps state in memory only (tests).
func Open(path string, now func() time.Time) (*State, error) {
	if now == nil {
		now = time.Now
	}
	st := &State{path: path, now: now}
	st.s = newSnapshot()
	if path == "" {
		return st, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &st.s); err != nil {
		return nil, fmt.Errorf("state: %s: %w", path, err)
	}
	st.fill()
	return st, nil
}

func newSnapshot() snapshot {
	var s snapshot
	fillMaps(&s)
	return s
}

func (st *State) fill() { fillMaps(&st.s) }

func fillMaps(s *snapshot) {
	if s.Members == nil {
		s.Members = map[uint32]*Member{}
	}
	if s.PSKs == nil {
		s.PSKs = map[string]*PSK{}
	}
	if s.Peers == nil {
		s.Peers = map[string]*Peer{}
	}
	if s.Visits == nil {
		s.Visits = map[uint32]*Visit{}
	}
	if s.Registrations == nil {
		s.Registrations = map[string]*Registration{}
	}
	if s.SeenPackets == nil {
		s.SeenPackets = map[string]time.Time{}
	}
	if s.SeenActivities == nil {
		s.SeenActivities = map[string]time.Time{}
	}
	if s.Channels == nil {
		s.Channels = map[string]*Channel{}
	}
	if s.Gateways == nil {
		s.Gateways = map[string]*Gateway{}
	}
	if s.NodeKeys == nil {
		s.NodeKeys = map[uint32][]byte{}
	}
}

// persist writes the snapshot atomically. The caller holds the lock.
func (st *State) persist() error {
	if st.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(&st.s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(st.path)
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), st.path)
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// randomSecret returns n random bytes as lowercase base32 (printable, no spaces).
func randomSecret(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return strings.ToLower(b32.EncodeToString(b))
}

// Identity returns a copy of the server identity.
func (st *State) Identity() Identity {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.s.Identity
}

// SetIdentity replaces the server identity.
func (st *State) SetIdentity(id Identity) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.s.Identity = id
	return st.persist()
}

// ---- PSKs ------------------------------------------------------------------

// NewPSK creates an enrolment PSK. For PSKRotating the period defaults to 7 days;
// for PSKMultiUse an expiry is required.
func (st *State) NewPSK(kind PSKKind, label string, period time.Duration, expires time.Time) (*PSK, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := st.now()
	p := &PSK{ID: randomSecret(5), Kind: kind, Secret: randomSecret(10), Label: label, Created: now}
	switch kind {
	case PSKNonExpiring, PSKSingleUse:
	case PSKRotating:
		if period <= 0 {
			period = DefaultRotation
		}
		p.Period, p.NextRotation = period, now.Add(period)
	case PSKMultiUse:
		if !expires.After(now) {
			return nil, errors.New("state: multi-use PSK needs a future expiry")
		}
		p.Expires = expires
	default:
		return nil, fmt.Errorf("state: unknown PSK kind %q", kind)
	}
	st.s.PSKs[p.ID] = p
	cp := *p
	return &cp, st.persist()
}

// rotateLocked advances rotating PSKs whose period has elapsed. After a rotation only
// the current secret is accepted.
func (st *State) rotateLocked(now time.Time) {
	for _, p := range st.s.PSKs {
		if p.Kind != PSKRotating || p.Revoked {
			continue
		}
		for !p.NextRotation.After(now) {
			p.Secret = randomSecret(10)
			p.NextRotation = p.NextRotation.Add(p.Period)
			if p.Period <= 0 {
				break
			}
		}
	}
}

// RevokePSK stops new enrolments with the PSK. Enrolled nodes are unaffected.
func (st *State) RevokePSK(id string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	p, ok := st.s.PSKs[id]
	if !ok {
		return errors.New("state: no such PSK")
	}
	p.Revoked = true
	return st.persist()
}

// PSKs lists PSKs, applying any due rotation first so the current secret is shown.
func (st *State) PSKs() []PSK {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.rotateLocked(st.now())
	_ = st.persist()
	out := make([]PSK, 0, len(st.s.PSKs))
	for _, p := range st.s.PSKs {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// ConsumePSK checks a presented secret and, if it is acceptable, records the use. It
// returns the PSK id. A single-use PSK is consumed by the first success.
func (st *State) ConsumePSK(secret string) (string, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := st.now()
	st.rotateLocked(now)
	var found *PSK
	for _, p := range st.s.PSKs {
		if subtle.ConstantTimeCompare([]byte(p.Secret), []byte(secret)) == 1 {
			found = p
		}
	}
	if found == nil || found.Revoked {
		return "", false
	}
	if found.Kind == PSKMultiUse && !found.Expires.After(now) {
		return "", false
	}
	if found.Kind == PSKSingleUse && found.Uses > 0 {
		return "", false
	}
	found.Uses++
	_ = st.persist()
	return found.ID, true
}

// ---- Members -----------------------------------------------------------------

// ErrKeyMismatch is returned when a node number is already bound to a different public key.
var ErrKeyMismatch = errors.New("state: node number is already enrolled with a different key")

// Enrol records a member. A node number already bound to a different key is refused, so
// a later claimant cannot replace the first key (SE2 in the firmware edits log).
func (st *State) Enrol(node uint32, pub []byte, via string, pending bool) (*Member, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if m, ok := st.s.Members[node]; ok {
		if string(m.PublicKey) != string(pub) {
			return nil, ErrKeyMismatch
		}
		if m.Pending && !pending {
			m.Pending, m.Via = false, via
			_ = st.persist()
		}
		cp := *m
		return &cp, nil
	}
	m := &Member{Node: node, PublicKey: append([]byte(nil), pub...), Enrolled: st.now(), Pending: pending, Via: via}
	st.s.Members[node] = m
	cp := *m
	return &cp, st.persist()
}

// Approve clears a member's pending flag.
func (st *State) Approve(node uint32) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	m, ok := st.s.Members[node]
	if !ok {
		return errors.New("state: no such member")
	}
	m.Pending = false
	m.Via = "admin"
	return st.persist()
}

// RemoveMember deletes a member and any registrations of theirs.
func (st *State) RemoveMember(node uint32) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.s.Members[node]; !ok {
		return errors.New("state: no such member")
	}
	delete(st.s.Members, node)
	for k, r := range st.s.Registrations {
		if r.Node == node {
			delete(st.s.Registrations, k)
		}
	}
	return st.persist()
}

// Member returns an enrolled (not pending) member.
func (st *State) Member(node uint32) (*Member, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	m, ok := st.s.Members[node]
	if !ok || m.Pending {
		return nil, false
	}
	cp := *m
	return &cp, true
}

// AnyMember returns a member whether or not pending.
func (st *State) AnyMember(node uint32) (*Member, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	m, ok := st.s.Members[node]
	if !ok {
		return nil, false
	}
	cp := *m
	return &cp, true
}

// Members lists all members.
func (st *State) Members() []Member {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]Member, 0, len(st.s.Members))
	for _, m := range st.s.Members {
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

// LearnKey records a public key seen in a NodeInfo packet, if its CRC-32 matches the
// node number (the caller checks that). The first key for a node number wins.
func (st *State) LearnKey(node uint32, pub []byte) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if old, ok := st.s.NodeKeys[node]; ok {
		return string(old) == string(pub)
	}
	st.s.NodeKeys[node] = append([]byte(nil), pub...)
	_ = st.persist()
	return true
}

// NodeKey returns a key learned from NodeInfo.
func (st *State) NodeKey(node uint32) ([]byte, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	k, ok := st.s.NodeKeys[node]
	return append([]byte(nil), k...), ok
}

// ---- Channels and gateways ---------------------------------------------------

// SetChannel adds or replaces a channel.
func (st *State) SetChannel(c Channel) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	cp := c
	st.s.Channels[strings.ToLower(c.Name)] = &cp
	return st.persist()
}

// Channel looks a channel up by name, case-insensitively as the firmware does for its
// own lookup. Use ExactName to know the spelling to publish with.
func (st *State) Channel(name string) (*Channel, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	c, ok := st.s.Channels[strings.ToLower(name)]
	if !ok {
		return nil, false
	}
	cp := *c
	return &cp, true
}

// Channels lists channels.
func (st *State) Channels() []Channel {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]Channel, 0, len(st.s.Channels))
	for _, c := range st.s.Channels {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SetGateway adds or replaces a gateway credential.
func (st *State) SetGateway(g Gateway) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	cp := g
	st.s.Gateways[g.Username] = &cp
	return st.persist()
}

// Gateway looks a gateway up by username.
func (st *State) Gateway(username string) (*Gateway, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	g, ok := st.s.Gateways[username]
	if !ok {
		return nil, false
	}
	cp := *g
	return &cp, true
}

// Gateways lists gateways.
func (st *State) Gateways() []Gateway {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]Gateway, 0, len(st.s.Gateways))
	for _, g := range st.s.Gateways {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// NoteGatewayNode records the node ID a gateway connected with.
func (st *State) NoteGatewayNode(username, nodeID string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if g, ok := st.s.Gateways[username]; ok && g.NodeID != nodeID {
		g.NodeID = nodeID
		_ = st.persist()
	}
}
