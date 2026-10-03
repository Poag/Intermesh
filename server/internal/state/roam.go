package state

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ---- Peers -------------------------------------------------------------------

// UpsertPeer adds or updates a peer. When the list holds more than cap entries after the
// insert, the least recently heard unblocked peer is dropped (blocked peers stay so that
// a block is never silently undone by eviction).
func (st *State) UpsertPeer(p Peer, cap int) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := st.now()
	if old, ok := st.s.Peers[p.Actor]; ok {
		if p.HomeTag != "" && p.HomeTag != old.HomeTag {
			old.Aliases = appendUnique(old.Aliases, old.HomeTag)
			old.HomeTag = p.HomeTag
		}
		if p.Inbox != "" {
			old.Inbox = p.Inbox
		}
		if p.KeyID != "" {
			old.KeyID, old.PublicKey = p.KeyID, p.PublicKey
			old.OldKeyID, old.OldKey, old.OldUntil = p.OldKeyID, p.OldKey, p.OldUntil
		}
		if !p.Created.IsZero() {
			old.Created = p.Created
		}
		old.LastHeard = now
		old.Manual = old.Manual || p.Manual
		return st.persist()
	}
	cp := p
	cp.FirstSeen, cp.LastHeard = now, now
	st.s.Peers[p.Actor] = &cp
	for cap > 0 && len(st.s.Peers) > cap {
		var victim *Peer
		for _, q := range st.s.Peers {
			if q.Blocked || q.Actor == p.Actor {
				continue
			}
			if victim == nil || q.LastHeard.Before(victim.LastHeard) {
				victim = q
			}
		}
		if victim == nil {
			break
		}
		delete(st.s.Peers, victim.Actor)
	}
	return st.persist()
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// Peer returns a peer by actor URL.
func (st *State) Peer(actor string) (*Peer, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	p, ok := st.s.Peers[actor]
	if !ok {
		return nil, false
	}
	cp := *p
	return &cp, true
}

// PeersByTag returns unblocked peers holding tag now or as a remembered alias.
func (st *State) PeersByTag(tag string) []Peer {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []Peer
	for _, p := range st.s.Peers {
		if p.Blocked {
			continue
		}
		if p.HomeTag == tag {
			out = append(out, *p)
			continue
		}
		for _, a := range p.Aliases {
			if a == tag {
				out = append(out, *p)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Actor < out[j].Actor })
	return out
}

// Peers lists all peers.
func (st *State) Peers() []Peer {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]Peer, 0, len(st.s.Peers))
	for _, p := range st.s.Peers {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Actor < out[j].Actor })
	return out
}

// SetBlocked blocks or unblocks a peer.
func (st *State) SetBlocked(actor string, blocked bool) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	p, ok := st.s.Peers[actor]
	if !ok {
		if !blocked {
			return nil
		}
		// Blocking a server that is not yet known still records the block.
		st.s.Peers[actor] = &Peer{Actor: actor, Blocked: true, FirstSeen: st.now(), LastHeard: st.now()}
		return st.persist()
	}
	p.Blocked = blocked
	return st.persist()
}

// IsBlocked reports whether actor is blocked.
func (st *State) IsBlocked(actor string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	p, ok := st.s.Peers[actor]
	return ok && p.Blocked
}

// ApplyRename changes a peer's tag. It is accepted only from the actor already known as
// holding oldTag, and the old tag is kept as an alias (SPEC.md Rename).
func (st *State) ApplyRename(actor, oldTag, newTag string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	p, ok := st.s.Peers[actor]
	if !ok || p.HomeTag != oldTag {
		return errors.New("state: rename not from the server holding the old tag")
	}
	p.Aliases = appendUnique(p.Aliases, oldTag)
	p.HomeTag = newTag
	p.LastHeard = st.now()
	return st.persist()
}

// ---- Visiting roamers (this server is the visited community) -----------------------------

// BeginVisit records a registration waiting for the home server's answer. It takes no slot.
func (st *State) BeginVisit(v Visit) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	cp := v
	cp.Accepted = false
	cp.Started = st.now()
	st.s.Visits[v.Node] = &cp
	return st.persist()
}

// AcceptVisit marks a visit accepted until expires, holding a slot from now on.
func (st *State) AcceptVisit(node uint32, expires time.Time, pub []byte) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	v, ok := st.s.Visits[node]
	if !ok {
		return errors.New("state: no pending visit")
	}
	v.Accepted, v.Expires = true, expires
	if len(pub) > 0 {
		v.PublicKey = append([]byte(nil), pub...)
	}
	return st.persist()
}

// EndVisit removes a visit.
func (st *State) EndVisit(node uint32) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.s.Visits, node)
	_ = st.persist()
}

// Visit returns the visit for a node.
func (st *State) Visit(node uint32) (*Visit, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	v, ok := st.s.Visits[node]
	if !ok {
		return nil, false
	}
	cp := *v
	return &cp, true
}

// ActiveVisit returns an accepted, unexpired visit.
func (st *State) ActiveVisit(node uint32) (*Visit, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	v, ok := st.s.Visits[node]
	if !ok || !v.Accepted || !v.Expires.After(st.now()) {
		return nil, false
	}
	cp := *v
	return &cp, true
}

// Visits lists visits.
func (st *State) Visits() []Visit {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]Visit, 0, len(st.s.Visits))
	for _, v := range st.s.Visits {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

// SlotsInUse counts accepted, unexpired visits. Pending visits take no slot.
func (st *State) SlotsInUse() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := st.now()
	n := 0
	for _, v := range st.s.Visits {
		if v.Accepted && v.Expires.After(now) {
			n++
		}
	}
	return n
}

// PendingVisits counts visits still waiting for the home server.
func (st *State) PendingVisits() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	n := 0
	for _, v := range st.s.Visits {
		if !v.Accepted {
			n++
		}
	}
	return n
}

// ExpireVisits removes expired visits and pending visits older than pendingTimeout, and
// returns the removed accepted ones so the caller can send Undo to their home servers.
func (st *State) ExpireVisits(pendingTimeout time.Duration) []Visit {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := st.now()
	var gone []Visit
	for n, v := range st.s.Visits {
		switch {
		case v.Accepted && !v.Expires.After(now):
			gone = append(gone, *v)
			delete(st.s.Visits, n)
		case !v.Accepted && now.Sub(v.Started) >= pendingTimeout:
			delete(st.s.Visits, n)
		}
	}
	if len(gone) > 0 {
		_ = st.persist()
	}
	return gone
}

// ---- Registrations of our own roamers (this server is the home community) ------------------------

func regKey(node uint32, visitor string) string { return fmt.Sprintf("%08x/%s", node, visitor) }

func packetKey(node, id uint32) string { return fmt.Sprintf("%08x/%08x", node, id) }

// MaxRegistrationDays is the longest registration, fixed at one week by the spec.
const MaxRegistrationDays = 7

// ErrRepeat is returned when a registration packet ID has been accepted before.
var ErrRepeat = errors.New("state: registration packet id already seen")

// CheckAndRecordPacket records a registration packet ID, refusing repeats. Retention is
// applied by Prune.
func (st *State) CheckAndRecordPacket(node, id uint32) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	k := packetKey(node, id)
	if _, seen := st.s.SeenPackets[k]; seen {
		return ErrRepeat
	}
	st.s.SeenPackets[k] = st.now()
	return st.persist()
}

// AcceptRegistration records an accepted registration of one of our nodes with a visited
// server and returns its expiry (now plus days, at most a week).
func (st *State) AcceptRegistration(node uint32, visitor string, packetID uint32, days int) (*Registration, error) {
	if days < 1 || days > MaxRegistrationDays {
		return nil, fmt.Errorf("state: days %d out of range", days)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	now := st.now()
	k := regKey(node, visitor)
	r, ok := st.s.Registrations[k]
	if !ok {
		r = &Registration{Node: node, Visitor: visitor}
		st.s.Registrations[k] = r
	}
	r.PacketID, r.Accepted, r.Expires = packetID, now, now.Add(time.Duration(days)*24*time.Hour)
	// Counters survive a re-registration only within the same packet ID; a new registration
	// derives new keys, so they restart at zero.
	r.UpCounter, r.DownCounter = 0, 0
	cp := *r
	return &cp, st.persist()
}

// Registration returns one registration.
func (st *State) Registration(node uint32, visitor string) (*Registration, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	r, ok := st.s.Registrations[regKey(node, visitor)]
	if !ok {
		return nil, false
	}
	cp := *r
	return &cp, true
}

// EndRegistration removes a registration (Undo, or expiry).
func (st *State) EndRegistration(node uint32, visitor string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	k := regKey(node, visitor)
	if _, ok := st.s.Registrations[k]; !ok {
		return false
	}
	delete(st.s.Registrations, k)
	_ = st.persist()
	return true
}

// EndAllFor removes every registration of a node and returns the visited servers, so Undo
// can be sent. Used when the roamer is heard on the home mesh again.
func (st *State) EndAllFor(node uint32) []string {
	st.mu.Lock()
	defer st.mu.Unlock()
	var visitors []string
	for k, r := range st.s.Registrations {
		if r.Node == node {
			visitors = append(visitors, r.Visitor)
			delete(st.s.Registrations, k)
		}
	}
	if len(visitors) > 0 {
		_ = st.persist()
	}
	sort.Strings(visitors)
	return visitors
}

// RouteFor picks the visited server to reply through: the registration that relayed a
// message from the roamer last (or, if none has, the most recently accepted one).
func (st *State) RouteFor(node uint32) (*Registration, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := st.now()
	var best *Registration
	for _, r := range st.s.Registrations {
		if r.Node != node || !r.Expires.After(now) {
			continue
		}
		if best == nil || latest(r).After(latest(best)) {
			best = r
		}
	}
	if best == nil {
		return nil, false
	}
	cp := *best
	return &cp, true
}

func latest(r *Registration) time.Time {
	if r.LastRelayed.After(r.Accepted) {
		return r.LastRelayed
	}
	return r.Accepted
}

// TouchRelayed records that a visited server relayed a message from the roamer.
func (st *State) TouchRelayed(node uint32, visitor string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if r, ok := st.s.Registrations[regKey(node, visitor)]; ok {
		r.LastRelayed = st.now()
		_ = st.persist()
	}
}

// NextDownCounter reserves the next counter for sealed traffic towards the roamer and
// persists it before returning, so a crash can never reuse a nonce.
func (st *State) NextDownCounter(node uint32, visitor string, parts int) (uint64, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	r, ok := st.s.Registrations[regKey(node, visitor)]
	if !ok {
		return 0, errors.New("state: no such registration")
	}
	start := r.DownCounter
	r.DownCounter += uint64(parts)
	return start, st.persist()
}

// ExpireRegistrations removes expired registrations and returns them.
func (st *State) ExpireRegistrations() []Registration {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := st.now()
	var gone []Registration
	for k, r := range st.s.Registrations {
		if !r.Expires.After(now) {
			gone = append(gone, *r)
			delete(st.s.Registrations, k)
		}
	}
	if len(gone) > 0 {
		_ = st.persist()
	}
	return gone
}

// Registrations lists registrations of our nodes.
func (st *State) Registrations() []Registration {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]Registration, 0, len(st.s.Registrations))
	for _, r := range st.s.Registrations {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Node != out[j].Node {
			return out[i].Node < out[j].Node
		}
		return strings.Compare(out[i].Visitor, out[j].Visitor) < 0
	})
	return out
}

// ---- Replay memory -------------------------------------------------------------------

// SeenActivity records an activity ID and reports whether it had already been seen.
func (st *State) SeenActivity(id string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.s.SeenActivities[id]; ok {
		return true
	}
	st.s.SeenActivities[id] = st.now()
	return false
}

// Prune forgets registration packet IDs older than packetRetention and activity IDs older
// than activityRetention. Packet retention is one week plus the admin's margin.
func (st *State) Prune(packetRetention, activityRetention time.Duration) {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := st.now()
	for k, t := range st.s.SeenPackets {
		if now.Sub(t) > packetRetention {
			delete(st.s.SeenPackets, k)
		}
	}
	for k, t := range st.s.SeenActivities {
		if now.Sub(t) > activityRetention {
			delete(st.s.SeenActivities, k)
		}
	}
	_ = st.persist()
}

// ---- Rate limiting ------------------------------------------------------------------

// RateLimiter is a fixed-window counter per key, used for the per node and per home tag
// registration limits. It is in-memory: a restart resets it, which is acceptable for a
// brake on junk registrations.
type RateLimiter struct {
	limit  int
	window time.Duration
	hits   map[string][]time.Time
}

// NewRateLimiter allows limit events per key per window. A limit of zero or less disables it.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{limit: limit, window: window, hits: map[string][]time.Time{}}
}

// Allow records an event for key and reports whether it is within the limit.
func (r *RateLimiter) Allow(key string, now time.Time) bool {
	if r.limit <= 0 {
		return true
	}
	cut := now.Add(-r.window)
	h := r.hits[key][:0]
	for _, t := range r.hits[key] {
		if t.After(cut) {
			h = append(h, t)
		}
	}
	if len(h) >= r.limit {
		r.hits[key] = h
		return false
	}
	r.hits[key] = append(h, now)
	return true
}

// RemovePeer deletes a peer (used when an admin-made link is undone).
func (st *State) RemovePeer(actor string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.s.Peers, actor)
	_ = st.persist()
}

// QueueRenameNotices records that every current member must be told the community's new
// tag the next time their node is heard.
func (st *State) QueueRenameNotices(newTag string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for n, m := range st.s.Members {
		if !m.Pending {
			st.s.RenameNotices[n] = newTag
		}
	}
	_ = st.persist()
}

// TakeRenameNotice returns and clears the pending notice for a node.
func (st *State) TakeRenameNotice(node uint32) (string, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	t, ok := st.s.RenameNotices[node]
	if ok {
		delete(st.s.RenameNotices, node)
		_ = st.persist()
	}
	return t, ok
}

// KnownNode reports whether a node has been seen before: it is a member, a visitor, or its
// key was learned. Used for the "new node detected" beacon trigger.
func (st *State) KnownNode(node uint32) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.s.Members[node]; ok {
		return true
	}
	if _, ok := st.s.Visits[node]; ok {
		return true
	}
	_, ok := st.s.NodeKeys[node]
	return ok
}

// BlockedTag reports whether a blocked peer holds (or held) the tag.
func (st *State) BlockedTag(tag string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, p := range st.s.Peers {
		if !p.Blocked {
			continue
		}
		if p.HomeTag == tag {
			return true
		}
		for _, a := range p.Aliases {
			if a == tag {
				return true
			}
		}
	}
	return false
}
