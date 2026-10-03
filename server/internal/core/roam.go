package core

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/Poag/Intermesh/server/internal/ap"
	"github.com/Poag/Intermesh/server/internal/broker"
	"github.com/Poag/Intermesh/server/internal/meshcrypto"
	"github.com/Poag/Intermesh/server/internal/meshwire"
	"github.com/Poag/Intermesh/server/internal/mfb"
	"github.com/Poag/Intermesh/server/internal/state"
)

func parseNodeHex(s string) (uint32, bool) {
	if len(s) != 8 {
		return 0, false
	}
	b, err := hex.DecodeString(s)
	if err != nil || s != hex.EncodeToString(b) {
		return 0, false
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), true
}

// ---- visited server: messages heard on the roaming channel -------------------------------

// handleRoamText processes an MFB1 line heard on the roaming channel.
func (e *Engine) handleRoamText(u broker.Uplink, p *meshwire.MeshPacket, data *meshwire.Data, text string) {
	msg, err := mfb.Parse(text)
	if err != nil {
		if errors.Is(err, mfb.ErrMalformed) && e.nodeLimit.Allow("bf"+nodeHex(p.From), e.now()) {
			e.refuse(p.From, mfb.CodeBadFormat, "", u.GatewayID, false)
		}
		return
	}
	switch m := msg.(type) {
	case *mfb.Roam:
		e.handleRegistration(u, p, data, m)
	case *mfb.Sealed:
		e.handleSealedUp(u, p, m)
	}
}

// handleRegistration is the visited server's side of "MFB1 R <hometag> <days>". It checks
// what it can see itself, then asks the home server; it relays nothing for the roamer until
// the home server accepts (decided 3 Oct 2026).
func (e *Engine) handleRegistration(u broker.Uplink, p *meshwire.MeshPacket, data *meshwire.Data, m *mfb.Roam) {
	node, via, now := p.From, u.GatewayID, e.now()
	deny := func(code, text string) { e.refuse(node, code, text, via, false) }

	if !e.cfg.RoamingOpen {
		deny(mfb.CodeCommunityClosed, "")
		return
	}
	if !e.nodeLimit.Allow("n"+nodeHex(node), now) {
		deny(mfb.CodeRepeat, "too many attempts")
		return
	}
	if e.ownTag(m.HomeTag) {
		return // the roamer is registering with its own community
	}
	if len(data.Signature) != meshcrypto.SignatureSize {
		deny(mfb.CodeUnsigned, "firmware 2.8 is required")
		return
	}
	if v, ok := e.st.Visit(node); ok && v.RegPacketID == p.ID {
		return // the same registration, heard again
	}
	if !e.tagLimit.Allow("t"+m.HomeTag, now) {
		deny(mfb.CodeNoSlots, "too many registrations for that community")
		return
	}
	if e.st.SlotsInUse() >= e.cfg.RoamingSlots || e.st.PendingVisits() >= e.cfg.MaxPendingVisits {
		deny(mfb.CodeNoSlots, "")
		return
	}
	peers := e.st.PeersByTag(m.HomeTag)
	if len(peers) == 0 {
		if e.st.BlockedTag(m.HomeTag) {
			deny(mfb.CodeBlocked, "")
		} else {
			deny(mfb.CodeHomeUnknown, "")
		}
		return
	}
	peer := peers[0]
	for _, c := range peers[1:] {
		if c.LastHeard.After(peer.LastHeard) {
			peer = c
		}
	}
	days := m.Days
	if days == 0 {
		days = e.cfg.DefaultDays
	}
	if err := e.st.BeginVisit(state.Visit{Node: node, HomeActor: peer.Actor, HomeTag: m.HomeTag, RegPacketID: p.ID, Via: via}); err != nil {
		e.log.Error("begin visit failed", "err", err)
		return
	}
	act, err := ap.Build(e.baseURL(), e.self.ActorURL, ap.TypeRoam, []string{peer.Actor}, now, ap.RoamObject{
		Node: nodeHex(node), HomeTag: m.HomeTag, PacketID: p.ID, Days: days,
		Packet: base64.StdEncoding.EncodeToString(p.Marshal()),
	}, nil)
	if err != nil {
		e.st.EndVisit(node)
		return
	}
	e.mu.Lock()
	e.pending[node] = act.ID
	e.mu.Unlock()
	e.fed.Enqueue(backgroundCtx(), peer.Inbox, act, func(error) { e.roamUndeliverable(node, act.ID) })
}

// roamUndeliverable runs when the Roam could not be delivered within the retry limit.
func (e *Engine) roamUndeliverable(node uint32, id string) {
	e.mu.Lock()
	cur := e.pending[node]
	if cur == id {
		delete(e.pending, node)
	}
	e.mu.Unlock()
	if cur != id {
		return
	}
	if v, ok := e.st.Visit(node); ok && !v.Accepted {
		e.st.EndVisit(node)
		e.refuse(node, mfb.CodeHomeUnknown, "home server not reachable", v.Via, false)
	}
}

// ---- visited server: the home server's answer -------------------------------------------

func (e *Engine) handleAnswer(from state.Peer, act *ap.Activity) error {
	var ref ap.UndoObject
	if err := act.DecodeObject(&ref); err != nil || ref.Type != ap.TypeRoam {
		return nil // an Accept or Reject of something other than a Roam (a Follow, handled elsewhere)
	}
	node, ok := parseNodeHex(ref.Node)
	if !ok {
		return &ap.BadActivity{Reason: "bad node"}
	}
	e.mu.Lock()
	want := e.pending[node]
	e.mu.Unlock()
	v, found := e.st.Visit(node)
	if !found || v.Accepted || v.HomeActor != from.Actor || want == "" || want != ref.ID {
		return nil // not an answer to a Roam we are waiting on
	}
	e.mu.Lock()
	delete(e.pending, node)
	e.mu.Unlock()

	if act.Type == ap.TypeReject {
		var r ap.RejectResult
		_ = act.DecodeResult(&r)
		e.st.EndVisit(node)
		e.refuse(node, r.Code, r.Text, v.Via, false)
		return nil
	}
	var res ap.AcceptResult
	if err := act.DecodeResult(&res); err != nil {
		return &ap.BadActivity{Reason: "accept without a result"}
	}
	expires, err := time.Parse(time.RFC3339, res.Expires)
	if err != nil || res.Days < 1 || res.Days > state.MaxRegistrationDays {
		return &ap.BadActivity{Reason: "accept with a bad expiry"}
	}
	if latest := e.now().Add(state.MaxRegistrationDays * 24 * time.Hour); expires.After(latest) {
		expires = latest // the longest registration is one week
	}
	var pub []byte
	if res.PublicKey != "" {
		if k, err := base64.StdEncoding.DecodeString(res.PublicKey); err == nil && len(k) == 32 && meshcrypto.NodeNumFromKey(k) == node {
			pub = k
			e.st.LearnKey(node, k)
		}
	}
	if err := e.st.AcceptVisit(node, expires, pub); err != nil {
		return err
	}
	e.event("registration", "roamer "+nodeHex(node)+" from community "+v.HomeTag+" registered for "+strconv.Itoa(res.Days)+" days")
	line := (&mfb.Confirm{Node: node, HomeTag: v.HomeTag, Days: res.Days, Name: e.cfg.Name}).String()
	e.broadcastText(e.roamChannel(), line, v.Via)
	return nil
}

// ---- home server: a visited server asks to register one of our nodes -------------------------

func (e *Engine) rejectRoam(to state.Peer, node uint32, roamID, code, text string) {
	act, err := ap.Build(e.baseURL(), e.self.ActorURL, ap.TypeReject, []string{to.Actor}, e.now(),
		ap.UndoObject{Type: ap.TypeRoam, ID: roamID, Node: nodeHex(node)}, ap.RejectResult{Code: code, Text: text})
	if err == nil {
		e.fed.Enqueue(backgroundCtx(), to.Inbox, act, nil)
	}
}

// handleRoam verifies a Roam: the forwarded packet's XEdDSA signature against the enrolled
// node's key, enrolment, a repeated packet ID, and the requested days. It answers with Accept
// or Reject. The visited server never holds the roamer's keys or the home channel keys.
func (e *Engine) handleRoam(from state.Peer, act *ap.Activity) error {
	var o ap.RoamObject
	if err := act.DecodeObject(&o); err != nil {
		return &ap.BadActivity{Reason: "bad roam"}
	}
	node, ok := parseNodeHex(o.Node)
	if !ok {
		return &ap.BadActivity{Reason: "bad node"}
	}
	rej := func(code, text string) error { e.rejectRoam(from, node, act.ID, code, text); return nil }

	if !e.ownTag(o.HomeTag) {
		return rej(mfb.CodeHomeUnknown, "not this community")
	}
	if o.Days < 1 || o.Days > state.MaxRegistrationDays {
		return rej(mfb.CodeBadFormat, "")
	}
	raw, err := base64.StdEncoding.DecodeString(o.Packet)
	if err != nil {
		return rej(mfb.CodeBadFormat, "")
	}
	p, err := meshwire.UnmarshalMeshPacket(raw)
	if err != nil || len(p.Encrypted) == 0 || p.From != node || p.ID != o.PacketID {
		return rej(mfb.CodeBadFormat, "")
	}
	rc := e.roamChannel()
	if rc == nil {
		return rej(mfb.CodeCommunityClosed, "roaming channel not configured")
	}
	plain, err := meshcrypto.CTR(rc.Key, p.From, p.ID, p.Encrypted)
	if err != nil {
		return rej(mfb.CodeBadFormat, "")
	}
	data, err := meshwire.UnmarshalData(plain)
	if err != nil || data.Portnum != meshwire.PortText {
		return rej(mfb.CodeBadFormat, "")
	}
	msg, err := mfb.Parse(string(data.Payload))
	r, isRoam := msg.(*mfb.Roam)
	if err != nil || !isRoam || !e.ownTag(r.HomeTag) {
		return rej(mfb.CodeBadFormat, "")
	}
	member, isMember := e.st.Member(node)
	if !isMember {
		return rej(mfb.CodeHomeRefused, "node not enrolled")
	}
	if len(data.Signature) != meshcrypto.SignatureSize {
		return rej(mfb.CodeUnsigned, "")
	}
	if !meshcrypto.VerifyXEdDSA(member.PublicKey, p.From, p.ID, p.To, data, data.Signature) {
		return rej(mfb.CodeUnsigned, "signature does not verify")
	}
	days := o.Days
	if r.Days != 0 && days > r.Days {
		days = r.Days // the roamer chose a shorter stay than the visited community's default
	}
	if err := e.st.CheckAndRecordPacket(node, p.ID); err != nil {
		return rej(mfb.CodeRepeat, "")
	}
	reg, err := e.st.AcceptRegistration(node, from.Actor, p.ID, days)
	if err != nil {
		return err
	}
	out, err := ap.Build(e.baseURL(), e.self.ActorURL, ap.TypeAccept, []string{from.Actor}, e.now(),
		ap.UndoObject{Type: ap.TypeRoam, ID: act.ID, Node: o.Node},
		ap.AcceptResult{Expires: reg.Expires.UTC().Format(time.RFC3339), Days: days, PublicKey: base64.StdEncoding.EncodeToString(member.PublicKey)})
	if err != nil {
		return err
	}
	e.fed.Enqueue(backgroundCtx(), from.Inbox, out, nil)
	e.event("registration", "node "+o.Node+" registered with "+from.Actor+" for "+strconv.Itoa(days)+" days")
	return nil
}

// handleUndo ends a registration early, from either side.
func (e *Engine) handleUndo(from state.Peer, act *ap.Activity) error {
	var ref ap.UndoObject
	if err := act.DecodeObject(&ref); err != nil {
		return &ap.BadActivity{Reason: "bad undo"}
	}
	switch ref.Type {
	case ap.TypeRoam:
		node, ok := parseNodeHex(ref.Node)
		if !ok {
			return &ap.BadActivity{Reason: "bad node"}
		}
		e.st.EndRegistration(node, from.Actor) // we are the home server
		if v, ok := e.st.Visit(node); ok && v.HomeActor == from.Actor {
			e.st.EndVisit(node) // we are the visited server
		}
	case ap.TypeFollow:
		if p, ok := e.st.Peer(from.Actor); ok && p.Manual {
			e.st.RemovePeer(from.Actor)
		}
	}
	return nil
}
