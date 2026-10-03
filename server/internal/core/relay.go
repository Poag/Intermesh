package core

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Poag/Intermesh/server/internal/ap"
	"github.com/Poag/Intermesh/server/internal/broker"
	"github.com/Poag/Intermesh/server/internal/meshwire"
	"github.com/Poag/Intermesh/server/internal/mfb"
	"github.com/Poag/Intermesh/server/internal/state"
)

func registrationCtx(node, regPacketID uint32) uint64 { return uint64(node)<<32 | uint64(regPacketID) }

func parsePartField(s string) (part, total int, ok bool) {
	a, b, found := strings.Cut(s, "/")
	if !found {
		return 0, 0, false
	}
	p, err1 := strconv.Atoi(a)
	t, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil || p < 1 || t < 1 || p > t || t > 9 {
		return 0, 0, false
	}
	return p, t, true
}

// ---- visited server, upstream: a roamer's sealed message heard on the roaming channel ------

// handleSealedUp relays a sealed part from a registered roamer to the home server. The visited
// server holds no key for it and cannot read it; it only forwards.
func (e *Engine) handleSealedUp(u broker.Uplink, p *meshwire.MeshPacket, s *mfb.Sealed) {
	if s.Node != p.From {
		return // a roamer can only send sealed traffic as itself
	}
	v, ok := e.st.ActiveVisit(p.From)
	if !ok || !e.relayLimit.Allow("r"+nodeHex(p.From), e.now()) {
		return
	}
	peer, ok := e.st.Peer(v.HomeActor)
	if !ok || peer.Blocked {
		return
	}
	act, err := ap.Build(e.baseURL(), e.self.ActorURL, ap.TypeRelay, []string{peer.Actor}, e.now(), ap.RelayObject{
		Node: nodeHex(s.Node), Direction: ap.DirUp, Kind: ap.KindSealed, Ch: fmt.Sprintf("%02x", s.Ch), Ctr: s.Ctr,
		Part: fmt.Sprintf("%d/%d", s.Part, s.Total), Data: base64.RawURLEncoding.EncodeToString(s.Data),
	}, nil)
	if err == nil {
		e.fed.Enqueue(backgroundCtx(), peer.Inbox, act, nil)
	}
}

// ---- Relay activities --------------------------------------------------------------------

func (e *Engine) handleRelay(from state.Peer, act *ap.Activity) error {
	var ro ap.RelayObject
	if err := act.DecodeObject(&ro); err != nil {
		return &ap.BadActivity{Reason: "bad relay"}
	}
	node, ok := parseNodeHex(ro.Node)
	if !ok {
		return &ap.BadActivity{Reason: "bad node"}
	}
	switch ro.Direction {
	case ap.DirUp:
		return e.relayUpAtHome(from, node, ro)
	case ap.DirDown:
		return e.relayDownAtVisited(from, node, ro)
	}
	return &ap.BadActivity{Reason: "bad direction"}
}

func (e *Engine) homeChannelByNumber(n uint8) (*state.Channel, bool) {
	for _, c := range e.st.Channels() {
		if c.Roaming && c.Number == n {
			cc := c
			return &cc, true
		}
	}
	return nil, false
}

// relayUpAtHome opens one sealed part from a roamer and, once the whole message has arrived,
// delivers it to the roamer's home channel. The key is derived from the home channel key, the
// home tag, the roamer's node number, the accepted registration packet ID and the channel name.
func (e *Engine) relayUpAtHome(from state.Peer, node uint32, ro ap.RelayObject) error {
	if ro.Kind != ap.KindSealed {
		return &ap.BadActivity{Reason: "only sealed traffic travels upstream"}
	}
	reg, ok := e.st.Registration(node, from.Actor)
	if !ok || !reg.Expires.After(e.now()) {
		return nil // no accepted registration for that visited server: nothing to relay
	}
	chNum, err := strconv.ParseUint(ro.Ch, 16, 8)
	part, total, pok := parsePartField(ro.Part)
	data, derr := base64.RawURLEncoding.DecodeString(ro.Data)
	if err != nil || len(ro.Ch) != 2 || !pok || derr != nil || len(data) < 16 {
		return &ap.BadActivity{Reason: "bad sealed part"}
	}
	ch, ok := e.homeChannelByNumber(uint8(chNum))
	if !ok {
		return nil
	}
	key, err := mfb.DeriveKey(ch.Key, e.HomeTag(), node, reg.PacketID, ch.Name, mfb.ToHome)
	if err != nil {
		return nil
	}
	s := &mfb.Sealed{Node: node, Ch: uint8(chNum), Ctr: ro.Ctr, Part: part, Total: total, Data: data}
	text, done, err := e.up.Add(e.now(), registrationCtx(node, reg.PacketID), key, s)
	if err != nil {
		e.log.Info("sealed part refused", "node", nodeHex(node), "err", err)
		return nil
	}
	e.st.TouchRelayed(node, from.Actor)
	if !done {
		return nil
	}
	e.deliverToHome(ch, node, text)
	return nil
}

// deliverToHome posts a roamer's message on its home channel as the server, attributed with
// the roamer's node id. The server cannot post as the roamer: a receiver on the balanced
// signature policy drops an unsigned broadcast from a node it knows signs.
func (e *Engine) deliverToHome(ch *state.Channel, node uint32, text string) {
	line := truncateUTF8(nodeHex(node)+": "+text, mfb.BroadcastLineBudget)
	e.sendChannel(ch, meshwire.BroadcastNum, meshwire.PortText, []byte(line), true, e.gatewaysFor(ch.Name, "", ""))
	e.fanoutToRoamers(ch, node, text)
}

func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// fanoutToRoamers sends a home channel message, sealed, to every roamer of ours who is
// registered with a visited server. Only channels marked for roaming are sent.
func (e *Engine) fanoutToRoamers(ch *state.Channel, sender uint32, text string) {
	if !ch.Roaming {
		return
	}
	per := mfb.MaxPartText(mfb.BroadcastLineBudget)
	line := truncateUTF8(nodeHex(sender)+": "+text, per*e.cfg.MaxParts)
	now := e.now()
	for _, reg := range e.st.Registrations() {
		if reg.Node == sender || !reg.Expires.After(now) {
			continue
		}
		peer, ok := e.st.Peer(reg.Visitor)
		if !ok || peer.Blocked {
			continue
		}
		parts := (len(line) + per - 1) / per
		start, err := e.st.NextDownCounter(reg.Node, reg.Visitor, parts)
		if err != nil {
			continue
		}
		key, err := mfb.DeriveKey(ch.Key, e.HomeTag(), reg.Node, reg.PacketID, ch.Name, mfb.ToRoamer)
		if err != nil {
			continue
		}
		sealed, _, err := mfb.SealText(key, reg.Node, ch.Number, start, line, mfb.BroadcastLineBudget, e.cfg.MaxParts)
		if err != nil {
			continue
		}
		for _, s := range sealed {
			act, err := ap.Build(e.baseURL(), e.self.ActorURL, ap.TypeRelay, []string{peer.Actor}, now, ap.RelayObject{
				Node: nodeHex(reg.Node), Direction: ap.DirDown, Kind: ap.KindSealed, Ch: fmt.Sprintf("%02x", s.Ch), Ctr: s.Ctr,
				Part: fmt.Sprintf("%d/%d", s.Part, s.Total), Data: base64.RawURLEncoding.EncodeToString(s.Data),
			}, nil)
			if err == nil {
				e.fed.Enqueue(backgroundCtx(), peer.Inbox, act, nil)
			}
		}
	}
}

// relayDownAtVisited downlinks traffic from a roamer's home server. The visited server routes
// by the registration it recorded; it never has the keys and cannot read sealed parts.
func (e *Engine) relayDownAtVisited(from state.Peer, node uint32, ro ap.RelayObject) error {
	v, ok := e.st.ActiveVisit(node)
	if !ok || v.HomeActor != from.Actor {
		return nil
	}
	switch ro.Kind {
	case ap.KindSealed:
		chNum, err := strconv.ParseUint(ro.Ch, 16, 8)
		part, total, pok := parsePartField(ro.Part)
		data, derr := base64.RawURLEncoding.DecodeString(ro.Data)
		if err != nil || len(ro.Ch) != 2 || !pok || derr != nil || len(data) < 16 {
			return &ap.BadActivity{Reason: "bad sealed part"}
		}
		line := (&mfb.Sealed{Node: node, Ch: uint8(chNum), Ctr: ro.Ctr, Part: part, Total: total, Data: data}).String()
		if len(line) > mfb.BroadcastLineBudget {
			return &ap.BadActivity{Reason: "sealed part too long"}
		}
		e.broadcastText(e.roamChannel(), line, v.Via)
	case ap.KindPacket:
		raw, err := base64.StdEncoding.DecodeString(ro.Packet)
		if err != nil {
			return &ap.BadActivity{Reason: "bad packet"}
		}
		p, err := meshwire.UnmarshalMeshPacket(raw)
		if err != nil || p.To != node || len(p.Encrypted) == 0 {
			return &ap.BadActivity{Reason: "bad packet"}
		}
		name := meshwire.PKIChannelID
		if !p.PKIEncrypted {
			name = e.roamChannel().Name
		}
		out := *p
		if out.HopLimit == 0 {
			out.HopLimit, out.HopStart = e.cfg.HopLimit, e.cfg.HopLimit
		}
		env := &meshwire.ServiceEnvelope{Packet: &out, ChannelID: name, GatewayID: e.serverID}
		e.publishTo(name, v.Via, env.Marshal())
	default:
		return &ap.BadActivity{Reason: "bad kind"}
	}
	return nil
}
