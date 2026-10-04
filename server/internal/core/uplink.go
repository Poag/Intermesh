package core

import (
	"strings"
	"time"

	"github.com/Poag/Intermesh/server/internal/ap"
	"github.com/Poag/Intermesh/server/internal/broker"
	"github.com/Poag/Intermesh/server/internal/meshcrypto"
	"github.com/Poag/Intermesh/server/internal/meshwire"
	"github.com/Poag/Intermesh/server/internal/state"
)

const dedupeWindow = 10 * time.Minute

// firstSight reports whether this (sender, packet id) has not been seen in the dedupe
// window. Several gateways in earshot of one node uplink the same packet, and subscribers
// must dedupe on packet ID (firmware MQTT notes).
func (e *Engine) firstSight(from, id uint32) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	k := uint64(from)<<32 | uint64(id)
	if t, ok := e.dedupe[k]; ok && now.Sub(t) < dedupeWindow {
		return false
	}
	e.dedupe[k] = now
	if len(e.dedupe) > 4096 {
		for kk, t := range e.dedupe {
			if now.Sub(t) >= dedupeWindow {
				delete(e.dedupe, kk)
			}
		}
	}
	return true
}

// HandleUplink processes one packet published by a gateway.
func (e *Engine) HandleUplink(u broker.Uplink) {
	env, err := meshwire.UnmarshalServiceEnvelope(u.Payload)
	if err != nil {
		e.warnOnce("badenv:"+u.Username, "gateway "+u.Username+" published something that is not a service envelope")
		return
	}
	if env.GatewayID != u.GatewayID || !strings.EqualFold(env.ChannelID, u.Channel) {
		e.warnOnce("mismatch:"+u.Username, "gateway "+u.Username+": envelope does not match its topic; dropped")
		return
	}
	p := env.Packet
	if p.ViaMQTT || p.From == 0 || p.From == e.serverNum {
		return
	}
	if !e.firstSight(p.From, p.ID) {
		return
	}
	if u.Channel == meshwire.PKIChannelID {
		e.handlePKI(u, p)
		return
	}
	e.handleChannel(u, p)
}

func (e *Engine) handleChannel(u broker.Uplink, p *meshwire.MeshPacket) {
	ch, ok := e.st.Channel(u.Channel)
	if !ok || !ch.Uplink {
		// Suggested 3 Oct 2026: when a gateway's permissions do not match a channel's settings,
		// drop the traffic and log an error naming the gateway and channel. The admin console
		// shows it too; the gateway is not messaged.
		e.log.Error("uplink dropped: channel not enabled for uplink", "gateway", u.Username, "channel", u.Channel)
		e.warnOnce("perm:"+u.Username+":"+u.Channel, "gateway "+u.Username+" uplinked channel "+u.Channel+", which is not enabled for uplink on the server; traffic dropped")
		return
	}
	if ch.Name != u.Channel {
		e.warnOnce("spell:"+u.Username+":"+u.Channel, "gateway "+u.Username+" spells channel "+ch.Name+" as "+u.Channel+"; downlink matches names exactly, so configure it as "+ch.Name)
	}
	if p.Decoded != nil {
		e.warnOnce("plain:"+u.Username, "gateway "+u.Username+" uplinks unencrypted traffic; MQTT encryption must be enabled on border node gateways, so its packets are dropped")
		return
	}
	if len(p.Encrypted) == 0 {
		return
	}
	if want := meshcrypto.ChannelHash(u.Channel, ch.Key, false); byte(p.Channel) != want {
		e.warnOnce("hash:"+u.Username+":"+u.Channel, "gateway "+u.Username+" channel "+u.Channel+": packet channel hash does not match the server's key or name for it (key mismatch, or AEAD, which is not supported)")
		return
	}
	plain, err := meshcrypto.CTR(ch.Key, p.From, p.ID, p.Encrypted)
	if err != nil {
		return
	}
	data, err := meshwire.UnmarshalData(plain)
	if err != nil {
		return // wrong key or not a Data message
	}
	roam := e.isRoamChannel(ch.Name)

	e.noteNode(p.From, u.GatewayID)
	if !roam {
		e.heardAtHome(p.From, u.GatewayID)
	}
	switch data.Portnum {
	case meshwire.PortNodeInfo:
		e.learnNodeInfo(p.From, data)
	case meshwire.PortText:
		text := string(data.Payload)
		if roam {
			e.handleRoamText(u, p, data, text)
			return
		}
		e.relayCommunity(u, p, ch)
		e.fanoutToRoamers(ch, p.From, text)
	default:
		if !roam {
			e.relayCommunity(u, p, ch)
		}
	}
}

// learnNodeInfo records the public key from a NodeInfo packet when its CRC-32 is the sender's
// node number (the firmware's own first-contact rule).
func (e *Engine) learnNodeInfo(from uint32, data *meshwire.Data) {
	user, err := meshwire.UnmarshalUser(data.Payload)
	if err != nil || len(user.PublicKey) != 32 || meshcrypto.NodeNumFromKey(user.PublicKey) != from {
		return
	}
	if !e.st.LearnKey(from, user.PublicKey) {
		e.warnOnce("keychange:"+meshcrypto.NodeID(from), "node "+meshcrypto.NodeID(from)+" announced a different public key than the one first learned; ignored")
	}
}

// relayCommunity downlinks a community-scope packet to the other gateways granted the
// channel, unchanged (still encrypted with the channel key). Federated and public scopes
// are treated as community in this version; neither crosses to other servers or to the
// public broker yet.
func (e *Engine) relayCommunity(u broker.Uplink, p *meshwire.MeshPacket, ch *state.Channel) {
	if ch.Scope == "" || ch.Scope == ScopeMesh || !ch.Downlink {
		return
	}
	for _, g := range e.gatewaysFor(ch.Name, "", u.GatewayID) {
		name := spell(g, ch.Name)
		out := *p
		out.ViaMQTT = false
		env := &meshwire.ServiceEnvelope{Packet: &out, ChannelID: name, GatewayID: e.serverID}
		if err := e.gw.Publish(name, g.NodeID, env.Marshal()); err != nil {
			e.log.Warn("community relay failed", "gateway", g.Username, "err", err)
		}
	}
}

// noteNode triggers a beacon when a node not seen before is heard, if the admin enabled that.
func (e *Engine) noteNode(node uint32, via string) {
	e.mu.Lock()
	seen := e.seenNodes[node]
	e.seenNodes[node] = true
	if len(e.seenNodes) > 20000 {
		e.seenNodes = map[uint32]bool{node: true}
	}
	e.mu.Unlock()
	if seen || !e.cfg.Beacon.Enabled || !e.cfg.Beacon.OnNewNode || e.st.KnownNode(node) {
		return
	}
	e.maybeBeacon(true)
}

// heardAtHome is called for a packet from a node on a home channel. If the node is a member
// it ends any roaming registrations (the roamer is back) and delivers a pending rename notice.
func (e *Engine) heardAtHome(node uint32, via string) {
	if _, ok := e.st.Member(node); !ok {
		return
	}
	for _, visitor := range e.st.EndAllFor(node) {
		if peer, ok := e.st.Peer(visitor); ok {
			e.sendUndo(*peer, node)
		}
	}
	if tag, ok := e.st.TakeRenameNotice(node); ok {
		// PKI only: a channel text addressed to a node is refused by the firmware, and members have
		// the server's key because they enrolled by direct message.
		e.sendPKI(node, "Community tag changed to "+tag+". Use it for new roaming registrations.", via)
	}
}

func (e *Engine) sendUndo(peer state.Peer, node uint32) {
	act, err := ap.Build(e.baseURL(), e.self.ActorURL, ap.TypeUndo, []string{peer.Actor}, e.now(),
		ap.UndoObject{Type: ap.TypeRoam, Node: nodeHex(node)}, nil)
	if err == nil {
		e.fed.Enqueue(backgroundCtx(), peer.Inbox, act, nil)
	}
}
