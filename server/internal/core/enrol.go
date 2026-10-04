package core

import (
	"errors"

	"github.com/Poag/Intermesh/server/internal/broker"
	"github.com/Poag/Intermesh/server/internal/meshcrypto"
	"github.com/Poag/Intermesh/server/internal/meshwire"
	"github.com/Poag/Intermesh/server/internal/mfb"
	"github.com/Poag/Intermesh/server/internal/state"
)

// handlePKI processes a PKI direct message uplinked on the PKI topic. Only messages to the
// server's own node are read; enrolment is the only message the server accepts this way.
func (e *Engine) handlePKI(u broker.Uplink, p *meshwire.MeshPacket) {
	if p.To != e.serverNum || len(p.Encrypted) == 0 {
		return
	}
	key, ok := e.keyFor(p.From)
	if !ok {
		// Gateways uplink the raw encrypted packet, which does not carry the sender's key, so
		// the server can only read a DM from a node whose key it learned from NodeInfo.
		e.warnOnce("nokey:"+meshcrypto.NodeID(p.From), "a direct message from "+meshcrypto.NodeID(p.From)+
			" arrived but its public key is not known; the node must be heard sending NodeInfo on a channel the server holds first")
		return
	}
	plain, err := meshcrypto.PKIDecrypt(e.meshPriv, key, p.From, p.ID, p.Encrypted)
	if err != nil {
		return
	}
	data, err := meshwire.UnmarshalData(plain)
	if err != nil || data.Portnum != meshwire.PortText {
		return
	}
	msg, err := mfb.Parse(string(data.Payload))
	if err != nil {
		if errors.Is(err, mfb.ErrMalformed) {
			e.refuse(p.From, mfb.CodeBadFormat, "", u.GatewayID, true)
		}
		return
	}
	e.heardAtHome(p.From, u.GatewayID)
	if m, ok := msg.(*mfb.Enrol); ok {
		e.enrol(p, key, m, u.GatewayID)
	}
}

// enrol handles "MFB1 E <psk>". The request carries the PSK itself inside a PKI direct
// message, so gateways and visited communities cannot read it (suggested 3 Oct 2026).
func (e *Engine) enrol(p *meshwire.MeshPacket, key []byte, m *mfb.Enrol, via string) {
	node := p.From
	// Replay protection by packet ID stays: a recorded enrolment cannot be replayed.
	if err := e.st.CheckAndRecordPacket(node, p.ID); err != nil {
		return
	}
	reply := func(msg interface{ String() string }) { e.sendPKI(node, msg.String(), via) }
	if e.cfg.Enrolment == EnrolClosed {
		reply(&mfb.Refusal{Node: node, Code: mfb.CodeEnrolClosed})
		return
	}
	var how string
	pending := false
	switch e.cfg.Enrolment {
	case EnrolPublic:
		how = "public"
	case EnrolPSK:
		id, ok := e.st.ConsumePSK(m.PSK)
		if m.PSK == "" || !ok {
			reply(&mfb.Refusal{Node: node, Code: mfb.CodeEnrolPSK})
			return
		}
		how = id
	case EnrolManual:
		if m.PSK == "" {
			how, pending = "", true
		} else if id, ok := e.st.ConsumePSK(m.PSK); ok {
			how = id
		} else {
			reply(&mfb.Refusal{Node: node, Code: mfb.CodeEnrolPSK})
			return
		}
	default:
		reply(&mfb.Refusal{Node: node, Code: mfb.CodeEnrolClosed})
		return
	}
	member, err := e.st.Enrol(node, key, how, pending)
	if errors.Is(err, state.ErrKeyMismatch) {
		reply(&mfb.Refusal{Node: node, Code: mfb.CodeHomeRefused, Text: "node number already enrolled"})
		return
	}
	if err != nil {
		e.log.Error("enrol failed", "node", meshcrypto.NodeID(node), "err", err)
		return
	}
	if member.Pending {
		e.event("enrolment", "node "+meshcrypto.NodeID(node)+" is waiting for approval")
		reply(&mfb.Pending{})
		return
	}
	e.event("enrolment", "node "+meshcrypto.NodeID(node)+" enrolled ("+how+")")
	reply(&mfb.Enrolled{})
}
