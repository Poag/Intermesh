package simmesh

import (
	"errors"
	"fmt"

	"github.com/Poag/Intermesh/server/internal/meshcrypto"
	"github.com/Poag/Intermesh/server/internal/meshwire"
)

// Signature policies, from config.proto PacketSignaturePolicy.
const (
	PolicyCompatible = "compatible" // the default: accept unsigned, drop a wrong signature
	PolicyBalanced   = "balanced"
	PolicyStrict     = "strict"
)

// Receiver applies the accept and drop rules the firmware applies to a packet that reaches a
// node, as read from source (Router.cpp perhapsDecode and checkXeddsaReceivePolicy,
// NodeDB.cpp updateUser). It is deliberately small: only the rules this project depends on.
// Tests use it so they cannot pass with a message the real firmware would refuse.
type Receiver struct {
	Node       *Node
	IgnoreMQTT bool              // lora.ignore_mqtt; on by default in duty-cycle limited regions
	Policy     string            // packet signature policy; empty means compatible
	Licensed   bool              // licensed (ham) nodes accept channel texts addressed to them
	Channels   map[string][]byte // channels the node holds: name to expanded key
	Known      map[uint32][]byte // public keys the node holds for other nodes
	Signers    map[uint32]bool   // nodes it has seen sign
}

// NewReceiver makes a receiver for node holding the given channels.
func NewReceiver(n *Node, channels map[string][]byte) *Receiver {
	return &Receiver{Node: n, Channels: channels, Known: map[uint32][]byte{}, Signers: map[uint32]bool{}}
}

// Hears returns the Data the node's firmware would deliver for a downlinked envelope that a
// gateway rebroadcast over the air (so it carries the via-MQTT flag), or an error naming the
// rule that makes the firmware drop it.
func (r *Receiver) Hears(env *meshwire.ServiceEnvelope) (*meshwire.Data, error) {
	if r.IgnoreMQTT {
		return nil, errors.New("dropped: ignore_mqtt is on and the packet came via MQTT")
	}
	p := env.Packet
	if p.HopStart == 0 {
		return nil, errors.New("dropped: hop_start is zero (pre-hop firmware drop)")
	}
	if env.ChannelID == meshwire.PKIChannelID {
		return r.hearsPKI(p)
	}
	var plain []byte
	var found bool
	for name, key := range r.Channels {
		if meshcrypto.ChannelHash(name, key, false) != byte(p.Channel) {
			continue
		}
		b, err := meshcrypto.CTR(key, p.From, p.ID, p.Encrypted)
		if err != nil {
			continue
		}
		if d, err := meshwire.UnmarshalData(b); err == nil && d.Portnum != 0 {
			plain, found = b, true
			break
		}
	}
	if !found {
		return nil, errors.New("not decodable: no held channel matches")
	}
	d, _ := meshwire.UnmarshalData(plain)
	if !r.Licensed && p.To == r.Node.Num && d.Portnum == meshwire.PortText {
		return nil, errors.New("dropped: rejecting legacy DM (a channel-encrypted text addressed to this node)")
	}
	if err := r.checkSignature(p, d); err != nil {
		return nil, err
	}
	if d.Portnum == meshwire.PortNodeInfo {
		r.learn(p.From, d)
	}
	return d, nil
}

func (r *Receiver) hearsPKI(p *meshwire.MeshPacket) (*meshwire.Data, error) {
	if p.To != r.Node.Num {
		return nil, errors.New("not addressed to this node")
	}
	key, ok := r.Known[p.From]
	if !ok {
		return nil, errors.New("dropped: the node does not hold the sender's public key")
	}
	plain, err := meshcrypto.PKIDecrypt(r.Node.Priv, key, p.From, p.ID, p.Encrypted)
	if err != nil {
		return nil, fmt.Errorf("pki decrypt failed: %w", err)
	}
	return meshwire.UnmarshalData(plain)
}

// learn stores a key from a NodeInfo whose CRC-32 is the sender's node number.
func (r *Receiver) learn(from uint32, d *meshwire.Data) {
	u, err := meshwire.UnmarshalUser(d.Payload)
	if err != nil || len(u.PublicKey) != 32 || meshcrypto.NodeNumFromKey(u.PublicKey) != from {
		return
	}
	if old, ok := r.Known[from]; ok && string(old) != string(u.PublicKey) {
		return // a different key for a node already known is refused
	}
	r.Known[from] = u.PublicKey
}

func (r *Receiver) checkSignature(p *meshwire.MeshPacket, d *meshwire.Data) error {
	strict := r.Policy == PolicyStrict
	balanced := r.Policy == PolicyBalanced
	switch len(d.Signature) {
	case meshcrypto.SignatureSize:
		if key, ok := r.Known[p.From]; ok {
			if !meshcrypto.VerifyXEdDSA(key, p.From, p.ID, p.To, d, d.Signature) {
				return errors.New("dropped: signature does not verify")
			}
			r.Signers[p.From] = true
			return nil
		}
		// first contact: only a NodeInfo whose key hashes to the node number bootstraps
		if d.Portnum == meshwire.PortNodeInfo {
			u, err := meshwire.UnmarshalUser(d.Payload)
			if err != nil || len(u.PublicKey) != 32 || meshcrypto.NodeNumFromKey(u.PublicKey) != p.From ||
				!meshcrypto.VerifyXEdDSA(u.PublicKey, p.From, p.ID, p.To, d, d.Signature) {
				return errors.New("dropped: invalid first-contact NodeInfo signature")
			}
			r.Known[p.From] = u.PublicKey
			r.Signers[p.From] = true
			return nil
		}
		if strict {
			return errors.New("dropped: strict policy and the sender's key is unknown")
		}
		return nil
	case 0:
		if strict {
			return errors.New("dropped: unsigned packet in strict policy")
		}
		if balanced && r.Signers[p.From] && p.To == meshwire.BroadcastNum {
			// an unsigned broadcast that would have fitted signed is a downgrade from a known signer
			probe := *d
			probe.Signature = make([]byte, meshcrypto.SignatureSize)
			if len(probe.Marshal()) <= meshcrypto.MaxSignedDataBytes {
				return errors.New("dropped: unsigned broadcast from a node that previously signed (balanced policy)")
			}
		}
		return nil
	}
	return errors.New("dropped: malformed signature field")
}
