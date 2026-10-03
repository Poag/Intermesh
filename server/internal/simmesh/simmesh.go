// Package simmesh simulates mesh nodes for tests: it builds the packets a Meshtastic node
// sends (signed, channel-encrypted or PKI-encrypted) wrapped as a gateway would publish
// them, and decodes what the server downlinks. It is test support, not part of the server.
package simmesh

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/Poag/Intermesh/server/internal/meshcrypto"
	"github.com/Poag/Intermesh/server/internal/meshwire"
)

// Node is a simulated node with its own key pair.
type Node struct {
	Priv, Pub []byte
	Num       uint32
}

// NewNode makes a node with a fresh key; its number is the CRC-32 of its public key.
func NewNode() *Node {
	priv := make([]byte, 32)
	rand.Read(priv)
	pub, _ := meshcrypto.PublicKey(priv)
	return &Node{Priv: priv, Pub: pub, Num: meshcrypto.NodeNumFromKey(pub)}
}

// ID is the node id as gateways write it.
func (n *Node) ID() string { return meshcrypto.NodeID(n.Num) }

// RandomID returns a nonzero random packet id.
func RandomID() uint32 {
	var b [4]byte
	for {
		rand.Read(b[:])
		if v := binary.LittleEndian.Uint32(b[:]); v != 0 {
			return v
		}
	}
}

// ChannelUplink builds the ServiceEnvelope a gateway publishes for a packet this node sent on a channel.
func (n *Node) ChannelUplink(t testing.TB, chName string, key []byte, gatewayID string, port uint32, payload []byte, to uint32, signed bool, packetID uint32) []byte {
	t.Helper()
	if packetID == 0 {
		packetID = RandomID()
	}
	d := &meshwire.Data{Portnum: port, Payload: payload, HasBitfield: true, Bitfield: meshwire.BitfieldOKToMQTT}
	if signed {
		z := make([]byte, 32)
		rand.Read(z)
		sig, err := meshcrypto.SignXEdDSA(n.Priv, n.Num, packetID, to, d, z)
		if err != nil {
			t.Fatal(err)
		}
		d.Signature = sig
	}
	enc, err := meshcrypto.CTR(key, n.Num, packetID, d.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	env := &meshwire.ServiceEnvelope{
		Packet: &meshwire.MeshPacket{From: n.Num, To: to, Channel: uint32(meshcrypto.ChannelHash(chName, key, false)), ID: packetID,
			Encrypted: enc, HopLimit: 3, HopStart: 3},
		ChannelID: chName, GatewayID: gatewayID,
	}
	return env.Marshal()
}

// NodeInfoUplink is the NodeInfo broadcast a node sends, carrying its public key.
func (n *Node) NodeInfoUplink(t testing.TB, chName string, key []byte, gatewayID string) []byte {
	u := &meshwire.User{ID: n.ID(), LongName: "sim " + n.ID(), ShortName: "SIM", PublicKey: n.Pub}
	return n.ChannelUplink(t, chName, key, gatewayID, meshwire.PortNodeInfo, u.Marshal(), meshwire.BroadcastNum, true, 0)
}

// DMUplink is a PKI direct message to another node, uplinked raw on the PKI topic.
func (n *Node) DMUplink(t testing.TB, toNum uint32, toPub []byte, text, gatewayID string) []byte {
	t.Helper()
	id := RandomID()
	d := &meshwire.Data{Portnum: meshwire.PortText, Payload: []byte(text), HasBitfield: true}
	var x [4]byte
	rand.Read(x[:])
	ct, err := meshcrypto.PKIEncrypt(n.Priv, toPub, n.Num, id, binary.LittleEndian.Uint32(x[:])|1, d.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	env := &meshwire.ServiceEnvelope{
		Packet:    &meshwire.MeshPacket{From: n.Num, To: toNum, ID: id, Encrypted: ct, PKIEncrypted: true, HopLimit: 3, HopStart: 3},
		ChannelID: meshwire.PKIChannelID, GatewayID: gatewayID,
	}
	return env.Marshal()
}

// OpenPKI decodes a downlinked PKI envelope addressed to this node, as its firmware would.
func (n *Node) OpenPKI(env *meshwire.ServiceEnvelope, senderPub []byte) (string, error) {
	pk := env.Packet
	plain, err := meshcrypto.PKIDecrypt(n.Priv, senderPub, pk.From, pk.ID, pk.Encrypted)
	if err != nil {
		return "", err
	}
	d, err := meshwire.UnmarshalData(plain)
	if err != nil {
		return "", err
	}
	return string(d.Payload), nil
}

// OpenChannel decodes a downlinked channel envelope with the channel key.
func OpenChannel(env *meshwire.ServiceEnvelope, key []byte) (*meshwire.Data, error) {
	plain, err := meshcrypto.CTR(key, env.Packet.From, env.Packet.ID, env.Packet.Encrypted)
	if err != nil {
		return nil, err
	}
	return meshwire.UnmarshalData(plain)
}
