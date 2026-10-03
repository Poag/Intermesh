// Package meshwire is a minimal protobuf codec for the few Meshtastic messages
// the community server touches: ServiceEnvelope, MeshPacket, Data and User.
//
// Field numbers come from meshtastic/protobufs (master, commit 95c5f8c1,
// 3 Oct 2026): mesh.proto and mqtt.proto. Unknown fields are skipped on decode.
// Only the fields listed here are carried; this is not a general codec.
package meshwire

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	PortText     = 1
	PortNodeInfo = 4
	PortPrivate  = 256

	// BroadcastNum is the destination of a broadcast packet.
	BroadcastNum uint32 = 0xffffffff

	// BitfieldOKToMQTT is bit 0 of Data.bitfield (BITFIELD_OK_TO_MQTT_MASK in Router.h).
	BitfieldOKToMQTT uint32 = 1 << 0
	// BitfieldWantResponse is bit 1 of Data.bitfield.
	BitfieldWantResponse uint32 = 1 << 1

	// PKIChannelID is the ServiceEnvelope channel_id used for PKI direct messages.
	PKIChannelID = "PKI"

	// HopMax is HOP_MAX in MeshTypes.h.
	HopMax = 7
)

// Data is meshtastic.Data.
type Data struct {
	Portnum      uint32
	Payload      []byte
	WantResponse bool
	Dest         uint32
	Source       uint32
	RequestID    uint32
	ReplyID      uint32
	Emoji        uint32
	Bitfield     uint32
	HasBitfield  bool
	Signature    []byte // xeddsa_signature, 0 or 64 bytes
}

// MeshPacket is meshtastic.MeshPacket, restricted to the fields used here.
type MeshPacket struct {
	From         uint32
	To           uint32
	Channel      uint32
	Decoded      *Data
	Encrypted    []byte
	ID           uint32
	HopLimit     uint32
	WantAck      bool
	ViaMQTT      bool
	HopStart     uint32
	PublicKey    []byte
	PKIEncrypted bool
	NextHop      uint32
	RelayNode    uint32
}

// ServiceEnvelope is meshtastic.ServiceEnvelope (mqtt.proto).
type ServiceEnvelope struct {
	Packet    *MeshPacket
	ChannelID string
	GatewayID string
}

// User is meshtastic.User, restricted to the fields used here.
type User struct {
	ID        string
	LongName  string
	ShortName string
	PublicKey []byte
}

func appendFixed32(b []byte, num protowire.Number, v uint32) []byte {
	if v == 0 {
		return b
	}
	b = protowire.AppendTag(b, num, protowire.Fixed32Type)
	return protowire.AppendFixed32(b, v)
}

func appendVarintField(b []byte, num protowire.Number, v uint64) []byte {
	if v == 0 {
		return b
	}
	b = protowire.AppendTag(b, num, protowire.VarintType)
	return protowire.AppendVarint(b, v)
}

func appendBool(b []byte, num protowire.Number, v bool) []byte {
	if !v {
		return b
	}
	return appendVarintField(b, num, 1)
}

func appendBytesField(b []byte, num protowire.Number, v []byte) []byte {
	if len(v) == 0 {
		return b
	}
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}

// Marshal encodes a Data message in field-number order.
func (d *Data) Marshal() []byte {
	var b []byte
	b = appendVarintField(b, 1, uint64(d.Portnum))
	b = appendBytesField(b, 2, d.Payload)
	b = appendBool(b, 3, d.WantResponse)
	b = appendFixed32(b, 4, d.Dest)
	b = appendFixed32(b, 5, d.Source)
	b = appendFixed32(b, 6, d.RequestID)
	b = appendFixed32(b, 7, d.ReplyID)
	b = appendFixed32(b, 8, d.Emoji)
	if d.HasBitfield {
		b = protowire.AppendTag(b, 9, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(d.Bitfield))
	}
	b = appendBytesField(b, 10, d.Signature)
	return b
}

var errTruncated = errors.New("meshwire: truncated or malformed protobuf")

// walk calls fn for each field in b. fn returns true if it consumed the value;
// otherwise the value is skipped.
func walk(b []byte, fn func(num protowire.Number, typ protowire.Type, b []byte) (int, bool)) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return errTruncated
		}
		b = b[n:]
		if used, ok := fn(num, typ, b); ok {
			if used < 0 {
				return errTruncated
			}
			b = b[used:]
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return errTruncated
		}
		b = b[n:]
	}
	return nil
}

func consumeVarint(typ protowire.Type, b []byte) (uint64, int, bool) {
	if typ != protowire.VarintType {
		return 0, 0, false
	}
	v, n := protowire.ConsumeVarint(b)
	return v, n, true
}

func consumeFixed32(typ protowire.Type, b []byte) (uint32, int, bool) {
	if typ != protowire.Fixed32Type {
		return 0, 0, false
	}
	v, n := protowire.ConsumeFixed32(b)
	return v, n, true
}

func consumeBytes(typ protowire.Type, b []byte) ([]byte, int, bool) {
	if typ != protowire.BytesType {
		return nil, 0, false
	}
	v, n := protowire.ConsumeBytes(b)
	if n < 0 {
		return nil, n, true
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, n, true
}

// UnmarshalData decodes a Data message.
func UnmarshalData(b []byte) (*Data, error) {
	d := &Data{}
	err := walk(b, func(num protowire.Number, typ protowire.Type, b []byte) (int, bool) {
		switch num {
		case 1:
			if v, n, ok := consumeVarint(typ, b); ok {
				d.Portnum = uint32(v)
				return n, true
			}
		case 2:
			if v, n, ok := consumeBytes(typ, b); ok {
				d.Payload = v
				return n, true
			}
		case 3:
			if v, n, ok := consumeVarint(typ, b); ok {
				d.WantResponse = v != 0
				return n, true
			}
		case 4:
			if v, n, ok := consumeFixed32(typ, b); ok {
				d.Dest = v
				return n, true
			}
		case 5:
			if v, n, ok := consumeFixed32(typ, b); ok {
				d.Source = v
				return n, true
			}
		case 6:
			if v, n, ok := consumeFixed32(typ, b); ok {
				d.RequestID = v
				return n, true
			}
		case 7:
			if v, n, ok := consumeFixed32(typ, b); ok {
				d.ReplyID = v
				return n, true
			}
		case 8:
			if v, n, ok := consumeFixed32(typ, b); ok {
				d.Emoji = v
				return n, true
			}
		case 9:
			if v, n, ok := consumeVarint(typ, b); ok {
				d.Bitfield = uint32(v)
				d.HasBitfield = true
				return n, true
			}
		case 10:
			if v, n, ok := consumeBytes(typ, b); ok {
				d.Signature = v
				return n, true
			}
		}
		return 0, false
	})
	if err != nil {
		return nil, err
	}
	return d, nil
}

// Marshal encodes a MeshPacket in field-number order.
func (p *MeshPacket) Marshal() []byte {
	var b []byte
	b = appendFixed32(b, 1, p.From)
	b = appendFixed32(b, 2, p.To)
	b = appendVarintField(b, 3, uint64(p.Channel))
	if p.Decoded != nil {
		b = protowire.AppendTag(b, 4, protowire.BytesType)
		b = protowire.AppendBytes(b, p.Decoded.Marshal())
	}
	b = appendBytesField(b, 5, p.Encrypted)
	b = appendFixed32(b, 6, p.ID)
	b = appendVarintField(b, 9, uint64(p.HopLimit))
	b = appendBool(b, 10, p.WantAck)
	b = appendBool(b, 14, p.ViaMQTT)
	b = appendVarintField(b, 15, uint64(p.HopStart))
	b = appendBytesField(b, 16, p.PublicKey)
	b = appendBool(b, 17, p.PKIEncrypted)
	b = appendVarintField(b, 18, uint64(p.NextHop))
	b = appendVarintField(b, 19, uint64(p.RelayNode))
	return b
}

// UnmarshalMeshPacket decodes a MeshPacket.
func UnmarshalMeshPacket(b []byte) (*MeshPacket, error) {
	p := &MeshPacket{}
	var derr error
	err := walk(b, func(num protowire.Number, typ protowire.Type, b []byte) (int, bool) {
		switch num {
		case 1:
			if v, n, ok := consumeFixed32(typ, b); ok {
				p.From = v
				return n, true
			}
		case 2:
			if v, n, ok := consumeFixed32(typ, b); ok {
				p.To = v
				return n, true
			}
		case 3:
			if v, n, ok := consumeVarint(typ, b); ok {
				p.Channel = uint32(v)
				return n, true
			}
		case 4:
			if v, n, ok := consumeBytes(typ, b); ok {
				if n >= 0 {
					p.Decoded, derr = UnmarshalData(v)
				}
				return n, true
			}
		case 5:
			if v, n, ok := consumeBytes(typ, b); ok {
				p.Encrypted = v
				return n, true
			}
		case 6:
			if v, n, ok := consumeFixed32(typ, b); ok {
				p.ID = v
				return n, true
			}
		case 9:
			if v, n, ok := consumeVarint(typ, b); ok {
				p.HopLimit = uint32(v)
				return n, true
			}
		case 10:
			if v, n, ok := consumeVarint(typ, b); ok {
				p.WantAck = v != 0
				return n, true
			}
		case 14:
			if v, n, ok := consumeVarint(typ, b); ok {
				p.ViaMQTT = v != 0
				return n, true
			}
		case 15:
			if v, n, ok := consumeVarint(typ, b); ok {
				p.HopStart = uint32(v)
				return n, true
			}
		case 16:
			if v, n, ok := consumeBytes(typ, b); ok {
				p.PublicKey = v
				return n, true
			}
		case 17:
			if v, n, ok := consumeVarint(typ, b); ok {
				p.PKIEncrypted = v != 0
				return n, true
			}
		case 18:
			if v, n, ok := consumeVarint(typ, b); ok {
				p.NextHop = uint32(v)
				return n, true
			}
		case 19:
			if v, n, ok := consumeVarint(typ, b); ok {
				p.RelayNode = uint32(v)
				return n, true
			}
		}
		return 0, false
	})
	if err != nil {
		return nil, err
	}
	if derr != nil {
		return nil, derr
	}
	return p, nil
}

// Marshal encodes a ServiceEnvelope.
func (e *ServiceEnvelope) Marshal() []byte {
	var b []byte
	if e.Packet != nil {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendBytes(b, e.Packet.Marshal())
	}
	if e.ChannelID != "" {
		b = protowire.AppendTag(b, 2, protowire.BytesType)
		b = protowire.AppendString(b, e.ChannelID)
	}
	if e.GatewayID != "" {
		b = protowire.AppendTag(b, 3, protowire.BytesType)
		b = protowire.AppendString(b, e.GatewayID)
	}
	return b
}

// UnmarshalServiceEnvelope decodes a ServiceEnvelope as published by a gateway.
func UnmarshalServiceEnvelope(b []byte) (*ServiceEnvelope, error) {
	e := &ServiceEnvelope{}
	var perr error
	err := walk(b, func(num protowire.Number, typ protowire.Type, b []byte) (int, bool) {
		switch num {
		case 1:
			if v, n, ok := consumeBytes(typ, b); ok {
				if n >= 0 {
					e.Packet, perr = UnmarshalMeshPacket(v)
				}
				return n, true
			}
		case 2:
			if v, n, ok := consumeBytes(typ, b); ok {
				e.ChannelID = string(v)
				return n, true
			}
		case 3:
			if v, n, ok := consumeBytes(typ, b); ok {
				e.GatewayID = string(v)
				return n, true
			}
		}
		return 0, false
	})
	if err != nil {
		return nil, err
	}
	if perr != nil {
		return nil, perr
	}
	if e.Packet == nil || e.ChannelID == "" || e.GatewayID == "" {
		return nil, fmt.Errorf("meshwire: incomplete service envelope")
	}
	return e, nil
}

// Marshal encodes a User.
func (u *User) Marshal() []byte {
	var b []byte
	for _, f := range []struct {
		num protowire.Number
		s   string
	}{{1, u.ID}, {2, u.LongName}, {3, u.ShortName}} {
		if f.s != "" {
			b = protowire.AppendTag(b, f.num, protowire.BytesType)
			b = protowire.AppendString(b, f.s)
		}
	}
	b = appendBytesField(b, 8, u.PublicKey)
	return b
}

// UnmarshalUser decodes a User (the NODEINFO_APP payload).
func UnmarshalUser(b []byte) (*User, error) {
	u := &User{}
	err := walk(b, func(num protowire.Number, typ protowire.Type, b []byte) (int, bool) {
		switch num {
		case 1:
			if v, n, ok := consumeBytes(typ, b); ok {
				u.ID = string(v)
				return n, true
			}
		case 2:
			if v, n, ok := consumeBytes(typ, b); ok {
				u.LongName = string(v)
				return n, true
			}
		case 3:
			if v, n, ok := consumeBytes(typ, b); ok {
				u.ShortName = string(v)
				return n, true
			}
		case 8:
			if v, n, ok := consumeBytes(typ, b); ok {
				u.PublicKey = v
				return n, true
			}
		}
		return 0, false
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}
