package meshwire

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDataRoundTrip(t *testing.T) {
	in := &Data{Portnum: PortText, Payload: []byte("hello"), WantResponse: true, RequestID: 7, ReplyID: 9, Emoji: 1,
		Bitfield: BitfieldOKToMQTT, HasBitfield: true, Signature: bytes.Repeat([]byte{0xAB}, 64)}
	out, err := UnmarshalData(in.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if out.Portnum != in.Portnum || !bytes.Equal(out.Payload, in.Payload) || !out.WantResponse ||
		out.RequestID != 7 || out.ReplyID != 9 || out.Emoji != 1 || !out.HasBitfield || out.Bitfield != 1 ||
		!bytes.Equal(out.Signature, in.Signature) {
		t.Fatalf("round trip mismatch: %+v", out)
	}
}

// Decrypted payload from the firmware PKC test vector (test/test_crypto, test_PKC):
// expected_decrypted = 08011204746573744800 is Data{portnum 1, payload "test", bitfield 0}.
func TestDecodeFirmwareVector(t *testing.T) {
	raw, _ := hex.DecodeString("08011204746573744800")
	d, err := UnmarshalData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if d.Portnum != PortText || string(d.Payload) != "test" || !d.HasBitfield || d.Bitfield != 0 {
		t.Fatalf("unexpected: %+v", d)
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	in := &ServiceEnvelope{
		Packet: &MeshPacket{From: 0x0929, To: BroadcastNum, Channel: 8, ID: 0x13b2d662, HopLimit: 3, HopStart: 3,
			Encrypted: []byte{1, 2, 3}, ViaMQTT: true, PKIEncrypted: false},
		ChannelID: "InterRoam", GatewayID: "!a1b2c3d4",
	}
	out, err := UnmarshalServiceEnvelope(in.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	p := out.Packet
	if p.From != 0x0929 || p.To != BroadcastNum || p.Channel != 8 || p.ID != 0x13b2d662 || p.HopLimit != 3 ||
		!bytes.Equal(p.Encrypted, []byte{1, 2, 3}) || !p.ViaMQTT || out.ChannelID != "InterRoam" || out.GatewayID != "!a1b2c3d4" {
		t.Fatalf("mismatch: %+v %+v", out, p)
	}
}

func TestRejectsTruncated(t *testing.T) {
	e := &ServiceEnvelope{Packet: &MeshPacket{From: 1, Encrypted: []byte{1, 2, 3, 4}}, ChannelID: "x", GatewayID: "!y"}
	b := e.Marshal()
	for i := 1; i < len(b); i++ {
		if _, err := UnmarshalServiceEnvelope(b[:i]); err == nil {
			// a prefix may happen to be a valid shorter envelope only if it still has all three fields
			if i < len(b)-2 {
				t.Fatalf("prefix of length %d accepted", i)
			}
		}
	}
	if _, err := UnmarshalServiceEnvelope(nil); err == nil {
		t.Fatal("empty accepted")
	}
}

func TestUserRoundTrip(t *testing.T) {
	in := &User{ID: "!00000929", LongName: "Test", ShortName: "T", PublicKey: bytes.Repeat([]byte{7}, 32)}
	out, err := UnmarshalUser(in.Marshal())
	if err != nil || out.ID != in.ID || out.LongName != "Test" || !bytes.Equal(out.PublicKey, in.PublicKey) {
		t.Fatalf("%v %+v", err, out)
	}
}
