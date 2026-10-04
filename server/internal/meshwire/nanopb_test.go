package meshwire

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// Cross-checks this codec against the firmware's own protobuf code (nanopb 0.4.9.2 with the
// generated meshtastic types, built with PB_ENABLE_MALLOC and PB_VALIDATE_UTF8 as the firmware
// builds it). Build the harness as testdata/README.md describes; the test is skipped unless
// INTERMESH_NANOPB_HARNESS names it.
func harness(t *testing.T, args ...string) map[string]string {
	t.Helper()
	bin := os.Getenv("INTERMESH_NANOPB_HARNESS")
	if bin == "" {
		t.Skip("INTERMESH_NANOPB_HARNESS not set")
	}
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		t.Fatalf("harness %v: %v", args[0], err)
	}
	m := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[k] = v
		}
	}
	return m
}

func rnd(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

func TestDataEncodingMatchesNanopb(t *testing.T) {
	sig := rnd(64)
	cases := []struct {
		name     string
		d        Data
		bitfield int
		sig      bool
	}{
		{"short text", Data{Portnum: PortText, Payload: []byte("hello")}, -1, false},
		{"with bitfield 1", Data{Portnum: PortText, Payload: []byte("hello"), HasBitfield: true, Bitfield: 1}, 1, false},
		{"bitfield zero", Data{Portnum: PortText, Payload: []byte("x"), HasBitfield: true, Bitfield: 0}, 0, false},
		{"signed", Data{Portnum: PortText, Payload: []byte("MFB1 R 4be10c77 3"), HasBitfield: true, Bitfield: 1, Signature: sig}, 1, true},
		{"nodeinfo port", Data{Portnum: PortNodeInfo, Payload: rnd(60), HasBitfield: true}, 0, false},
		{"private port", Data{Portnum: PortPrivate, Payload: rnd(120), HasBitfield: true}, 0, false},
		{"empty payload", Data{Portnum: PortText}, -1, false},
	}
	for _, size := range []int{1, 100, 127, 128, 166, 167, 200, 233} {
		cases = append(cases, struct {
			name     string
			d        Data
			bitfield int
			sig      bool
		}{fmt.Sprintf("payload %d", size), Data{Portnum: PortText, Payload: rnd(size), HasBitfield: true, Bitfield: 1}, 1, false})
	}
	for _, c := range cases {
		sigHex := "-"
		if c.sig {
			sigHex = hex.EncodeToString(c.d.Signature)
		}
		h := harness(t, "dataenc", strconv.Itoa(int(c.d.Portnum)), orDash(hex.EncodeToString(c.d.Payload)), strconv.Itoa(c.bitfield), sigHex)
		got := hex.EncodeToString(c.d.Marshal())
		if got != h["bytes"] {
			t.Errorf("%s: Go %s\n   nanopb %s", c.name, got, h["bytes"])
		}
		// the firmware's decoder accepts what Go encoded, and reads the same fields
		d := harness(t, "datadec", got)
		if d["ok"] != "1" || d["portnum"] != strconv.Itoa(int(c.d.Portnum)) || d["payload_size"] != strconv.Itoa(len(c.d.Payload)) {
			t.Errorf("%s: nanopb decode %v", c.name, d)
		}
		back, err := UnmarshalData(mustHex(t, h["bytes"]))
		if err != nil || !bytes.Equal(back.Payload, c.d.Payload) || back.Portnum != c.d.Portnum || back.HasBitfield != c.d.HasBitfield {
			t.Errorf("%s: Go decode of nanopb bytes: %v %+v", c.name, err, back)
		}
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The signed-size rule in the spec: Data including a 64-byte signature must fit 239 bytes. The
// largest payload for which that holds, with a bitfield present, is the line budget the codec uses.
func TestSignedSizeRuleAndLineBudgetMatchNanopb(t *testing.T) {
	sig := hex.EncodeToString(rnd(64))
	maxFit := 0
	for n := 1; n <= 233; n++ {
		h := harness(t, "dataenc", "1", hex.EncodeToString(bytes.Repeat([]byte{'a'}, n)), "1", sig)
		size, _ := strconv.Atoi(h["size"])
		if size <= 239 {
			maxFit = n
		}
	}
	if maxFit != 166 {
		t.Fatalf("the largest text that still fits when signed is %d bytes, the codec assumes 166", maxFit)
	}
	// and the signature field costs exactly 66 bytes
	a := harness(t, "dataenc", "1", "6161", "1", "-")
	b := harness(t, "dataenc", "1", "6161", "1", sig)
	sa, _ := strconv.Atoi(a["size"])
	sb, _ := strconv.Atoi(b["size"])
	if sb-sa != 66 {
		t.Fatalf("signature field costs %d bytes", sb-sa)
	}
}

func TestEnvelopeMatchesNanopb(t *testing.T) {
	type c struct {
		name string
		env  ServiceEnvelope
	}
	cases := []c{
		{"channel broadcast", ServiceEnvelope{Packet: &MeshPacket{From: 0x0929, To: BroadcastNum, Channel: 8, ID: 0x13b2d662, HopLimit: 3, HopStart: 3, Encrypted: rnd(40)}, ChannelID: "InterRoam", GatewayID: "!a1b2c3d4"}},
		{"pki dm", ServiceEnvelope{Packet: &MeshPacket{From: 0xdeadbeef, To: 0x12345678, ID: 1, HopLimit: 7, HopStart: 7, PKIEncrypted: true, Encrypted: rnd(36)}, ChannelID: "PKI", GatewayID: "!00000001"}},
		{"largest payload", ServiceEnvelope{Packet: &MeshPacket{From: 1, To: 2, Channel: 255, ID: 0xffffffff, HopLimit: 3, HopStart: 3, Encrypted: rnd(233)}, ChannelID: "Home", GatewayID: "!aabbcc01"}},
		{"downlink as the server sends it", ServiceEnvelope{Packet: &MeshPacket{From: 0xc0ffee01, To: BroadcastNum, Channel: 0x4f, ID: 77, HopLimit: 3, HopStart: 3, Encrypted: rnd(166)}, ChannelID: "InterRoam", GatewayID: "!13be5f3c"}},
	}
	for _, x := range cases {
		x := x
		p := x.env.Packet
		enc := hex.EncodeToString(p.Encrypted)
		pki := "0"
		if p.PKIEncrypted {
			pki = "1"
		}
		h := harness(t, "envenc", u(p.From), u(p.To), u(p.Channel), u(p.ID), u(p.HopLimit), u(p.HopStart), pki, enc, x.env.ChannelID, x.env.GatewayID)
		got := hex.EncodeToString(x.env.Marshal())
		if got != h["bytes"] {
			t.Errorf("%s: encodings differ\n  Go     %s\n  nanopb %s", x.name, got, h["bytes"])
		}
		d := harness(t, "envdec", got)
		want := map[string]string{"ok": "1", "channel_id": x.env.ChannelID, "gateway_id": x.env.GatewayID, "from": u(p.From), "to": u(p.To),
			"channel": u(p.Channel), "id": u(p.ID), "hop_limit": u(p.HopLimit), "hop_start": u(p.HopStart), "variant": "encrypted",
			"enc_size": strconv.Itoa(len(p.Encrypted)), "pki_encrypted": pki, "via_mqtt": "0"}
		for k, v := range want {
			if d[k] != v {
				t.Errorf("%s: nanopb read %s=%q, want %q", x.name, k, d[k], v)
			}
		}
		if d["enc"] != enc {
			t.Errorf("%s: encrypted bytes differ", x.name)
		}
		back, err := UnmarshalServiceEnvelope(mustHex(t, h["bytes"]))
		if err != nil || back.Packet.From != p.From || back.ChannelID != x.env.ChannelID || !bytes.Equal(back.Packet.Encrypted, p.Encrypted) {
			t.Errorf("%s: Go decode of nanopb bytes failed: %v", x.name, err)
		}
	}
}

func u(v uint32) string { return strconv.FormatUint(uint64(v), 10) }

func TestUserAndSharedContactMatchNanopb(t *testing.T) {
	key := rnd(32)
	user := User{ID: "!13be5f3c", LongName: "Kent Mesh", ShortName: "7512", PublicKey: key}
	// nanopb always writes the deprecated six-byte macaddr field (six zero bytes) that this codec
	// leaves out, so the bytes differ; what matters is that each side reads the other's output.
	h := harness(t, "userenc", user.ID, user.LongName, user.ShortName, hex.EncodeToString(key))
	back, err := UnmarshalUser(mustHex(t, h["bytes"]))
	if err != nil || back.ID != user.ID || back.LongName != user.LongName || back.ShortName != user.ShortName || !bytes.Equal(back.PublicKey, key) {
		t.Fatalf("Go reads nanopb's user as %+v (%v)", back, err)
	}
	d := harness(t, "userdec", hex.EncodeToString(user.Marshal()))
	if d["ok"] != "1" || d["id"] != user.ID || d["long_name"] != user.LongName || d["short_name"] != user.ShortName || d["public_key"] != hex.EncodeToString(key) {
		t.Fatalf("nanopb reads the user as %v", d)
	}
	sc := SharedContact{NodeNum: 331243324, User: &user}
	hc := harness(t, "contactenc", u(sc.NodeNum), user.ID, user.LongName, user.ShortName, hex.EncodeToString(key))
	bc, err := UnmarshalSharedContact(mustHex(t, hc["bytes"]))
	if err != nil || bc.NodeNum != sc.NodeNum || bc.User == nil || bc.User.ID != user.ID || !bytes.Equal(bc.User.PublicKey, key) {
		t.Fatalf("Go reads nanopb's shared contact as %+v (%v)", bc, err)
	}
	dc := harness(t, "contactdec", hex.EncodeToString(sc.Marshal()))
	if dc["ok"] != "1" || dc["node_num"] != u(sc.NodeNum) || dc["has_user"] != "1" || dc["id"] != user.ID || dc["public_key"] != hex.EncodeToString(key) {
		t.Fatalf("nanopb reads the contact as %v", dc)
	}
	// a long name of 39 bytes is the most the firmware's 40 byte field holds
	long := strings.Repeat("n", 39)
	lu := User{ID: "!00000001", LongName: long, ShortName: "abcd", PublicKey: key}
	dl := harness(t, "userdec", hex.EncodeToString(lu.Marshal()))
	if dl["ok"] != "1" || dl["long_name"] != long {
		t.Fatalf("39 byte long name: %v", dl)
	}
	over := User{ID: "!00000001", LongName: strings.Repeat("n", 40), ShortName: "abcd", PublicKey: key}
	if r := harness(t, "userdec", hex.EncodeToString(over.Marshal())); r["ok"] != "0" {
		t.Logf("a 40 byte long name decodes as %v (the firmware truncates or refuses it)", r)
	}
}
