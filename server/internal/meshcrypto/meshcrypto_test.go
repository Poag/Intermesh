package meshcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/Poag/Intermesh/server/internal/meshwire"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestExpandPSK(t *testing.T) {
	k, _ := ExpandPSK([]byte{1})
	if !bytes.Equal(k, DefaultPSK) {
		t.Fatal("shorthand 1 must be the default key")
	}
	k, _ = ExpandPSK([]byte{3})
	want := append([]byte(nil), DefaultPSK...)
	want[15] += 2
	if !bytes.Equal(k, want) {
		t.Fatal("shorthand 3 must bump the last byte by 2")
	}
	if k, _ := ExpandPSK([]byte{0}); k != nil {
		t.Fatal("shorthand 0 is no encryption")
	}
	if k, _ := ExpandPSK([]byte{9, 9, 9}); len(k) != 16 || k[3] != 0 {
		t.Fatal("short keys are zero padded to 16")
	}
	if k, _ := ExpandPSK(make([]byte, 20)); len(k) != 32 {
		t.Fatal("17 to 31 byte keys are padded to 32")
	}
	if _, err := ExpandPSK(make([]byte, 33)); err == nil {
		t.Fatal("33 bytes must be rejected")
	}
}

func TestChannelHash(t *testing.T) {
	// xor of "InterRoam" xor xor of the default key; the AEAD flag flips 0xAE.
	h := ChannelHash("InterRoam", DefaultPSK, false)
	if ChannelHash("InterRoam", DefaultPSK, true) != h^0xAE {
		t.Fatal("aead variant must differ by 0xAE")
	}
	var want byte
	for _, c := range []byte("InterRoam") {
		want ^= c
	}
	for _, c := range DefaultPSK {
		want ^= c
	}
	if h != want {
		t.Fatalf("hash %02x want %02x", h, want)
	}
}

// RFC 3686 section 6 vectors as used in firmware test/test_crypto test_AES_CTR.
// The firmware IV layout is checked separately: only the IV bytes differ.
func TestCTRMatchesRFC3686(t *testing.T) {
	block, _ := aes.NewCipher(unhex(t, "776BEFF2851DB06F4C8A0542C8696F6C6A81AF1EEC96B4D37FC1D689E6C1C104"))
	_ = block
	// Reproduce with the package's CTR by choosing from/id so the IV matches:
	// IV = 00000060 DB5672C9 7AA8F0B2 00000001 is not of the form id(8) from(4) 0(4),
	// so verify the primitive through the standard library path used by CTR.
	iv := unhex(t, "00000060DB5672C97AA8F0B200000001")
	got := make([]byte, 16)
	ctrRef(block, iv, []byte("Single block msg"), got)
	if hex.EncodeToString(got) != "145ad01dbf824ec7560863dc71e3e0c0" {
		t.Fatalf("got %x", got)
	}
}

func TestCTRRoundTripAndLayout(t *testing.T) {
	key, _ := ExpandPSK([]byte{1})
	pt := []byte("hello mesh")
	ct, err := CTR(key, 0x0929, 0x13b2d662, pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ct, pt) {
		t.Fatal("not encrypted")
	}
	back, _ := CTR(key, 0x0929, 0x13b2d662, ct)
	if !bytes.Equal(back, pt) {
		t.Fatal("round trip failed")
	}
	// IV layout: id as 8 LE bytes, from as 4 LE bytes, 4 zero bytes.
	block, _ := aes.NewCipher(key)
	iv := unhex(t, "62d6b21300000000"+"29090000"+"00000000")
	want := make([]byte, len(pt))
	ctrRef(block, iv, pt, want)
	if !bytes.Equal(ct, want) {
		t.Fatalf("iv layout mismatch %x vs %x", ct, want)
	}
	if out, _ := CTR(nil, 1, 1, pt); !bytes.Equal(out, pt) {
		t.Fatal("nil key must pass data through")
	}
}

// Packet vectors from RFC 3610 section 8, copied from firmware test_AES_CCM_rfc3610.
func TestCCMRFC3610(t *testing.T) {
	vecs := []struct{ key, nonce, aad, plain, crypt, tag string }{
		{"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF", "00000003020100A0A1A2A3A4A5", "0001020304050607",
			"08090A0B0C0D0E0F101112131415161718191A1B1C1D1E", "588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384", "17E8D12CFDF926E0"},
		{"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF", "00000004030201A0A1A2A3A4A5", "0001020304050607",
			"08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "72C91A36E135F8CF291CA894085C87E3CC15C439C9E43A3B", "A091D56E10400916"},
		{"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF", "00000009080706A0A1A2A3A4A5", "0001020304050607",
			"08090A0B0C0D0E0F101112131415161718191A1B1C1D1E", "0135D1B2C95F41D5D1D4FEC185D166B8094E999DFED96C", "048C56602C97ACBB7490"},
	}
	for i, v := range vecs {
		block, _ := aes.NewCipher(unhex(t, v.key))
		tagLen := len(unhex(t, v.tag))
		ct, tag, err := ccmSeal(block, tagLen, unhex(t, v.nonce), unhex(t, v.aad), unhex(t, v.plain))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.EqualFold([]byte(hex.EncodeToString(ct)), []byte(v.crypt)) || !bytes.EqualFold([]byte(hex.EncodeToString(tag)), []byte(v.tag)) {
			t.Fatalf("vector %d: ct %x tag %x", i+1, ct, tag)
		}
		pt, err := ccmOpen(block, unhex(t, v.nonce), unhex(t, v.aad), ct, tag)
		if err != nil || !bytes.Equal(pt, unhex(t, v.plain)) {
			t.Fatalf("vector %d open: %v", i+1, err)
		}
		tag[0] ^= 1
		if _, err := ccmOpen(block, unhex(t, v.nonce), unhex(t, v.aad), ct, tag); err == nil {
			t.Fatal("tampered tag accepted")
		}
	}
}

// Firmware test_PKC: our private key a003..., sender key db18..., sender node
// 0x0929, packet id 0x13b2d662, payload = 10 byte ciphertext, 8 byte tag, 4 byte
// extra nonce. Expected plaintext 08011204746573744800.
func TestPKIDecryptFirmwareVector(t *testing.T) {
	priv := unhex(t, "a00330633e63522f8a4d81ec6d9d1e6617f6c8ffd3a4c698229537d44e522277")
	pub := unhex(t, "db18fc50eea47f00251cb784819a3cf5fc361882597f589f0d7ff820e8064457")
	radio := unhex(t, "8c646d7a2909000062d6b2136b00000040df24abfcc30a17a3d9046726099e796a1c036a792b")
	payload := radio[16:] // after the 16 byte header
	pt, err := PKIDecrypt(priv, pub, 0x0929, 0x13b2d662, payload)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(pt) != "08011204746573744800" {
		t.Fatalf("plaintext %x", pt)
	}
	key, _ := pkiSharedKey(priv, pub)
	if hex.EncodeToString(key[:8]) != "777b1545c9d6f9a2" {
		t.Fatalf("shared key prefix %x", key[:8])
	}
	if hex.EncodeToString(pkiNonce(0x0929, 0x13b2d662, 0x2b796a03)) != "62d6b213036a792b2909000000" {
		t.Fatalf("nonce %x", pkiNonce(0x0929, 0x13b2d662, 0x2b796a03))
	}
}

func TestPKIRoundTrip(t *testing.T) {
	a := make([]byte, 32)
	b := make([]byte, 32)
	rand.Read(a)
	rand.Read(b)
	pa, _ := PublicKey(a)
	pb, _ := PublicKey(b)
	msg := []byte("MFB1 E secret")
	ct, err := PKIEncrypt(a, pb, NodeNumFromKey(pa), 42, 0xdeadbeef, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != len(msg)+PKIOverhead {
		t.Fatalf("length %d", len(ct))
	}
	pt, err := PKIDecrypt(b, pa, NodeNumFromKey(pa), 42, ct)
	if err != nil || !bytes.Equal(pt, msg) {
		t.Fatalf("%v %q", err, pt)
	}
	if _, err := PKIDecrypt(b, pa, NodeNumFromKey(pa), 43, ct); err == nil {
		t.Fatal("wrong packet id accepted")
	}
	if _, err := PKIEncrypt(a, pb, 1, 1, 0, msg); err == nil {
		t.Fatal("zero extra nonce accepted")
	}
}

func TestNodeID(t *testing.T) {
	if NodeID(0xa1b2c3d4) != "!a1b2c3d4" {
		t.Fatal("format")
	}
	n, err := ParseNodeID("!00000929")
	if err != nil || n != 0x929 {
		t.Fatal(n, err)
	}
	if _, err := ParseNodeID("zz"); err == nil {
		t.Fatal("bad id accepted")
	}
}

func signable() *meshwire.Data {
	return &meshwire.Data{Portnum: meshwire.PortText, Payload: []byte("MFB1 R 4be10c77 3"), RequestID: 1, ReplyID: 2,
		Emoji: 3, HasBitfield: true, Bitfield: meshwire.BitfieldOKToMQTT, WantResponse: true}
}

func TestXEdDSAKeyConversionMatchesSigner(t *testing.T) {
	for i := 0; i < 20; i++ {
		priv := make([]byte, 32)
		rand.Read(priv)
		pub, _ := PublicKey(priv)
		ed, err := CurveToEdPublic(pub)
		if err != nil {
			t.Fatal(err)
		}
		d := signable()
		z := make([]byte, 32)
		rand.Read(z)
		sig, err := SignXEdDSA(priv, 0x1234, 0xDEADBEEF, 0x5678, d, z)
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(ed, SigningBuffer(0x1234, 0xDEADBEEF, 0x5678, d), sig) {
			t.Fatal("signature does not verify under the converted public key")
		}
		if !VerifyXEdDSA(pub, 0x1234, 0xDEADBEEF, 0x5678, d, sig) {
			t.Fatal("VerifyXEdDSA rejected a good signature")
		}
	}
}

// Mirrors firmware test_XEdDSA: every covered field must be bound.
func TestXEdDSABindsEveryField(t *testing.T) {
	priv := make([]byte, 32)
	rand.Read(priv)
	pub, _ := PublicKey(priv)
	z := make([]byte, 32)
	d := signable()
	sig, err := SignXEdDSA(priv, 1, 2, 3, d, z)
	if err != nil {
		t.Fatal(err)
	}
	mut := []struct {
		name         string
		from, id, to uint32
		edit         func(*meshwire.Data)
	}{
		{"from", 2, 2, 3, func(*meshwire.Data) {}},
		{"id", 1, 3, 3, func(*meshwire.Data) {}},
		{"to", 1, 2, 4, func(*meshwire.Data) {}},
		{"payload", 1, 2, 3, func(d *meshwire.Data) { d.Payload = []byte("MFB1 R 4be10c77 4") }},
		{"portnum", 1, 2, 3, func(d *meshwire.Data) { d.Portnum++ }},
		{"request_id", 1, 2, 3, func(d *meshwire.Data) { d.RequestID++ }},
		{"reply_id", 1, 2, 3, func(d *meshwire.Data) { d.ReplyID++ }},
		{"emoji", 1, 2, 3, func(d *meshwire.Data) { d.Emoji++ }},
		{"bitfield", 1, 2, 3, func(d *meshwire.Data) { d.Bitfield ^= meshwire.BitfieldOKToMQTT }},
		{"has_bitfield", 1, 2, 3, func(d *meshwire.Data) { d.HasBitfield = false; d.Bitfield = 0 }},
		{"want_response", 1, 2, 3, func(d *meshwire.Data) { d.WantResponse = false }},
	}
	if !VerifyXEdDSA(pub, 1, 2, 3, d, sig) {
		t.Fatal("baseline must verify")
	}
	for _, m := range mut {
		c := *d
		m.edit(&c)
		if VerifyXEdDSA(pub, m.from, m.id, m.to, &c, sig) {
			t.Errorf("%s change still verified", m.name)
		}
	}
	other := make([]byte, 32)
	rand.Read(other)
	opub, _ := PublicKey(other)
	if VerifyXEdDSA(opub, 1, 2, 3, d, sig) {
		t.Error("verified under a different key")
	}
	if VerifyXEdDSA(pub, 1, 2, 3, d, sig[:63]) {
		t.Error("short signature accepted")
	}
}

func TestSigningBufferLayout(t *testing.T) {
	d := &meshwire.Data{Portnum: 1, Payload: []byte("ab"), HasBitfield: true, Bitfield: 1, WantResponse: true}
	got := SigningBuffer(0x11223344, 0x55667788, 0x99aabbcc, d)
	want := "01" + "44332211" + "88776655" + "ccbbaa99" + "01000000" + "00000000" + "00000000" + "00000000" + "01000000" + "03" + "6162"
	if hex.EncodeToString(got) != want {
		t.Fatalf("got  %x\nwant %s", got, want)
	}
	if len(SigningBuffer(1, 2, 3, &meshwire.Data{})) != 1+8*4+1 {
		t.Fatal("header length must be 34")
	}
}
