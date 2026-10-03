package meshcrypto

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"errors"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"

	"github.com/Poag/Intermesh/server/internal/meshwire"
)

// SignatureSize is XEDDSA_SIGNATURE_SIZE.
const SignatureSize = 64

// SignatureFieldBytes is XEDDSA_SIGNATURE_FIELD_BYTES: the signature plus the
// protobuf tag and length bytes.
const SignatureFieldBytes = SignatureSize + 2

// MaxSignedDataBytes is the largest Data encoding (including the signature
// field) a node will sign: the 255-byte LoRa payload limit minus the 16-byte
// header (Router.cpp signedDataFits).
const MaxSignedDataBytes = 255 - 16

const (
	xeddsaVersion         = 0x01
	xeddsaFlagWantResp    = 0x01
	xeddsaFlagHasBitfield = 0x02
)

// SigningBuffer builds the bytes a signature covers (CryptoEngine.cpp
// buildSigningBuffer): version, then little-endian from, id, to, portnum,
// request_id, reply_id, emoji and bitfield (0 when absent), a flags byte, then
// the payload.
func SigningBuffer(from, packetID, to uint32, d *meshwire.Data) []byte {
	buf := make([]byte, 0, 38+len(d.Payload))
	buf = append(buf, xeddsaVersion)
	for _, v := range []uint32{from, packetID, to, d.Portnum, d.RequestID, d.ReplyID, d.Emoji} {
		buf = binary.LittleEndian.AppendUint32(buf, v)
	}
	var bf uint32
	if d.HasBitfield {
		bf = d.Bitfield
	}
	buf = binary.LittleEndian.AppendUint32(buf, bf)
	var flags byte
	if d.WantResponse {
		flags |= xeddsaFlagWantResp
	}
	if d.HasBitfield {
		flags |= xeddsaFlagHasBitfield
	}
	buf = append(buf, flags)
	return append(buf, d.Payload...)
}

// CurveToEdPublic converts an X25519 public key to the Ed25519 public key with
// sign bit zero that XEdDSA verifies against: y = (u-1)/(u+1) mod p
// (CryptoEngine::curve_to_ed_pub).
func CurveToEdPublic(curvePub []byte) ([]byte, error) {
	var u, one, num, den field.Element
	if _, err := u.SetBytes(curvePub); err != nil {
		return nil, err
	}
	one.One()
	num.Subtract(&u, &one)
	den.Add(&u, &one)
	den.Invert(&den)
	num.Multiply(&num, &den)
	out := num.Bytes()
	out[31] &= 0x7f
	return out, nil
}

// VerifyXEdDSA reports whether sig is a valid signature by the node holding
// curvePub over the packet (verification is plain Ed25519 against the
// converted key).
func VerifyXEdDSA(curvePub []byte, from, packetID, to uint32, d *meshwire.Data, sig []byte) bool {
	if len(curvePub) != 32 || len(sig) != SignatureSize {
		return false
	}
	ed, err := CurveToEdPublic(curvePub)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed, SigningBuffer(from, packetID, to, d), sig)
}

// SignXEdDSA signs the packet with a Curve25519 private key. z must be 32
// random bytes (the spec's Z, mixed into the nonce); the signature verifies
// under VerifyXEdDSA and under the firmware's verifier.
func SignXEdDSA(curvePriv []byte, from, packetID, to uint32, d *meshwire.Data, z []byte) ([]byte, error) {
	if len(curvePriv) != 32 || len(z) != 32 {
		return nil, errors.New("meshcrypto: key and z must be 32 bytes")
	}
	return signMessage(curvePriv, SigningBuffer(from, packetID, to, d), z)
}

func signMessage(curvePriv, msg, z []byte) ([]byte, error) {
	a, err := edwards25519.NewScalar().SetBytesWithClamping(curvePriv)
	if err != nil {
		return nil, err
	}
	A := new(edwards25519.Point).ScalarBaseMult(a).Bytes()
	if A[31]&0x80 != 0 { // XEdDSA fixes the public key's sign bit to zero
		a.Negate(a)
		A = new(edwards25519.Point).ScalarBaseMult(a).Bytes()
	}
	prefix := sha512.Sum512(a.Bytes())
	h := sha512.New()
	h.Write(prefix[32:])
	h.Write(msg)
	h.Write(z)
	r, err := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		return nil, err
	}
	R := new(edwards25519.Point).ScalarBaseMult(r).Bytes()

	h = sha512.New()
	h.Write(R)
	h.Write(A)
	h.Write(msg)
	k, err := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		return nil, err
	}
	s := edwards25519.NewScalar().MultiplyAdd(k, a, r) // k*a + r
	return append(R, s.Bytes()...), nil
}

// signRaw and verifyRaw sign and verify arbitrary bytes; they exist so tests can
// compare against the firmware library without going through a Data envelope.
func signRaw(curvePriv, msg, z []byte) ([]byte, error) { return signMessage(curvePriv, msg, z) }

func verifyRaw(edPub, msg, sig []byte) bool { return ed25519.Verify(edPub, msg, sig) }
