package ap

import (
	"crypto/ed25519"
	"errors"
	"math/big"
)

const b58alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(b []byte) string {
	n := new(big.Int).SetBytes(b)
	var out []byte
	mod := new(big.Int)
	base := big.NewInt(58)
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		out = append(out, b58alphabet[mod.Int64()])
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		out = append(out, b58alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func base58Decode(s string) ([]byte, error) {
	n := new(big.Int)
	base := big.NewInt(58)
	for _, c := range []byte(s) {
		i := -1
		for k := 0; k < len(b58alphabet); k++ {
			if b58alphabet[k] == c {
				i = k
				break
			}
		}
		if i < 0 {
			return nil, errors.New("multibase: bad base58 character")
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(i)))
	}
	out := n.Bytes()
	zeros := 0
	for _, c := range []byte(s) {
		if c != b58alphabet[0] {
			break
		}
		zeros++
	}
	return append(make([]byte, zeros), out...), nil
}

// ed25519 public key multicodec prefix (varint 0xed01).
var ed25519Prefix = []byte{0xed, 0x01}

// EncodeEd25519Multikey returns the multibase (base58btc, "z" prefix) form of an Ed25519
// public key with its multicodec prefix, as used for publicKeyMultibase.
func EncodeEd25519Multikey(pub ed25519.PublicKey) string {
	return "z" + base58Encode(append(append([]byte(nil), ed25519Prefix...), pub...))
}

// DecodeEd25519Multikey is the inverse of EncodeEd25519Multikey.
func DecodeEd25519Multikey(s string) (ed25519.PublicKey, error) {
	if len(s) < 2 || s[0] != 'z' {
		return nil, errors.New("multibase: expected base58btc with z prefix")
	}
	b, err := base58Decode(s[1:])
	if err != nil {
		return nil, err
	}
	if len(b) != 2+ed25519.PublicKeySize || b[0] != ed25519Prefix[0] || b[1] != ed25519Prefix[1] {
		return nil, errors.New("multibase: not an ed25519 public key")
	}
	return ed25519.PublicKey(b[2:]), nil
}
