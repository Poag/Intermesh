package meshcrypto

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/curve25519"
)

// PKIOverhead is MESHTASTIC_PKC_OVERHEAD: 8-byte tag plus 4-byte extra nonce.
const PKIOverhead = 12

// pkiSharedKey is SHA-256 of the X25519 shared secret (setCryptoSharedSecret).
func pkiSharedKey(priv, remotePub []byte) ([]byte, error) {
	if len(priv) != 32 || len(remotePub) != 32 {
		return nil, errors.New("meshcrypto: keys must be 32 bytes")
	}
	shared, err := curve25519.X25519(priv, remotePub) // rejects an all-zero result
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(shared)
	return h[:], nil
}

// pkiNonce is CryptoEngine::initNonce followed by the 13-byte read the CCM
// code does: packet ID, extra nonce (replacing the packet ID's upper half when
// nonzero), sender node number, one zero byte, all little-endian.
func pkiNonce(from, packetID, extra uint32) []byte {
	n := make([]byte, 16)
	binary.LittleEndian.PutUint64(n[0:8], uint64(packetID))
	binary.LittleEndian.PutUint32(n[8:12], from)
	if extra != 0 {
		binary.LittleEndian.PutUint32(n[4:8], extra)
	}
	return n[:ccmNonceBytes]
}

// PKIDecrypt opens a PKI direct message payload (ciphertext, 8-byte tag,
// 4-byte extra nonce). priv is our Curve25519 private key and remotePub the
// sender's public key.
func PKIDecrypt(priv, remotePub []byte, from, packetID uint32, payload []byte) ([]byte, error) {
	if len(payload) <= PKIOverhead {
		return nil, errors.New("meshcrypto: pki payload too short")
	}
	key, err := pkiSharedKey(priv, remotePub)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	n := len(payload) - PKIOverhead
	extra := binary.LittleEndian.Uint32(payload[n+8:])
	return ccmOpen(block, pkiNonce(from, packetID, extra), nil, payload[:n], payload[n:n+8])
}

// PKIEncrypt seals plaintext for remotePub. extra is the 32-bit extra nonce,
// which the firmware draws from a hardware RNG; callers must supply a random
// nonzero value.
func PKIEncrypt(priv, remotePub []byte, from, packetID, extra uint32, plain []byte) ([]byte, error) {
	if extra == 0 {
		return nil, errors.New("meshcrypto: extra nonce must be nonzero")
	}
	key, err := pkiSharedKey(priv, remotePub)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ct, tag, err := ccmSeal(block, 8, pkiNonce(from, packetID, extra), nil, plain)
	if err != nil {
		return nil, err
	}
	out := append(ct, tag...)
	var e [4]byte
	binary.LittleEndian.PutUint32(e[:], extra)
	return append(out, e[:]...), nil
}

// PublicKey returns the X25519 public key for a private key.
func PublicKey(priv []byte) ([]byte, error) {
	return curve25519.X25519(priv, curve25519.Basepoint)
}
