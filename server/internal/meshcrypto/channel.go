// Package meshcrypto implements the Meshtastic cryptography the community
// server needs, as read from the firmware (develop 3fdc613d, v2.8.1 8e6a88d0):
// channel AES-CTR, PKI direct messages (X25519, SHA-256, AES-CCM), XEdDSA
// signatures and node-number derivation. See the vault note "InterMesh
// Firmware Findings" for where each rule comes from.
package meshcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

// DefaultPSK is defaultpsk in src/mesh/Channels.h.
var DefaultPSK = []byte{0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01}

// ExpandPSK turns a channel's stored psk into the key used for encryption,
// following Channels::getKey. A nil result means encryption is off.
func ExpandPSK(psk []byte) ([]byte, error) {
	switch {
	case len(psk) == 0:
		return nil, nil
	case len(psk) == 1:
		n := psk[0]
		if n == 0 {
			return nil, nil
		}
		k := append([]byte(nil), DefaultPSK...)
		k[len(k)-1] = k[len(k)-1] + n - 1
		return k, nil
	case len(psk) < 16:
		k := make([]byte, 16)
		copy(k, psk)
		return k, nil
	case len(psk) == 16 || len(psk) == 32:
		return append([]byte(nil), psk...), nil
	case len(psk) < 32:
		k := make([]byte, 32)
		copy(k, psk)
		return k, nil
	}
	return nil, errors.New("meshcrypto: psk longer than 32 bytes")
}

func xorHash(b []byte) byte {
	var h byte
	for _, c := range b {
		h ^= c
	}
	return h
}

// ChannelHash is Channels::generateHash: the byte carried in the packet header
// for encrypted packets. aead is the channel's use_aead setting.
func ChannelHash(name string, key []byte, aead bool) byte {
	h := xorHash([]byte(name)) ^ xorHash(key)
	if aead {
		h ^= 0xAE
	}
	return h
}

// CTR applies the channel cipher (it is its own inverse). The IV is the packet
// ID as 8 little-endian bytes, the sender node number as 4 little-endian bytes
// and four zero bytes (CryptoEngine::initNonce); the counter is the last four
// bytes. A nil key leaves data unchanged, as the firmware does.
func CTR(key []byte, from, packetID uint32, data []byte) ([]byte, error) {
	out := append([]byte(nil), data...)
	if len(key) == 0 {
		return out, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var iv [16]byte
	binary.LittleEndian.PutUint64(iv[0:8], uint64(packetID))
	binary.LittleEndian.PutUint32(iv[8:12], from)
	cipher.NewCTR(block, iv[:]).XORKeyStream(out, out)
	return out, nil
}
