package meshcrypto

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

// CCM per RFC 3610 with L=2, matching src/mesh/aes-ccm.cpp (the nonce is 13
// bytes). Only the parts the firmware uses are implemented.
const (
	ccmL          = 2
	ccmNonceBytes = 15 - ccmL
)

func ccmMAC(b cipher.Block, tagLen int, nonce, aad, msg []byte) []byte {
	var blk, x [16]byte
	flags := byte((tagLen-2)/2)<<3 | (ccmL - 1)
	if len(aad) > 0 {
		flags |= 0x40
	}
	blk[0] = flags
	copy(blk[1:], nonce)
	blk[14] = byte(len(msg) >> 8)
	blk[15] = byte(len(msg))
	b.Encrypt(x[:], blk[:])

	if len(aad) > 0 {
		buf := append([]byte{byte(len(aad) >> 8), byte(len(aad))}, aad...)
		for i := 0; i < len(buf); i += 16 {
			var chunk [16]byte
			copy(chunk[:], buf[i:])
			for j := range x {
				x[j] ^= chunk[j]
			}
			b.Encrypt(x[:], x[:])
		}
	}
	for i := 0; i < len(msg); i += 16 {
		var chunk [16]byte
		copy(chunk[:], msg[i:])
		for j := range x {
			x[j] ^= chunk[j]
		}
		b.Encrypt(x[:], x[:])
	}
	return x[:tagLen]
}

func ccmCounterBlock(nonce []byte, i uint16) [16]byte {
	var a [16]byte
	a[0] = ccmL - 1
	copy(a[1:], nonce)
	a[14] = byte(i >> 8)
	a[15] = byte(i)
	return a
}

// ccmSeal returns the ciphertext and the tagLen-byte tag, separately.
func ccmSeal(b cipher.Block, tagLen int, nonce, aad, plain []byte) (ct, tag []byte, err error) {
	if len(nonce) != ccmNonceBytes {
		return nil, nil, errors.New("ccm: nonce must be 13 bytes")
	}
	t := ccmMAC(b, tagLen, nonce, aad, plain)
	ct = make([]byte, len(plain))
	for i := 0; i < len(plain); i += 16 {
		a := ccmCounterBlock(nonce, uint16(i/16+1))
		var s [16]byte
		b.Encrypt(s[:], a[:])
		for j := 0; j < 16 && i+j < len(plain); j++ {
			ct[i+j] = plain[i+j] ^ s[j]
		}
	}
	a0 := ccmCounterBlock(nonce, 0)
	var s0 [16]byte
	b.Encrypt(s0[:], a0[:])
	tag = make([]byte, tagLen)
	for j := range tag {
		tag[j] = t[j] ^ s0[j]
	}
	return ct, tag, nil
}

var errCCMAuth = errors.New("ccm: authentication failed")

// ccmOpen verifies the tag and returns the plaintext.
func ccmOpen(b cipher.Block, nonce, aad, ct, tag []byte) ([]byte, error) {
	if len(nonce) != ccmNonceBytes {
		return nil, errors.New("ccm: nonce must be 13 bytes")
	}
	plain := make([]byte, len(ct))
	for i := 0; i < len(ct); i += 16 {
		a := ccmCounterBlock(nonce, uint16(i/16+1))
		var s [16]byte
		b.Encrypt(s[:], a[:])
		for j := 0; j < 16 && i+j < len(ct); j++ {
			plain[i+j] = ct[i+j] ^ s[j]
		}
	}
	t := ccmMAC(b, len(tag), nonce, aad, plain)
	a0 := ccmCounterBlock(nonce, 0)
	var s0 [16]byte
	b.Encrypt(s0[:], a0[:])
	exp := make([]byte, len(tag))
	for j := range exp {
		exp[j] = t[j] ^ s0[j]
	}
	if subtle.ConstantTimeCompare(exp, tag) != 1 {
		return nil, errCCMAuth
	}
	return plain, nil
}
