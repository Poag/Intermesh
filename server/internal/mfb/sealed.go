package mfb

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Direction labels for the two sealing keys of one registration.
const (
	ToHome   = "to-home"
	ToRoamer = "to-roamer"
)

// DeriveKey derives the sealing key for one direction of one registration:
// HKDF-SHA256 from the home channel key, with the home tag, the roamer's node
// number, the accepted registration packet ID and the home channel name as
// context, plus a direction label (SPEC.md section 3, sealed traffic).
//
// The exact context encoding below is this implementation's choice and is part
// of the draft spec, pending the independent cryptography review.
func DeriveKey(channelKey []byte, homeTag string, node, regPacketID uint32, channelName, direction string) ([]byte, error) {
	if len(channelKey) == 0 {
		return nil, errors.New("mfb: empty channel key")
	}
	info := fmt.Sprintf("intermesh/MFB1/seal/v1|%s|%s|%08x|%08x|%s", direction, homeTag, node, regPacketID, channelName)
	return hkdf.Key(sha256.New, channelKey, nil, info, chacha20poly1305.KeySize)
}

func sealNonce(ctr uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n
}

// aad binds the visible header fields to the ciphertext so a relay cannot
// renumber parts or move a part between messages.
func aad(node uint32, ch byte, ctr uint64, part, total int) []byte {
	return []byte(fmt.Sprintf("%08x %02x %x %d/%d", node, ch, ctr, part, total))
}

// SealPart encrypts one part. The counter is also the nonce and must never
// repeat under one key.
func SealPart(key []byte, node uint32, ch byte, ctr uint64, part, total int, plain []byte) (*Sealed, error) {
	var a cipher.AEAD
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	data := a.Seal(nil, sealNonce(ctr), plain, aad(node, ch, ctr, part, total))
	return &Sealed{Node: node, Ch: ch, Ctr: ctr, Part: part, Total: total, Data: data}, nil
}

// OpenPart authenticates and decrypts one part.
func OpenPart(key []byte, s *Sealed) ([]byte, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return a.Open(nil, sealNonce(s.Ctr), s.Data, aad(s.Node, s.Ch, s.Ctr, s.Part, s.Total))
}

// Budget helpers. These are derived from reading Router.cpp and are estimates
// until measured on air.
//
// A node signs a broadcast only if the Data encoding including the 66-byte
// signature field fits in 239 bytes (255 minus the 16-byte header). With a
// portnum field (2 bytes), a 2 or 3 byte payload header and a bitfield field
// (2 bytes), that leaves BroadcastLineBudget bytes of text.
const (
	// BroadcastLineBudget is the longest text line a node can send as a signed broadcast.
	BroadcastLineBudget = 166
	// UnsignedLineBudget is the longest text line the server can downlink unsigned
	// (Data.payload is limited to 233 bytes and 239 minus 2 minus 3 minus 2 is 232).
	UnsignedLineBudget = 232
	// DMLineBudget is the longest line in a PKI direct message (255 minus 16 header minus 12 overhead
	// minus 2 minus 3 minus 2).
	DMLineBudget = 220
)

// lineOverhead is the length of "MFB1 S nnnnnnnn cc <ctr> p/t " for a 16-hex-digit counter.
func lineOverhead(ctrDigits int) int { return len("MFB1 S ") + 8 + 1 + 2 + 1 + ctrDigits + 1 + 3 + 1 }

// MaxPartText is the number of plaintext bytes one sealed part can carry in a line of at most
// budget bytes, assuming a counter of up to 16 hex digits.
func MaxPartText(budget int) int {
	avail := budget - lineOverhead(16)
	// base64url without padding: 4 characters per 3 bytes; the data also holds a 16-byte tag.
	raw := avail * 3 / 4
	n := raw - chacha20poly1305.Overhead
	if n < 0 {
		return 0
	}
	return n
}

// SealText splits text into at most maxParts parts of at most MaxPartText(budget) bytes,
// seals each under its own counter (starting at startCtr) and returns the parts and the
// next unused counter. Splitting is by bytes; callers should keep texts to whole UTF-8
// characters across the receiver's reassembly, which joins parts before decoding.
func SealText(key []byte, node uint32, ch byte, startCtr uint64, text string, budget, maxParts int) ([]*Sealed, uint64, error) {
	per := MaxPartText(budget)
	if per <= 0 {
		return nil, startCtr, errors.New("mfb: budget too small")
	}
	b := []byte(text)
	total := (len(b) + per - 1) / per
	if total == 0 {
		total = 1
	}
	if total > maxParts {
		return nil, startCtr, fmt.Errorf("mfb: message needs %d parts, limit is %d", total, maxParts)
	}
	out := make([]*Sealed, 0, total)
	ctr := startCtr
	for i := 0; i < total; i++ {
		lo := i * per
		hi := min(lo+per, len(b))
		p, err := SealPart(key, node, ch, ctr, i+1, total, b[lo:hi])
		if err != nil {
			return nil, startCtr, err
		}
		out = append(out, p)
		ctr++
	}
	return out, ctr, nil
}
