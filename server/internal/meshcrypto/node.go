package meshcrypto

import (
	"fmt"
	"hash/crc32"
	"strconv"
	"strings"
)

// NodeNum is a Meshtastic node number. For a node with a PKI key it is the
// CRC-32 (IEEE, as ErriezCRC32 1.0.1 computes it: reflected polynomial
// 0xEDB88320, initial value 0xFFFFFFFF, final complement) of the 32-byte
// public key (NodeDB.cpp, Router.cpp verifyFirstContactNodeInfo).
func NodeNumFromKey(pub []byte) uint32 { return crc32.ChecksumIEEE(pub) }

// NodeID formats a node number the way gateways write it in MQTT topics and
// the gateway_id field: "!" and eight lowercase hex digits.
func NodeID(n uint32) string { return fmt.Sprintf("!%08x", n) }

// ParseNodeID accepts "!a1b2c3d4" or "a1b2c3d4".
func ParseNodeID(s string) (uint32, error) {
	s = strings.TrimPrefix(s, "!")
	if len(s) != 8 {
		return 0, fmt.Errorf("node id %q: want 8 hex digits", s)
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("node id %q: %w", s, err)
	}
	return uint32(v), nil
}
