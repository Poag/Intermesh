// Package mfb parses and formats the MFB1 on-air messages defined in SPEC.md
// section 3: beacon (B), roaming broadcast (R), enrolment DM (E), replies
// K and P, registration confirmation (C), refusal notice (X) and sealed traffic
// (S). A message is one line of ASCII text starting "MFB1", a type letter and
// space-separated fields.
package mfb

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Tag is the protocol tag and version every message starts with.
const Tag = "MFB1"

var (
	// ErrIgnore means the line is not an MFB1 message this version knows. A
	// receiver ignores such messages without replying (SPEC.md section 2).
	ErrIgnore = errors.New("mfb: not a known MFB1 message")
	// ErrMalformed means the line is a known message type with bad fields. The
	// receiver may answer with refusal code BF.
	ErrMalformed = errors.New("mfb: malformed message")
)

// Refusal codes (SPEC.md refusal notice).
const (
	CodeCommunityClosed = "CL"
	CodeNoSlots         = "NS"
	CodeBlocked         = "BL"
	CodeUnsigned        = "US"
	CodeHomeUnknown     = "UH"
	CodeHomeRefused     = "HR"
	CodeRepeat          = "RP"
	CodeBadFormat       = "BF"
	CodeEnrolPSK        = "EP"
	CodeEnrolClosed     = "EC"
)

var refusalCodes = map[string]bool{
	CodeCommunityClosed: true, CodeNoSlots: true, CodeBlocked: true, CodeUnsigned: true, CodeHomeUnknown: true,
	CodeHomeRefused: true, CodeRepeat: true, CodeBadFormat: true, CodeEnrolPSK: true, CodeEnrolClosed: true,
}

// ValidCode reports whether c is a defined refusal code.
func ValidCode(c string) bool { return refusalCodes[c] }

// Beacon is "MFB1 B <tag> <node> <state> <slots> <days>".
type Beacon struct {
	HomeTag string
	Node    uint32
	Open    bool
	Slots   int
	Days    int
}

// Roam is "MFB1 R <hometag> <days>". Days 0 means "-", the community default.
type Roam struct {
	HomeTag string
	Days    int
}

// Enrol is "MFB1 E <psk>". PSK is empty when the field is "-".
type Enrol struct{ PSK string }

// Enrolled is the reply "MFB1 K".
type Enrolled struct{}

// Pending is the reply "MFB1 P".
type Pending struct{}

// Confirm is "MFB1 C <node> <tag> <days> <name>"; the name is last and may contain spaces. The
// message names the roamer because the firmware refuses a channel-encrypted text addressed to
// a node, so it travels as a broadcast on the roaming channel (or as a PKI direct message).
type Confirm struct {
	Node    uint32
	HomeTag string
	Days    int
	Name    string
}

// Refusal is "MFB1 X <node> <code> [free text]", delivered like Confirm.
type Refusal struct {
	Node uint32
	Code string
	Text string
}

// Sealed is "MFB1 S <node> <ch> <ctr> <part> <data>".
type Sealed struct {
	Node  uint32
	Ch    byte
	Ctr   uint64
	Part  int
	Total int
	Data  []byte // ciphertext followed by the 16-byte tag
}

// MaxNameLen is the proposed limit on a community name in a confirmation.
const MaxNameLen = 24

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func isASCIIPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func hex8(s string) (uint32, bool) {
	if !isLowerHex(s, 8) {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 16, 32)
	return uint32(v), err == nil
}

func parseDays(s string) (int, bool) {
	if len(s) != 1 || s[0] < '1' || s[0] > '7' {
		return 0, false
	}
	return int(s[0] - '0'), true
}

// Parse decodes one message line. Anything that is not MFB1, or has an unknown
// type letter, returns ErrIgnore. A known type with bad fields returns
// ErrMalformed.
func Parse(line string) (any, error) {
	if !isASCIIPrintable(line) {
		return nil, ErrIgnore
	}
	f := strings.Split(line, " ")
	if len(f) < 2 || f[0] != Tag || len(f[1]) != 1 {
		return nil, ErrIgnore
	}
	switch f[1] {
	case "B":
		if len(f) != 7 {
			return nil, ErrMalformed
		}
		node, ok1 := hex8(f[3])
		days, ok2 := parseDays(f[6])
		slots, err := strconv.Atoi(f[5])
		if !isLowerHex(f[2], 8) || !ok1 || !ok2 || err != nil || slots < 0 || (f[4] != "O" && f[4] != "C") {
			return nil, ErrMalformed
		}
		return &Beacon{HomeTag: f[2], Node: node, Open: f[4] == "O", Slots: slots, Days: days}, nil
	case "R":
		if len(f) != 4 || !isLowerHex(f[2], 8) {
			return nil, ErrMalformed
		}
		days := 0
		if f[3] != "-" {
			d, ok := parseDays(f[3])
			if !ok {
				return nil, ErrMalformed
			}
			days = d
		}
		return &Roam{HomeTag: f[2], Days: days}, nil
	case "E":
		if len(f) != 3 || f[2] == "" {
			return nil, ErrMalformed
		}
		if f[2] == "-" {
			return &Enrol{}, nil
		}
		return &Enrol{PSK: f[2]}, nil
	case "K":
		if len(f) != 2 {
			return nil, ErrMalformed
		}
		return &Enrolled{}, nil
	case "P":
		if len(f) != 2 {
			return nil, ErrMalformed
		}
		return &Pending{}, nil
	case "C":
		if len(f) < 6 || !isLowerHex(f[3], 8) {
			return nil, ErrMalformed
		}
		node, ok1 := hex8(f[2])
		days, ok2 := parseDays(f[4])
		name := strings.Join(f[5:], " ")
		if !ok1 || !ok2 || name == "" || len(name) > MaxNameLen {
			return nil, ErrMalformed
		}
		return &Confirm{Node: node, HomeTag: f[3], Days: days, Name: name}, nil
	case "X":
		if len(f) < 4 || !refusalCodes[f[3]] {
			return nil, ErrMalformed
		}
		node, ok := hex8(f[2])
		if !ok {
			return nil, ErrMalformed
		}
		return &Refusal{Node: node, Code: f[3], Text: strings.Join(f[4:], " ")}, nil
	case "S":
		if len(f) != 7 {
			return nil, ErrMalformed
		}
		node, ok := hex8(f[2])
		if !ok || len(f[3]) != 2 || !isLowerHex(f[3], 2) {
			return nil, ErrMalformed
		}
		ch, _ := strconv.ParseUint(f[3], 16, 8)
		if len(f[4]) == 0 || len(f[4]) > 16 || !isLowerHexAny(f[4]) {
			return nil, ErrMalformed
		}
		ctr, _ := strconv.ParseUint(f[4], 16, 64)
		part, total, ok := parsePart(f[5])
		if !ok {
			return nil, ErrMalformed
		}
		data, err := base64.RawURLEncoding.DecodeString(f[6])
		if err != nil || len(data) < 16 {
			return nil, ErrMalformed
		}
		return &Sealed{Node: node, Ch: byte(ch), Ctr: ctr, Part: part, Total: total, Data: data}, nil
	}
	return nil, ErrIgnore
}

func isLowerHexAny(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func parsePart(s string) (part, total int, ok bool) {
	a, b, found := strings.Cut(s, "/")
	if !found {
		return 0, 0, false
	}
	p, err1 := strconv.Atoi(a)
	t, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil || p < 1 || t < 1 || p > t || t > 9 {
		return 0, 0, false
	}
	return p, t, true
}

// String formats the message as its on-air line.
func (m *Beacon) String() string {
	st := "C"
	if m.Open {
		st = "O"
	}
	return fmt.Sprintf("MFB1 B %s %08x %s %d %d", m.HomeTag, m.Node, st, m.Slots, m.Days)
}

func (m *Roam) String() string {
	d := "-"
	if m.Days != 0 {
		d = strconv.Itoa(m.Days)
	}
	return fmt.Sprintf("MFB1 R %s %s", m.HomeTag, d)
}

func (m *Enrol) String() string {
	if m.PSK == "" {
		return "MFB1 E -"
	}
	return "MFB1 E " + m.PSK
}

func (*Enrolled) String() string { return "MFB1 K" }
func (*Pending) String() string  { return "MFB1 P" }

func (m *Confirm) String() string {
	return fmt.Sprintf("MFB1 C %08x %s %d %s", m.Node, m.HomeTag, m.Days, m.Name)
}

func (m *Refusal) String() string {
	if m.Text == "" {
		return fmt.Sprintf("MFB1 X %08x %s", m.Node, m.Code)
	}
	return fmt.Sprintf("MFB1 X %08x %s %s", m.Node, m.Code, m.Text)
}

func (m *Sealed) String() string {
	return fmt.Sprintf("MFB1 S %08x %02x %x %d/%d %s", m.Node, m.Ch, m.Ctr, m.Part, m.Total, base64.RawURLEncoding.EncodeToString(m.Data))
}
