package mfb

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRoundTrips(t *testing.T) {
	msgs := []fmtMsg{
		&Beacon{HomeTag: "9f3a07c2", Node: 0xa1b2c3d4, Open: true, Slots: 12, Days: 3},
		&Beacon{HomeTag: "00000001", Node: 1, Open: false, Slots: 0, Days: 7},
		&Roam{HomeTag: "4be10c77", Days: 3},
		&Roam{HomeTag: "4be10c77", Days: 0},
		&Enrol{}, &Enrol{PSK: "correct-horse"},
		&Enrolled{}, &Pending{},
		&Confirm{HomeTag: "9f3a07c2", Days: 3, Name: "Kent Mesh Group"},
		&Refusal{Code: CodeNoSlots}, &Refusal{Code: CodeHomeRefused, Text: "ask the admin"},
		&Sealed{Node: 0xc0ffee01, Ch: 1, Ctr: 0x1f, Part: 2, Total: 3, Data: bytes.Repeat([]byte{9}, 20)},
	}
	for _, m := range msgs {
		line := m.String()
		got, err := Parse(line)
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if got.(fmtMsg).String() != line {
			t.Fatalf("%q reformatted as %q", line, got.(fmtMsg).String())
		}
	}
}

type fmtMsg interface{ String() string }

func TestSpecExamples(t *testing.T) {
	m, err := Parse("MFB1 B 9f3a07c2 a1b2c3d4 O 12 3")
	if err != nil {
		t.Fatal(err)
	}
	b := m.(*Beacon)
	if b.HomeTag != "9f3a07c2" || b.Node != 0xa1b2c3d4 || !b.Open || b.Slots != 12 || b.Days != 3 {
		t.Fatalf("%+v", b)
	}
	m, err = Parse("MFB1 R 4be10c77 3")
	if err != nil || m.(*Roam).Days != 3 {
		t.Fatal(err, m)
	}
	m, _ = Parse("MFB1 R 4be10c77 -")
	if m.(*Roam).Days != 0 {
		t.Fatal("dash means default")
	}
}

func TestIgnoreAndMalformed(t *testing.T) {
	for _, l := range []string{"", "hello", "MFB2 B x", "MFB1", "MFB1 Z 1", "MFB1 BB 1", "MFB1 R 4be10c77 3 é", "mfb1 R 4be10c77 3"} {
		if _, err := Parse(l); !errors.Is(err, ErrIgnore) {
			t.Errorf("%q: want ErrIgnore, got %v", l, err)
		}
	}
	for _, l := range []string{
		"MFB1 B 9f3a07c2 a1b2c3d4 X 12 3", "MFB1 B 9F3A07C2 a1b2c3d4 O 12 3", "MFB1 B 9f3a07c2 a1b2c3d4 O -1 3",
		"MFB1 B 9f3a07c2 a1b2c3d4 O 12 8", "MFB1 B 9f3a07c2 a1b2c3d4 O 12 0", "MFB1 B 9f3a07c2 a1b2c3d4 O 12",
		"MFB1 R 4be10c7 3", "MFB1 R 4be10c77 8", "MFB1 R 4be10c77 33", "MFB1 R 4be10c77",
		"MFB1 E", "MFB1 K x", "MFB1 C 9f3a07c2 3", "MFB1 C 9f3a07c2 3 " + strings.Repeat("n", 25),
		"MFB1 X ZZ", "MFB1 X",
		"MFB1 S c0ffee01 1 1f 2/3 AAAA", "MFB1 S c0ffee01 1 1f 4/3 " + strings.Repeat("A", 40), "MFB1 S c0ffee01 01 zz 1/1 " + strings.Repeat("A", 40),
	} {
		if _, err := Parse(l); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: want ErrMalformed, got %v", l, err)
		}
	}
}

func testKey(t *testing.T) []byte {
	t.Helper()
	k, err := DeriveKey(bytes.Repeat([]byte{7}, 32), "4be10c77", 0xc0ffee01, 0x1234, "Home", ToHome)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKeyDerivationSeparatesContexts(t *testing.T) {
	ck := bytes.Repeat([]byte{7}, 32)
	base, _ := DeriveKey(ck, "4be10c77", 1, 2, "Home", ToHome)
	for name, other := range map[string][]byte{
		"direction": mustKey(DeriveKey(ck, "4be10c77", 1, 2, "Home", ToRoamer)),
		"tag":       mustKey(DeriveKey(ck, "4be10c78", 1, 2, "Home", ToHome)),
		"node":      mustKey(DeriveKey(ck, "4be10c77", 2, 2, "Home", ToHome)),
		"packet id": mustKey(DeriveKey(ck, "4be10c77", 1, 3, "Home", ToHome)),
		"channel":   mustKey(DeriveKey(ck, "4be10c77", 1, 2, "Away", ToHome)),
		"key":       mustKey(DeriveKey(bytes.Repeat([]byte{8}, 32), "4be10c77", 1, 2, "Home", ToHome)),
	} {
		if bytes.Equal(base, other) {
			t.Errorf("%s does not change the key", name)
		}
	}
	if _, err := DeriveKey(nil, "x", 1, 2, "y", ToHome); err == nil {
		t.Error("empty channel key accepted")
	}
}

func mustKey(k []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return k
}

func TestSealSingleAndMultiPart(t *testing.T) {
	key := testKey(t)
	for _, text := range []string{"hi", strings.Repeat("a", 100), strings.Repeat("z", 200)} {
		parts, next, err := SealText(key, 0xc0ffee01, 1, 10, text, BroadcastLineBudget, 3)
		if err != nil {
			t.Fatal(err)
		}
		if next != 10+uint64(len(parts)) {
			t.Fatalf("counter must advance per part: next %d parts %d", next, len(parts))
		}
		r := NewReassembler(3)
		var got string
		var done bool
		for i, p := range parts {
			line := p.String()
			if len(line) > BroadcastLineBudget {
				t.Fatalf("line %d is %d bytes, budget %d", i, len(line), BroadcastLineBudget)
			}
			m, err := Parse(line)
			if err != nil {
				t.Fatal(err)
			}
			got, done, err = r.Add(time.Now(), key, m.(*Sealed))
			if err != nil {
				t.Fatal(err)
			}
		}
		if !done || got != text {
			t.Fatalf("got %q done %v", got, done)
		}
	}
}

func TestMaxPartTextFitsBudgets(t *testing.T) {
	key := testKey(t)
	for _, budget := range []int{BroadcastLineBudget, UnsignedLineBudget, DMLineBudget} {
		n := MaxPartText(budget)
		plain := make([]byte, n)
		rand.Read(plain)
		// worst-case header: 16 hex digit counter, part 9/9
		p, err := SealPart(key, 0xffffffff, 0xff, ^uint64(0), 9, 9, plain)
		if err != nil {
			t.Fatal(err)
		}
		if l := len(p.String()); l > budget {
			t.Errorf("budget %d: line is %d bytes (part text %d)", budget, l, n)
		}
		t.Logf("budget %d bytes: %d bytes of text per part", budget, n)
	}
}

func TestPartLimit(t *testing.T) {
	key := testKey(t)
	if _, _, err := SealText(key, 1, 1, 0, strings.Repeat("x", 1000), BroadcastLineBudget, 3); err == nil {
		t.Fatal("over-long message accepted")
	}
	r := NewReassembler(2)
	p, _ := SealPart(key, 1, 1, 0, 1, 3, []byte("x"))
	if _, _, err := r.Add(time.Now(), key, p); !errors.Is(err, ErrTooManyParts) {
		t.Fatalf("got %v", err)
	}
}

func TestTamperingAndReplay(t *testing.T) {
	key := testKey(t)
	parts, _, _ := SealText(key, 1, 1, 100, strings.Repeat("q", 150), BroadcastLineBudget, 3)
	if len(parts) < 2 {
		t.Fatal("need a multi-part message")
	}
	r := NewReassembler(3)
	renumbered := *parts[0]
	renumbered.Part, renumbered.Total = 2, 2
	if _, _, err := r.Add(time.Now(), key, &renumbered); err == nil {
		t.Fatal("renumbered part accepted")
	}
	moved := *parts[0]
	moved.Node = 2
	if _, _, err := r.Add(time.Now(), key, &moved); err == nil {
		t.Fatal("part moved to another node accepted")
	}
	flipped := *parts[0]
	flipped.Data = append([]byte(nil), parts[0].Data...)
	flipped.Data[0] ^= 1
	if _, _, err := r.Add(time.Now(), key, &flipped); err == nil {
		t.Fatal("corrupted ciphertext accepted")
	}
	if _, _, err := r.Add(time.Now(), key, parts[0]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Add(time.Now(), key, parts[0]); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay not detected: %v", err)
	}
	wrongKey := bytes.Repeat([]byte{1}, 32)
	if _, _, err := NewReassembler(3).Add(time.Now(), wrongKey, parts[0]); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestMissingPartExpires(t *testing.T) {
	key := testKey(t)
	parts, _, _ := SealText(key, 7, 3, 0, strings.Repeat("m", 150), BroadcastLineBudget, 3)
	r := NewReassembler(3)
	t0 := time.Unix(1000, 0)
	if _, done, err := r.Add(t0, key, parts[0]); err != nil || done {
		t.Fatal(err, done)
	}
	if l := r.Expire(t0.Add(119*time.Second), 2*time.Minute); len(l) != 0 {
		t.Fatal("expired early")
	}
	lost := r.Expire(t0.Add(2*time.Minute), 2*time.Minute)
	if len(lost) != 1 || lost[0].Node != 7 || lost[0].Ch != 3 || lost[0].Have != 1 || lost[0].Total != len(parts) {
		t.Fatalf("%+v", lost)
	}
	if len(r.Expire(t0.Add(time.Hour), time.Minute)) != 0 {
		t.Fatal("lost twice")
	}
}

func TestReplayWindow(t *testing.T) {
	var w ReplayWindow
	if !w.Check(5) {
		t.Fatal("first counter must pass")
	}
	w.Commit(5)
	if w.Check(5) {
		t.Fatal("repeat passes")
	}
	if !w.Check(3) {
		t.Fatal("reordered counter must pass")
	}
	w.Commit(70)
	if w.Check(5) {
		t.Fatal("counter more than 63 behind must fail")
	}
	if !w.Check(10) || w.Check(70) {
		t.Fatal("window edges")
	}
	w.Commit(10)
	if w.Check(10) {
		t.Fatal("committed counter passes")
	}
}
