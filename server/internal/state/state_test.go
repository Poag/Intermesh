package state

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newState(t *testing.T) (*State, *clock) {
	t.Helper()
	c := &clock{t: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
	st, err := Open("", c.now)
	if err != nil {
		t.Fatal(err)
	}
	return st, c
}

func TestPSKKinds(t *testing.T) {
	st, c := newState(t)

	single, _ := st.NewPSK(PSKSingleUse, "one", 0, time.Time{})
	if _, ok := st.ConsumePSK(single.Secret); !ok {
		t.Fatal("first use of a single-use PSK must succeed")
	}
	if _, ok := st.ConsumePSK(single.Secret); ok {
		t.Fatal("second use of a single-use PSK must fail")
	}

	multi, _ := st.NewPSK(PSKMultiUse, "many", 0, c.now().Add(time.Hour))
	for i := 0; i < 3; i++ {
		if _, ok := st.ConsumePSK(multi.Secret); !ok {
			t.Fatal("multi-use PSK must work repeatedly")
		}
	}
	c.advance(2 * time.Hour)
	if _, ok := st.ConsumePSK(multi.Secret); ok {
		t.Fatal("expired multi-use PSK accepted")
	}
	if _, err := st.NewPSK(PSKMultiUse, "", 0, c.now().Add(-time.Hour)); err == nil {
		t.Fatal("multi-use PSK with a past expiry accepted")
	}

	forever, _ := st.NewPSK(PSKNonExpiring, "", 0, time.Time{})
	c.advance(1000 * time.Hour)
	if _, ok := st.ConsumePSK(forever.Secret); !ok {
		t.Fatal("non-expiring PSK expired")
	}
	if err := st.RevokePSK(forever.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.ConsumePSK(forever.Secret); ok {
		t.Fatal("revoked PSK accepted")
	}
	if _, ok := st.ConsumePSK("not-a-psk"); ok {
		t.Fatal("garbage accepted")
	}
}

func TestRotatingPSKDefaultsToSevenDaysAndOnlyCurrentWorks(t *testing.T) {
	st, c := newState(t)
	p, _ := st.NewPSK(PSKRotating, "rot", 0, time.Time{})
	if p.Period != 7*24*time.Hour {
		t.Fatalf("default period %v", p.Period)
	}
	old := p.Secret
	if _, ok := st.ConsumePSK(old); !ok {
		t.Fatal("current secret rejected")
	}
	c.advance(7*24*time.Hour + time.Minute)
	if _, ok := st.ConsumePSK(old); ok {
		t.Fatal("old secret accepted after rotation")
	}
	var cur string
	for _, q := range st.PSKs() {
		if q.ID == p.ID {
			cur = q.Secret
		}
	}
	if cur == old || cur == "" {
		t.Fatal("secret did not rotate")
	}
	if _, ok := st.ConsumePSK(cur); !ok {
		t.Fatal("new secret rejected")
	}
}

func TestEnrolBindsFirstKey(t *testing.T) {
	st, _ := newState(t)
	k1, k2 := make([]byte, 32), make([]byte, 32)
	k2[0] = 1
	if _, err := st.Enrol(0x1234, k1, "public", false); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Enrol(0x1234, k2, "public", false); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("different key for the same node accepted: %v", err)
	}
	if _, err := st.Enrol(0x1234, k1, "public", false); err != nil {
		t.Fatal("re-enrolling with the same key must be idempotent")
	}
	// pending then approved
	if _, err := st.Enrol(0x9999, k2, "", true); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Member(0x9999); ok {
		t.Fatal("pending member visible as enrolled")
	}
	if err := st.Approve(0x9999); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Member(0x9999); !ok {
		t.Fatal("approved member missing")
	}
	if err := st.RemoveMember(0x9999); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.AnyMember(0x9999); ok {
		t.Fatal("removed member present")
	}
}

func TestRegistrationReplayAndExpiry(t *testing.T) {
	st, c := newState(t)
	if err := st.CheckAndRecordPacket(1, 100); err != nil {
		t.Fatal(err)
	}
	if err := st.CheckAndRecordPacket(1, 100); !errors.Is(err, ErrRepeat) {
		t.Fatalf("repeat not refused: %v", err)
	}
	if err := st.CheckAndRecordPacket(2, 100); err != nil {
		t.Fatal("same packet id from another node must be accepted")
	}
	st.Prune(7*24*time.Hour+time.Hour, time.Hour)
	if err := st.CheckAndRecordPacket(1, 100); !errors.Is(err, ErrRepeat) {
		t.Fatal("pruned too early")
	}
	c.advance(8*24*time.Hour + time.Hour)
	st.Prune(7*24*time.Hour+time.Hour, time.Hour)
	if err := st.CheckAndRecordPacket(1, 100); err != nil {
		t.Fatalf("not forgotten after retention: %v", err)
	}

	if _, err := st.AcceptRegistration(1, "https://b", 5, 0); err == nil {
		t.Fatal("zero days accepted")
	}
	if _, err := st.AcceptRegistration(1, "https://b", 5, 8); err == nil {
		t.Fatal("eight days accepted")
	}
	r, err := st.AcceptRegistration(1, "https://b", 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	if want := c.now().Add(72 * time.Hour); !r.Expires.Equal(want) {
		t.Fatalf("expiry %v want %v", r.Expires, want)
	}
	c.advance(73 * time.Hour)
	if _, ok := st.RouteFor(1); ok {
		t.Fatal("expired registration routed")
	}
	if gone := st.ExpireRegistrations(); len(gone) != 1 {
		t.Fatalf("expired %d", len(gone))
	}
}

func TestRouteForPrefersLastRelayed(t *testing.T) {
	st, c := newState(t)
	st.AcceptRegistration(7, "https://a", 1, 3)
	c.advance(time.Minute)
	st.AcceptRegistration(7, "https://b", 2, 3)
	if r, _ := st.RouteFor(7); r.Visitor != "https://b" {
		t.Fatalf("most recently accepted should win first, got %s", r.Visitor)
	}
	c.advance(time.Minute)
	st.TouchRelayed(7, "https://a")
	if r, _ := st.RouteFor(7); r.Visitor != "https://a" {
		t.Fatalf("last relayed should win, got %s", r.Visitor)
	}
	visitors := st.EndAllFor(7)
	if len(visitors) != 2 {
		t.Fatalf("EndAllFor %v", visitors)
	}
	if _, ok := st.RouteFor(7); ok {
		t.Fatal("route survives EndAllFor")
	}
}

func TestDownCounterNeverRepeatsAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	c := &clock{t: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
	st, err := Open(path, c.now)
	if err != nil {
		t.Fatal(err)
	}
	st.AcceptRegistration(9, "https://v", 77, 2)
	a, _ := st.NextDownCounter(9, "https://v", 3)
	b, _ := st.NextDownCounter(9, "https://v", 1)
	if a != 0 || b != 3 {
		t.Fatalf("counters %d %d", a, b)
	}
	st2, err := Open(path, c.now)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := st2.NextDownCounter(9, "https://v", 1)
	if n != 4 {
		t.Fatalf("counter after reload %d, want 4", n)
	}
	if _, err := st.NextDownCounter(10, "https://v", 1); err == nil {
		t.Fatal("counter for unknown registration")
	}
}

func TestVisitsSlotsAndPending(t *testing.T) {
	st, c := newState(t)
	st.BeginVisit(Visit{Node: 1, HomeActor: "https://h", HomeTag: "aaaaaaaa", RegPacketID: 1})
	st.BeginVisit(Visit{Node: 2, HomeActor: "https://h", HomeTag: "aaaaaaaa", RegPacketID: 2})
	if st.SlotsInUse() != 0 || st.PendingVisits() != 2 {
		t.Fatal("pending visits must take no slot")
	}
	st.AcceptVisit(1, c.now().Add(24*time.Hour), nil)
	if st.SlotsInUse() != 1 || st.PendingVisits() != 1 {
		t.Fatal("accepted visit takes a slot")
	}
	if _, ok := st.ActiveVisit(2); ok {
		t.Fatal("pending visit active")
	}
	c.advance(10 * time.Minute)
	st.ExpireVisits(5 * time.Minute)
	if st.PendingVisits() != 0 {
		t.Fatal("stale pending visit kept")
	}
	c.advance(25 * time.Hour)
	if gone := st.ExpireVisits(time.Minute); len(gone) != 1 || gone[0].Node != 1 {
		t.Fatalf("%+v", gone)
	}
	if st.SlotsInUse() != 0 {
		t.Fatal("slot not freed")
	}
}

func TestPeersCapBlockRename(t *testing.T) {
	st, c := newState(t)
	for i, name := range []string{"https://a", "https://b", "https://c"} {
		c.advance(time.Minute)
		if err := st.UpsertPeer(Peer{Actor: name, HomeTag: "0000000" + string(rune('1'+i))}, 2); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := st.Peer("https://a"); ok {
		t.Fatal("least recently heard peer was not dropped")
	}
	st.SetBlocked("https://b", true)
	c.advance(time.Minute)
	st.UpsertPeer(Peer{Actor: "https://d", HomeTag: "00000004"}, 2)
	if _, ok := st.Peer("https://b"); !ok || !st.IsBlocked("https://b") {
		t.Fatal("blocked peer must survive eviction")
	}
	if len(st.PeersByTag("00000002")) != 0 {
		t.Fatal("blocked peer returned by tag")
	}
	if _, ok := st.Peer("https://c"); ok {
		t.Fatal("c should have been evicted when d joined a full list")
	}
	if err := st.ApplyRename("https://d", "ffffffff", "00000009"); err == nil {
		t.Fatal("rename accepted for a tag the peer does not hold")
	}
	if err := st.ApplyRename("https://nobody", "00000004", "00000009"); err == nil {
		t.Fatal("rename accepted from an unknown server")
	}
	if err := st.ApplyRename("https://d", "00000004", "00000009"); err != nil {
		t.Fatal(err)
	}
	if len(st.PeersByTag("00000009")) != 1 || len(st.PeersByTag("00000004")) != 1 {
		t.Fatal("new tag and old alias must both resolve")
	}
}

func TestActivityReplayMemory(t *testing.T) {
	st, c := newState(t)
	if st.SeenActivity("x") {
		t.Fatal("first sight reported as seen")
	}
	if !st.SeenActivity("x") {
		t.Fatal("repeat not detected")
	}
	c.advance(10 * time.Minute)
	st.Prune(time.Hour, 5*time.Minute)
	if st.SeenActivity("x") {
		t.Fatal("activity id not forgotten after the window")
	}
}

func TestRateLimiter(t *testing.T) {
	r := NewRateLimiter(2, time.Minute)
	t0 := time.Unix(0, 0)
	if !r.Allow("k", t0) || !r.Allow("k", t0.Add(time.Second)) || r.Allow("k", t0.Add(2*time.Second)) {
		t.Fatal("limit not enforced")
	}
	if !r.Allow("other", t0) {
		t.Fatal("keys must be independent")
	}
	if !r.Allow("k", t0.Add(61*time.Second)) {
		t.Fatal("window did not slide")
	}
	if !NewRateLimiter(0, time.Minute).Allow("k", t0) {
		t.Fatal("zero limit must disable")
	}
}

func TestChannelLookupIsCaseInsensitive(t *testing.T) {
	st, _ := newState(t)
	st.SetChannel(Channel{Name: "InterRoam", Key: []byte{1}, Uplink: true, Downlink: true})
	if _, ok := st.Channel("interroam"); !ok {
		t.Fatal("lookup should ignore case")
	}
}
