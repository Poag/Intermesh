package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Poag/Intermesh/server/internal/ap"
	"github.com/Poag/Intermesh/server/internal/meshwire"
	"github.com/Poag/Intermesh/server/internal/mfb"
	"github.com/Poag/Intermesh/server/internal/state"
)

// xr is the refusal line a node should receive: the message names the node.
func xr(n *simNode, code string) string { return "MFB1 X " + nodeHex(n.num) + " " + code }

func lastPKIText(t *testing.T, s *site, n *simNode) string {
	t.Helper()
	got := decodePKI(t, s.gw.all(), n, s.serverNum(), s.serverPub())
	if len(got) == 0 {
		return ""
	}
	return got[len(got)-1].Text
}

func TestEnrolmentModes(t *testing.T) {
	clk := newClock()
	for _, mode := range []string{EnrolPublic, EnrolPSK, EnrolManual, EnrolClosed} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			s := newSite(t, clk, "Home", func(c *Config) { c.Enrolment = mode })
			n := newSimNode()
			// the server learns the node's key from the NodeInfo it broadcast on a bridged channel
			s.uplink("Home", n.nodeInfoUplink(t, "Home", s.home.Key, s.gwID))
			send := func(text string) string {
				s.gw.clear()
				s.uplink("PKI", n.dmUplink(t, s.serverNum(), s.serverPub(), text, s.gwID))
				return lastPKIText(t, s, n)
			}
			switch mode {
			case EnrolPublic:
				if got := send("MFB1 E -"); got != "MFB1 K" {
					t.Fatalf("public enrolment: %q", got)
				}
			case EnrolClosed:
				if got := send("MFB1 E -"); got != xr(n, "EC") {
					t.Fatalf("closed: %q", got)
				}
			case EnrolPSK:
				if got := send("MFB1 E -"); got != xr(n, "EP") {
					t.Fatalf("no PSK: %q", got)
				}
				if got := send("MFB1 E wrong"); got != xr(n, "EP") {
					t.Fatalf("wrong PSK: %q", got)
				}
				p, _ := s.st.NewPSK(state.PSKSingleUse, "", 0, time.Time{})
				if got := send("MFB1 E " + p.Secret); got != "MFB1 K" {
					t.Fatalf("right PSK: %q", got)
				}
				other := newSimNode()
				s.uplink("Home", other.nodeInfoUplink(t, "Home", s.home.Key, s.gwID))
				s.gw.clear()
				s.uplink("PKI", other.dmUplink(t, s.serverNum(), s.serverPub(), "MFB1 E "+p.Secret, s.gwID))
				if got := lastPKIText(t, s, other); got != xr(other, "EP") {
					t.Fatalf("a single-use PSK worked twice: %q", got)
				}
			case EnrolManual:
				if got := send("MFB1 E -"); got != "MFB1 P" {
					t.Fatalf("manual, no PSK: %q", got)
				}
				if _, ok := s.st.Member(n.num); ok {
					t.Fatal("pending node counted as enrolled")
				}
				if err := s.st.Approve(n.num); err != nil {
					t.Fatal(err)
				}
				if _, ok := s.st.Member(n.num); !ok {
					t.Fatal("approval did not enrol")
				}
				n2 := newSimNode()
				s.uplink("Home", n2.nodeInfoUplink(t, "Home", s.home.Key, s.gwID))
				p, _ := s.st.NewPSK(state.PSKNonExpiring, "", 0, time.Time{})
				s.gw.clear()
				s.uplink("PKI", n2.dmUplink(t, s.serverNum(), s.serverPub(), "MFB1 E "+p.Secret, s.gwID))
				if got := lastPKIText(t, s, n2); got != "MFB1 K" {
					t.Fatalf("manual with PSK: %q", got)
				}
			}
			if mode != EnrolClosed && mode != EnrolManual {
				if _, ok := s.st.Member(n.num); !ok {
					t.Fatal("node not enrolled")
				}
			}
			if mode == EnrolClosed {
				if _, ok := s.st.AnyMember(n.num); ok {
					t.Fatal("closed server enrolled a node")
				}
			}
			// replies go back through the gateway the request came through
			for _, p := range s.gw.all() {
				if p.Target != s.gwID {
					t.Fatalf("reply targeted %q, want the originating gateway", p.Target)
				}
			}
		})
	}
}

func TestEnrolmentNeedsKnownKeyAndRefusesReplayAndKeySwap(t *testing.T) {
	clk := newClock()
	s := newSite(t, clk, "Home", func(c *Config) { c.Enrolment = EnrolPublic })
	n := newSimNode()
	// no NodeInfo heard yet: the server cannot decrypt, so there is no reply, only a console warning
	s.uplink("PKI", n.dmUplink(t, s.serverNum(), s.serverPub(), "MFB1 E -", s.gwID))
	if len(s.gw.all()) != 0 {
		t.Fatal("replied to a node whose key was unknown")
	}
	var warned bool
	for _, ev := range s.eng.Events() {
		if ev.Kind == "warning" && strings.Contains(ev.Message, "public key is not known") {
			warned = true
		}
	}
	if !warned {
		t.Fatal("no console warning for the unreadable direct message")
	}

	s.uplink("Home", n.nodeInfoUplink(t, "Home", s.home.Key, s.gwID))
	raw := n.dmUplink(t, s.serverNum(), s.serverPub(), "MFB1 E -", s.gwID)
	s.uplink("PKI", raw)
	if lastPKIText(t, s, n) != "MFB1 K" {
		t.Fatal("not enrolled")
	}
	// the same packet again, after the dedupe window, is refused by the replay memory
	clk.Advance(11 * time.Minute)
	s.gw.clear()
	s.uplink("PKI", raw)
	if len(s.gw.all()) != 0 {
		t.Fatal("a replayed enrolment got a reply")
	}

	// a different key claiming the same node number cannot replace the first
	if _, err := s.st.Enrol(n.num, make([]byte, 32), "public", false); err == nil {
		t.Fatal("key swap accepted")
	}
}

func TestNodeInfoWithWrongNodeNumberIsIgnored(t *testing.T) {
	clk := newClock()
	s := newSite(t, clk, "Home", nil)
	n := newSimNode()
	liar := newSimNode()
	// liar claims n's node number: its key's CRC-32 does not match, so the key must not be learned
	u := &meshwire.User{ID: n.id(), PublicKey: liar.pub}
	forged := &simNode{priv: liar.priv, pub: liar.pub, num: n.num}
	s.uplink("Home", forged.channelUplink(t, "Home", s.home.Key, s.gwID, meshwire.PortNodeInfo, u.Marshal(), meshwire.BroadcastNum, true, 0))
	if _, ok := s.st.NodeKey(n.num); ok {
		t.Fatal("learned a key whose CRC-32 is not the node number")
	}
}

// the whole roaming path across two servers over real HTTP.
func TestRoamingEndToEnd(t *testing.T) {
	clk := newClock()
	home := newSite(t, clk, "Kent Mesh", nil)
	away := newSite(t, clk, "Away Group", nil)
	ctx := context.Background()
	if _, err := away.eng.LinkUp(ctx, home.actor()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the home server learns the visited server", func() bool { _, ok := home.st.Peer(away.actor()); return ok })

	roamer := newSimNode()
	home.st.Enrol(roamer.num, roamer.pub, "admin", false)
	homeTag := home.eng.HomeTag()

	const pktID = 0x1234abcd
	line := (&mfb.Roam{HomeTag: homeTag, Days: 2}).String()
	away.uplink("InterRoam", roamer.channelUplink(t, "InterRoam", away.roamKey(), away.gwID, meshwire.PortText, []byte(line), meshwire.BroadcastNum, true, pktID))

	eventually(t, "the visited server has an accepted visit", func() bool { _, ok := away.st.ActiveVisit(roamer.num); return ok })
	reg, ok := home.st.Registration(roamer.num, away.actor())
	if !ok || reg.PacketID != pktID {
		t.Fatalf("home registration: %+v", reg)
	}
	if want := clk.Now().Add(48 * time.Hour); reg.Expires.Sub(want) > time.Minute || want.Sub(reg.Expires) > time.Minute {
		t.Fatalf("expiry %v, want about %v (the roamer asked for 2 days, the default is 3)", reg.Expires, want)
	}

	// the roamer was told, by a unicast on the roaming channel
	var conf *mfb.Confirm
	for _, h := range decodeChannel(t, away.gw.all(), "InterRoam", away.roamKey()) {
		if m, err := mfb.Parse(h.Text); err == nil {
			if c, ok := m.(*mfb.Confirm); ok && c.Node == roamer.num {
				if h.To != meshwire.BroadcastNum {
					t.Fatalf("the confirmation was addressed to %08x: the firmware refuses a channel text addressed to a node, so it must be a broadcast", h.To)
				}
				conf = c
			}
		}
	}
	if conf == nil || conf.HomeTag != homeTag || conf.Days != 2 || conf.Name != "Away Group" {
		t.Fatalf("confirmation: %+v", conf)
	}

	// upstream: the roamer's app seals a message; the visited server relays it blind
	ch := home.home
	toHome, _ := mfb.DeriveKey(ch.Key, homeTag, roamer.num, pktID, ch.Name, mfb.ToHome)
	parts, _, err := mfb.SealText(toHome, roamer.num, ch.Number, 0, "hello from afar", mfb.BroadcastLineBudget, 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range parts {
		away.uplink("InterRoam", roamer.channelUplink(t, "InterRoam", away.roamKey(), away.gwID, meshwire.PortText, []byte(p.String()), meshwire.BroadcastNum, true, 0))
	}
	want := nodeHex(roamer.num) + ": hello from afar"
	eventually(t, "the roamer's message appears on its home channel", func() bool {
		for _, h := range decodeChannel(t, home.gw.all(), "Home", ch.Key) {
			if h.Text == want && h.From == home.serverNum() && h.Signed {
				return true
			}
		}
		return false
	})

	// downstream: a home channel message reaches the roamer, sealed to its registration
	member := newSimNode()
	home.uplink("Home", member.channelUplink(t, "Home", ch.Key, home.gwID, meshwire.PortText, []byte("dinner at 7"), meshwire.BroadcastNum, true, 0))
	toRoamer, _ := mfb.DeriveKey(ch.Key, homeTag, roamer.num, pktID, ch.Name, mfb.ToRoamer)
	ra := mfb.NewReassembler(3)
	var got string
	eventually(t, "the sealed home message reaches the roamer through the visited server", func() bool {
		for _, h := range decodeChannel(t, away.gw.all(), "InterRoam", away.roamKey()) {
			m, err := mfb.Parse(h.Text)
			if err != nil {
				continue
			}
			if s, ok := m.(*mfb.Sealed); ok && s.Node == roamer.num {
				if h.To != meshwire.BroadcastNum {
					t.Fatalf("sealed downlink addressed to %08x: must be a broadcast", h.To)
				}
				if text, done, err := ra.Add(time.Now(), 1, toRoamer, s); err == nil && done {
					got = text
					return true
				}
			}
		}
		return false
	})
	if got != nodeHex(member.num)+": dinner at 7" {
		t.Fatalf("roamer received %q", got)
	}
	// the visited server never saw a key or the plaintext
	for _, p := range away.gw.all() {
		if strings.Contains(string(p.Payload), "dinner") {
			t.Fatal("plaintext on the visited server's downlink")
		}
	}

	// the roamer is heard on the home mesh again: the registration ends on both servers
	home.uplink("Home", roamer.channelUplink(t, "Home", ch.Key, home.gwID, meshwire.PortText, []byte("back home"), meshwire.BroadcastNum, true, 0))
	eventually(t, "the registration ends early when the roamer is heard at home", func() bool {
		_, v := away.st.ActiveVisit(roamer.num)
		_, r := home.st.Registration(roamer.num, away.actor())
		return !v && !r
	})
}

func refusalFor(t *testing.T, s *site, n *simNode) string {
	t.Helper()
	var code string
	for _, h := range decodeChannel(t, s.gw.all(), "InterRoam", s.roamKey()) {
		if m, err := mfb.Parse(h.Text); err == nil {
			if r, ok := m.(*mfb.Refusal); ok && r.Node == n.num {
				code = r.Code
			}
		}
	}
	return code
}

func register(t *testing.T, s *site, n *simNode, tag string, signed bool, pktID uint32) {
	t.Helper()
	line := (&mfb.Roam{HomeTag: tag}).String()
	s.uplink("InterRoam", n.channelUplink(t, "InterRoam", s.roamKey(), s.gwID, meshwire.PortText, []byte(line), meshwire.BroadcastNum, signed, pktID))
}

func TestRoamingRefusals(t *testing.T) {
	clk := newClock()
	home := newSite(t, clk, "Home", nil)
	away := newSite(t, clk, "Away", nil)
	if _, err := away.eng.LinkUp(context.Background(), home.actor()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "link", func() bool { _, ok := home.st.Peer(away.actor()); return ok })
	tag := home.eng.HomeTag()

	enrolled := newSimNode()
	home.st.Enrol(enrolled.num, enrolled.pub, "admin", false)

	t.Run("unsigned registration is refused with US at the visited server", func(t *testing.T) {
		n := newSimNode()
		register(t, away, n, tag, false, 0)
		if c := refusalFor(t, away, n); c != "US" {
			t.Fatalf("got %q", c)
		}
		if _, ok := away.st.Visit(n.num); ok {
			t.Fatal("an unsigned registration started a visit")
		}
	})
	t.Run("unknown community tag gives UH", func(t *testing.T) {
		n := newSimNode()
		register(t, away, n, "deadbeef", true, 0)
		if c := refusalFor(t, away, n); c != "UH" {
			t.Fatalf("got %q", c)
		}
	})
	t.Run("node not enrolled at home gives HR", func(t *testing.T) {
		n := newSimNode()
		register(t, away, n, tag, true, 0)
		eventually(t, "HR refusal", func() bool { return refusalFor(t, away, n) == "HR" })
		if _, ok := away.st.ActiveVisit(n.num); ok {
			t.Fatal("registered although the home server refused")
		}
		if _, ok := away.st.Visit(n.num); ok {
			t.Fatal("a refused visit was kept")
		}
	})
	t.Run("signature that does not belong to the enrolled key gives US from home", func(t *testing.T) {
		impostor := newSimNode()
		forged := &simNode{priv: impostor.priv, pub: impostor.pub, num: enrolled.num} // claims the enrolled node's number
		register(t, away, forged, tag, true, 0)
		eventually(t, "US refusal from home", func() bool { return refusalFor(t, away, enrolled) == "US" })
		if _, ok := home.st.Registration(enrolled.num, away.actor()); ok {
			t.Fatal("registered on a forged signature")
		}
	})
	t.Run("the visited server relays nothing before the home server accepts", func(t *testing.T) {
		n := newSimNode()
		// a visit that is still pending takes no slot and relays no sealed traffic
		away.st.BeginVisit(state.Visit{Node: n.num, HomeActor: home.actor(), HomeTag: tag, RegPacketID: 1})
		if away.st.SlotsInUse() != 0 {
			t.Fatal("pending visit took a slot")
		}
		before := len(home.st.Registrations())
		p, _ := mfb.SealPart(make([]byte, 32), n.num, 1, 0, 1, 1, []byte("x"))
		away.uplink("InterRoam", n.channelUplink(t, "InterRoam", away.roamKey(), away.gwID, meshwire.PortText, []byte(p.String()), meshwire.BroadcastNum, true, 0))
		away.wait()
		if len(home.st.Registrations()) != before || len(home.gw.all()) != 0 {
			t.Fatal("something was relayed for a node the home server had not accepted")
		}
		away.st.EndVisit(n.num)
	})
	t.Run("a registration packet is accepted once; replay gives RP", func(t *testing.T) {
		const pid = 0x7777
		register(t, away, enrolled, tag, true, pid)
		eventually(t, "registered", func() bool { _, ok := away.st.ActiveVisit(enrolled.num); return ok })
		// end it, let the dedupe window pass, and replay the recorded broadcast from another gateway
		away.st.EndVisit(enrolled.num)
		home.st.EndRegistration(enrolled.num, away.actor())
		clk.Advance(11 * time.Minute)
		away.gw.clear()
		register(t, away, enrolled, tag, true, pid)
		eventually(t, "RP refusal", func() bool { return refusalFor(t, away, enrolled) == "RP" })
		if _, ok := away.st.ActiveVisit(enrolled.num); ok {
			t.Fatal("a replayed registration was accepted")
		}
	})
	t.Run("blocked home server gives BL", func(t *testing.T) {
		away.st.SetBlocked(home.actor(), true)
		defer away.st.SetBlocked(home.actor(), false)
		n := newSimNode()
		register(t, away, n, tag, true, 0)
		if c := refusalFor(t, away, n); c != "BL" {
			t.Fatalf("got %q", c)
		}
	})
	t.Run("closed community gives CL", func(t *testing.T) {
		closed := newSite(t, clk, "Closed", func(c *Config) { c.RoamingOpen = false })
		n := newSimNode()
		register(t, closed, n, tag, true, 0)
		if c := refusalFor(t, closed, n); c != "CL" {
			t.Fatalf("got %q", c)
		}
	})
	t.Run("no free slots gives NS", func(t *testing.T) {
		full := newSite(t, clk, "Full", func(c *Config) { c.RoamingSlots = 0 })
		n := newSimNode()
		register(t, full, n, tag, true, 0)
		if c := refusalFor(t, full, n); c != "NS" {
			t.Fatalf("got %q", c)
		}
	})
	t.Run("per-node rate limit gives RP", func(t *testing.T) {
		limited := newSite(t, clk, "Limited", func(c *Config) { c.RatePerNode = 2 })
		n := newSimNode()
		for i := 0; i < 3; i++ {
			register(t, limited, n, "deadbeef", true, 0)
		}
		if c := refusalFor(t, limited, n); c != "UH" && c != "RP" {
			t.Fatalf("got %q", c)
		}
		limited.gw.clear()
		register(t, limited, n, "deadbeef", true, 0)
		if c := refusalFor(t, limited, n); c != "RP" {
			t.Fatalf("fourth attempt got %q, want RP", c)
		}
	})
}

func TestHomeUnreachableGivesUHAfterRetriesGiveUp(t *testing.T) {
	clk := newClock()
	home := newSite(t, clk, "Home", nil)
	away := newSite(t, clk, "Away", nil)
	if _, err := away.eng.LinkUp(context.Background(), home.actor()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "link", func() bool { _, ok := home.st.Peer(away.actor()); return ok })
	tag := home.eng.HomeTag()
	home.hs.Close() // the home server goes away
	away.out.Schedule = []time.Duration{time.Second}
	n := newSimNode()
	home.st.Enrol(n.num, n.pub, "admin", false)
	register(t, away, n, tag, true, 0)
	away.wait()
	eventually(t, "UH after the delivery was abandoned", func() bool { return refusalFor(t, away, n) == "UH" })
	if _, ok := away.st.Visit(n.num); ok {
		t.Fatal("visit kept after the home server was unreachable")
	}
}

func TestTagClashNewerServerRenames(t *testing.T) {
	clk := newClock()
	older := newSite(t, clk, "Older", nil)
	clk.Advance(time.Hour)
	newer := newSite(t, clk, "Newer", nil)
	// force the same tag
	id := newer.st.Identity()
	id.HomeTag = older.eng.HomeTag()
	newer.st.SetIdentity(id)
	member := newSimNode()
	newer.st.Enrol(member.num, member.pub, "admin", false)

	if _, err := newer.eng.LinkUp(context.Background(), older.actor()); err != nil {
		t.Fatal(err)
	}
	newer.wait()
	older.wait()
	if newer.eng.HomeTag() == older.eng.HomeTag() {
		t.Fatal("the newer server kept the clashing tag")
	}
	if got := older.eng.HomeTag(); got != older.st.Identity().HomeTag || len(older.st.Identity().Renamed) != 0 {
		t.Fatal("the older server changed its tag")
	}
	if r := newer.st.Identity().Renamed; len(r) != 1 || r[0] != older.eng.HomeTag() {
		t.Fatalf("old tag not remembered as an alias: %v", r)
	}
	if !newer.eng.ownTag(older.eng.HomeTag()) {
		t.Fatal("the old tag should still be recognised as ours")
	}
	// members are told by DM the next time their node is heard at home
	if _, ok := newer.st.TakeRenameNotice(member.num); !ok {
		t.Fatal("no rename notice queued for the member")
	}
}

func TestRenameAcceptedOnlyFromHolderOfOldTag(t *testing.T) {
	clk := newClock()
	a := newSite(t, clk, "A", nil)
	b := newSite(t, clk, "B", nil)
	c := newSite(t, clk, "C", nil)
	a.st.UpsertPeer(state.Peer{Actor: b.actor(), HomeTag: "11111111", Inbox: b.srv.Self.InboxURL}, 500)
	mk := func(from *site, old, nw, server string) *ap.Activity {
		act, _ := ap.Build(from.hs.URL, from.actor(), ap.TypeRename, []string{a.actor()}, clk.Now(), ap.RenameObject{OldTag: old, NewTag: nw, Server: server}, nil)
		return act
	}
	pb, _ := a.st.Peer(b.actor())
	if err := a.eng.handleRename(*pb, mk(b, "11111111", "22222222", b.actor())); err != nil {
		t.Fatal(err)
	}
	if len(a.st.PeersByTag("22222222")) != 1 {
		t.Fatal("rename not applied")
	}
	if err := a.eng.handleRename(*pb, mk(b, "99999999", "33333333", b.actor())); err == nil {
		t.Fatal("rename of a tag the server does not hold accepted")
	}
	if err := a.eng.handleRename(*pb, mk(b, "22222222", "44444444", c.actor())); err == nil {
		t.Fatal("rename naming another server accepted")
	}
}

func TestIntroduceSpreadsServersAfterConfirmingThemAndIgnoresLiars(t *testing.T) {
	clk := newClock()
	a := newSite(t, clk, "A", nil)
	b := newSite(t, clk, "B", nil)
	c := newSite(t, clk, "C", nil)
	// A knows C; B links to A and so hears about C
	a.srv.Learn(context.Background(), c.actor(), true)
	if _, err := b.eng.LinkUp(context.Background(), a.actor()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "B hears about C through A's Introduce", func() bool { _, ok := b.st.Peer(c.actor()); return ok })
	// and C, introduced to by B on first contact, learns B
	eventually(t, "C learns B at first contact", func() bool { _, ok := c.st.Peer(b.actor()); return ok })

	// a server that does not answer is not added
	ghost := "https://ghost.invalid/actor"
	act, _ := ap.Build(a.hs.URL, a.actor(), ap.TypeIntroduce, []string{b.actor()}, clk.Now(),
		ap.IntroduceObject{Servers: []ap.IntroducedServer{{Actor: ghost, HomeTag: "12345678", LastHeard: clk.Now().Format(time.RFC3339)}}}, nil)
	pa, _ := b.st.Peer(a.actor())
	b.eng.handleIntroduce(*pa, act)
	time.Sleep(300 * time.Millisecond)
	if _, ok := b.st.Peer(ghost); ok {
		t.Fatal("a server that never answered was added")
	}
}

func TestBeaconAndAnnouncement(t *testing.T) {
	clk := newClock()
	s := newSite(t, clk, "Beacon Town", func(c *Config) {
		c.Beacon = BeaconConfig{Enabled: true, Interval: time.Hour, MinGap: 10 * time.Minute, OnNewNode: true}
		c.RoamingSlots = 12
		c.DefaultDays = 3
	})
	line := s.eng.BeaconLine()
	m, err := mfb.Parse(line)
	b, ok := m.(*mfb.Beacon)
	if err != nil || !ok || b.HomeTag != s.eng.HomeTag() || b.Node != s.serverNum() || !b.Open || b.Slots != 12 || b.Days != 3 {
		t.Fatalf("%q %v %+v", line, err, m)
	}
	s.eng.SendBeacon()
	var beacons int
	for _, h := range decodeChannel(t, s.gw.all(), "InterRoam", s.roamKey()) {
		if h.Text == line && h.Signed && h.From == s.serverNum() && h.To == meshwire.BroadcastNum {
			beacons++
		}
	}
	if beacons != 1 {
		t.Fatalf("expected one signed broadcast beacon, found %d", beacons)
	}

	// the new-node trigger respects the minimum gap
	s.gw.clear()
	s.eng.mu.Lock()
	s.eng.lastBeacon = clk.Now()
	s.eng.mu.Unlock()
	n := newSimNode()
	s.uplink("Home", n.nodeInfoUplink(t, "Home", s.home.Key, s.gwID))
	if len(decodeChannel(t, s.gw.all(), "InterRoam", s.roamKey())) != 0 {
		t.Fatal("beacon sent inside the minimum gap")
	}
	clk.Advance(11 * time.Minute)
	n2 := newSimNode()
	s.uplink("Home", n2.nodeInfoUplink(t, "Home", s.home.Key, s.gwID))
	if len(decodeChannel(t, s.gw.all(), "InterRoam", s.roamKey())) == 0 {
		t.Fatal("no beacon for a new node after the gap")
	}

	// announcement: a signed NodeInfo whose node number is the CRC-32 of the key it carries
	s.gw.clear()
	s.eng.Announce()
	var announced bool
	for _, h := range decodeChannel(t, s.gw.all(), "Home", s.home.Key) {
		if h.Port == meshwire.PortNodeInfo && h.Signed && h.From == s.serverNum() {
			announced = true
		}
	}
	if !announced {
		t.Fatal("no signed NodeInfo announcement")
	}
}

func TestBeaconsAreOffByDefault(t *testing.T) {
	if DefaultConfig().Beacon.Enabled {
		t.Fatal("beacons must be off by default")
	}
	clk := newClock()
	s := newSite(t, clk, "Quiet", nil)
	n := newSimNode()
	s.uplink("Home", n.nodeInfoUplink(t, "Home", s.home.Key, s.gwID))
	var ticked time.Time
	s.eng.Tick(&ticked)
	if len(s.gw.all()) != 0 {
		t.Fatal("a beacon was sent with beacons off")
	}
}

func TestPermissionMismatchDropsAndWarnsWithoutMessagingTheGateway(t *testing.T) {
	clk := newClock()
	s := newSite(t, clk, "Home", nil)
	// a channel the server knows but with uplink off
	s.st.SetChannel(state.Channel{Name: "Quiet", Number: 2, Key: make([]byte, 16), Uplink: false, Downlink: true, Scope: ScopeMesh})
	s.st.SetGateway(state.Gateway{Username: "gw", Channels: []string{"Home", "InterRoam", "Quiet"}, NodeID: s.gwID, Created: clk.Now()})
	n := newSimNode()
	s.uplink("Quiet", n.channelUplink(t, "Quiet", make([]byte, 16), s.gwID, meshwire.PortText, []byte("hi"), meshwire.BroadcastNum, true, 0))
	if len(s.gw.all()) != 0 {
		t.Fatal("the gateway was messaged")
	}
	var warned bool
	for _, ev := range s.eng.Events() {
		if ev.Kind == "warning" && strings.Contains(ev.Message, "gw") && strings.Contains(ev.Message, "Quiet") {
			warned = true
		}
	}
	if !warned {
		t.Fatal("no console warning naming the gateway and channel")
	}
}

func TestUnencryptedGatewayTrafficIsDroppedWithAWarning(t *testing.T) {
	clk := newClock()
	s := newSite(t, clk, "Home", nil)
	n := newSimNode()
	env := &meshwire.ServiceEnvelope{
		Packet:    &meshwire.MeshPacket{From: n.num, To: meshwire.BroadcastNum, ID: 5, Decoded: &meshwire.Data{Portnum: meshwire.PortText, Payload: []byte("MFB1 R 4be10c77 3")}},
		ChannelID: "InterRoam", GatewayID: s.gwID,
	}
	s.uplink("InterRoam", env.Marshal())
	if len(s.gw.all()) != 0 {
		t.Fatal("acted on unencrypted traffic")
	}
	var warned bool
	for _, ev := range s.eng.Events() {
		if strings.Contains(ev.Message, "encryption must be enabled") {
			warned = true
		}
	}
	if !warned {
		t.Fatal("no warning about MQTT encryption")
	}
}

func TestCommunityScopeRelaysBetweenGatewaysButMeshScopeDoesNot(t *testing.T) {
	clk := newClock()
	s := newSite(t, clk, "Home", nil)
	s.st.SetGateway(state.Gateway{Username: "gw2", Channels: []string{"Home", "Mesh", "InterRoam"}, NodeID: "!aabbcc02", Created: clk.Now()})
	s.st.SetGateway(state.Gateway{Username: "gw", Channels: []string{"Home", "Mesh", "InterRoam"}, NodeID: s.gwID, Created: clk.Now()})
	meshKey := make([]byte, 16)
	meshKey[0] = 9
	s.st.SetChannel(state.Channel{Name: "Mesh", Number: 3, Key: meshKey, Scope: ScopeMesh, Uplink: true, Downlink: true})
	n := newSimNode()

	s.uplink("Home", n.channelUplink(t, "Home", s.home.Key, s.gwID, meshwire.PortText, []byte("to the other site"), meshwire.BroadcastNum, true, 0))
	var toGW2, toGW1 int
	for _, p := range s.gw.all() {
		switch p.Target {
		case "!aabbcc02":
			toGW2++
		case s.gwID:
			toGW1++
		}
	}
	if toGW2 != 1 || toGW1 != 0 {
		t.Fatalf("community relay: to other gateway %d, back to source %d", toGW2, toGW1)
	}
	s.gw.clear()
	s.uplink("Mesh", n.channelUplink(t, "Mesh", meshKey, s.gwID, meshwire.PortText, []byte("stay local"), meshwire.BroadcastNum, true, 0))
	if len(s.gw.all()) != 0 {
		t.Fatal("a mesh-only channel was relayed")
	}
}
