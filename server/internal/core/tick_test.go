package core

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/Poag/Intermesh/server/internal/ap"
	"github.com/Poag/Intermesh/server/internal/meshwire"
	"github.com/Poag/Intermesh/server/internal/mfb"
	"github.com/Poag/Intermesh/server/internal/state"
)

// registered sets up a home and a visited server with one roamer registered for days.
func registered(t *testing.T, clk *fakeClock, days int, awayMod func(*Config)) (home, away *site, roamer *simNode, pktID uint32) {
	t.Helper()
	home = newSite(t, clk, "Home", nil)
	away = newSite(t, clk, "Away", awayMod)
	if _, err := away.eng.LinkUp(context.Background(), home.actor()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "link", func() bool { _, ok := home.st.Peer(away.actor()); return ok })
	roamer = newSimNode()
	home.st.Enrol(roamer.num, roamer.pub, "admin", false)
	pktID = 0x5150
	line := (&mfb.Roam{HomeTag: home.eng.HomeTag(), Days: days}).String()
	away.uplink("InterRoam", roamer.channelUplink(t, "InterRoam", away.roamKey(), away.gwID, meshwire.PortText, []byte(line), meshwire.BroadcastNum, true, pktID))
	eventually(t, "registered", func() bool { _, ok := away.st.ActiveVisit(roamer.num); return ok })
	return
}

func TestExpiredRegistrationIsUndoneOnBothServers(t *testing.T) {
	clk := newClock()
	home, away, roamer, _ := registered(t, clk, 1, nil)
	if _, ok := home.st.Registration(roamer.num, away.actor()); !ok {
		t.Fatal("home has no registration")
	}
	clk.Advance(25 * time.Hour)
	var tick time.Time
	away.eng.Tick(&tick) // the visited server notices the expiry and tells the home server
	eventually(t, "the visited server forgets the roamer", func() bool { _, ok := away.st.Visit(roamer.num); return !ok })
	eventually(t, "the home server is told", func() bool { _, ok := home.st.Registration(roamer.num, away.actor()); return !ok })
	if away.st.SlotsInUse() != 0 {
		t.Fatal("slot not freed")
	}
}

func TestPendingRegistrationTimesOutWithUH(t *testing.T) {
	clk := newClock()
	home := newSite(t, clk, "Home", nil)
	away := newSite(t, clk, "Away", func(c *Config) { c.PendingTimeout = time.Minute })
	if _, err := away.eng.LinkUp(context.Background(), home.actor()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "link", func() bool { _, ok := home.st.Peer(away.actor()); return ok })
	// the home server accepts the delivery but never answers: its handler swallows the Roam
	swallow := func(ctx context.Context, from state.Peer, act *ap.Activity) error { return nil }
	home.override.Store(&swallow)
	n := newSimNode()
	register(t, away, n, home.eng.HomeTag(), true, 0)
	away.wait()
	if v, ok := away.st.Visit(n.num); !ok || v.Accepted {
		t.Fatalf("expected a pending visit: %+v", v)
	}
	if away.st.SlotsInUse() != 0 {
		t.Fatal("a pending visit took a slot")
	}
	clk.Advance(2 * time.Minute)
	var tick time.Time
	away.eng.Tick(&tick)
	if refusalFor(t, away, n) != "UH" {
		t.Fatalf("got %q, want UH after the home server never answered", refusalFor(t, away, n))
	}
	if _, ok := away.st.Visit(n.num); ok {
		t.Fatal("pending visit kept after the timeout")
	}
}

func TestMultiPartMessageUpwardsAndALostPartIsDropped(t *testing.T) {
	clk := newClock()
	home, away, roamer, pktID := registered(t, clk, 3, nil)
	ch := home.home
	key, _ := mfb.DeriveKey(ch.Key, home.eng.HomeTag(), roamer.num, pktID, ch.Name, mfb.ToHome)
	text := strings.Repeat("abcdefghij", 15) // 150 bytes: needs two parts
	parts, next, err := mfb.SealText(key, roamer.num, ch.Number, 0, text, mfb.BroadcastLineBudget, 3)
	if err != nil || len(parts) != 2 {
		t.Fatalf("%v parts %d", err, len(parts))
	}
	for _, p := range parts {
		away.uplink("InterRoam", roamer.channelUplink(t, "InterRoam", away.roamKey(), away.gwID, meshwire.PortText, []byte(p.String()), meshwire.BroadcastNum, true, 0))
	}
	want := nodeHex(roamer.num) + ": " + text
	eventually(t, "the whole message reaches the home channel", func() bool {
		for _, h := range decodeChannel(t, home.gw.all(), "Home", ch.Key) {
			if h.Text == want {
				return true
			}
		}
		return false
	})

	// a second message loses its second part; nothing is delivered and the partial is dropped
	home.gw.clear()
	parts2, _, _ := mfb.SealText(key, roamer.num, ch.Number, next, strings.Repeat("z", 150), mfb.BroadcastLineBudget, 3)
	away.uplink("InterRoam", roamer.channelUplink(t, "InterRoam", away.roamKey(), away.gwID, meshwire.PortText, []byte(parts2[0].String()), meshwire.BroadcastNum, true, 0))
	away.wait()
	time.Sleep(100 * time.Millisecond)
	if len(home.gw.all()) != 0 {
		t.Fatal("a partial message was delivered")
	}
	clk.Advance(3 * time.Minute)
	var tick time.Time
	home.eng.Tick(&tick)
	// the late part arrives after the wait: it cannot complete the message any more
	away.uplink("InterRoam", roamer.channelUplink(t, "InterRoam", away.roamKey(), away.gwID, meshwire.PortText, []byte(parts2[1].String()), meshwire.BroadcastNum, true, 0))
	away.wait()
	time.Sleep(100 * time.Millisecond)
	if len(home.gw.all()) != 0 {
		t.Fatal("a message was delivered after its first part expired")
	}
}

func TestTooLongHomeMessageIsTruncatedToTheMaximumParts(t *testing.T) {
	clk := newClock()
	home, away, roamer, pktID := registered(t, clk, 3, nil)
	ch := home.home
	member := newSimNode()
	long := strings.Repeat("0123456789", 30) // 300 bytes, more than three parts hold
	home.uplink("Home", member.channelUplink(t, "Home", ch.Key, home.gwID, meshwire.PortText, []byte(long), meshwire.BroadcastNum, true, 0))
	toRoamer, _ := mfb.DeriveKey(ch.Key, home.eng.HomeTag(), roamer.num, pktID, ch.Name, mfb.ToRoamer)
	ra := mfb.NewReassembler(3)
	var got string
	eventually(t, "the truncated message arrives", func() bool {
		for _, h := range decodeChannel(t, away.gw.all(), "InterRoam", away.roamKey()) {
			if m, err := mfb.Parse(h.Text); err == nil {
				if s, ok := m.(*mfb.Sealed); ok && s.Node == roamer.num {
					if text, done, err := ra.Add(time.Now(), 1, toRoamer, s); err == nil && done {
						got = text
						return true
					}
				}
			}
		}
		return false
	})
	max := mfb.MaxPartText(mfb.BroadcastLineBudget) * 3
	if len(got) == 0 || len(got) > max || !strings.HasPrefix(got, nodeHex(member.num)+": 0123") {
		t.Fatalf("got %d bytes (limit %d): %.40q", len(got), max, got)
	}
}

func TestRawPacketRelayDownIsDownlinkedThroughTheRegistrationGateway(t *testing.T) {
	clk := newClock()
	home, away, roamer, _ := registered(t, clk, 3, nil)
	// a pre-encrypted direct message for the roamer, as the fallback for stock apps
	pk := &meshwire.MeshPacket{From: home.serverNum(), To: roamer.num, ID: 4242, Encrypted: []byte("opaque-pki-bytes-for-the-roamer"), PKIEncrypted: true}
	act, _ := ap.Build(home.hs.URL, home.actor(), ap.TypeRelay, []string{away.actor()}, clk.Now(), ap.RelayObject{
		Node: nodeHex(roamer.num), Direction: ap.DirDown, Kind: ap.KindPacket, Packet: base64.StdEncoding.EncodeToString(pk.Marshal())}, nil)
	away.gw.clear()
	if err := home.srv.Client.Send(context.Background(), away.srv.Self.InboxURL, act); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the packet is downlinked on the PKI topic to the gateway the roamer registered through", func() bool {
		for _, p := range away.gw.all() {
			if p.Channel == meshwire.PKIChannelID && p.Target == away.gwID {
				env, err := meshwire.UnmarshalServiceEnvelope(p.Payload)
				return err == nil && env.Packet.To == roamer.num && env.Packet.HopLimit > 0 && string(env.Packet.Encrypted) == "opaque-pki-bytes-for-the-roamer"
			}
		}
		return false
	})
	// a Relay from a server that is not the roamer's home server is ignored
	other := newSite(t, clk, "Other", nil)
	act2, _ := ap.Build(other.hs.URL, other.actor(), ap.TypeRelay, []string{away.actor()}, clk.Now(), ap.RelayObject{
		Node: nodeHex(roamer.num), Direction: ap.DirDown, Kind: ap.KindPacket, Packet: base64.StdEncoding.EncodeToString(pk.Marshal())}, nil)
	away.gw.clear()
	other.srv.Client.Send(context.Background(), away.srv.Self.InboxURL, act2)
	time.Sleep(200 * time.Millisecond)
	if len(away.gw.all()) != 0 {
		t.Fatal("a server that is not the roamer's home downlinked to it")
	}
}

func TestRelayUpFromAServerWithNoRegistrationIsIgnored(t *testing.T) {
	clk := newClock()
	home, away, roamer, pktID := registered(t, clk, 3, nil)
	ch := home.home
	key, _ := mfb.DeriveKey(ch.Key, home.eng.HomeTag(), roamer.num, pktID, ch.Name, mfb.ToHome)
	parts, _, _ := mfb.SealText(key, roamer.num, ch.Number, 0, "sneaky", mfb.BroadcastLineBudget, 3)
	p := parts[0]
	// another server relays the (somehow obtained) sealed part: the home server has no registration with it
	other := newSite(t, clk, "Other", nil)
	act, _ := ap.Build(other.hs.URL, other.actor(), ap.TypeRelay, []string{home.actor()}, clk.Now(), ap.RelayObject{
		Node: nodeHex(roamer.num), Direction: ap.DirUp, Kind: ap.KindSealed, Ch: "01", Ctr: p.Ctr, Part: "1/1",
		Data: base64.RawURLEncoding.EncodeToString(p.Data)}, nil)
	home.gw.clear()
	other.srv.Client.Send(context.Background(), home.srv.Self.InboxURL, act)
	time.Sleep(200 * time.Millisecond)
	if len(home.gw.all()) != 0 {
		t.Fatal("a sealed part from an unregistered server was delivered")
	}
	_ = away
}

func TestKeyRotationThroughTheEngineKeepsFederationWorking(t *testing.T) {
	clk := newClock()
	home := newSite(t, clk, "Home", nil)
	away := newSite(t, clk, "Away", nil)
	if _, err := away.eng.LinkUp(context.Background(), home.actor()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "link", func() bool { _, ok := home.st.Peer(away.actor()); return ok })
	if err := away.eng.RotateAPKey(away.srv.Client, time.Hour); err != nil {
		t.Fatal(err)
	}
	clk.Advance(11 * time.Second) // past the lookup cooldown
	roamer := newSimNode()
	home.st.Enrol(roamer.num, roamer.pub, "admin", false)
	register(t, away, roamer, home.eng.HomeTag(), true, 0x99)
	eventually(t, "a delivery signed with the new key is accepted", func() bool { _, ok := away.st.ActiveVisit(roamer.num); return ok })
	p, _ := home.st.Peer(away.actor())
	if !strings.HasSuffix(p.KeyID, "#key-2") || p.OldKeyID == "" {
		t.Fatalf("home did not pick up the rotation: %+v", p)
	}
}

func TestUnlinkForgetsAHandMadeLink(t *testing.T) {
	clk := newClock()
	a := newSite(t, clk, "A", nil)
	b := newSite(t, clk, "B", nil)
	if _, err := a.eng.LinkUp(context.Background(), b.actor()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "b learns a", func() bool { _, ok := b.st.Peer(a.actor()); return ok })
	a.eng.Unlink(b.actor())
	a.wait()
	if _, ok := a.st.Peer(b.actor()); ok {
		t.Fatal("a hand-made link was not forgotten")
	}
}
