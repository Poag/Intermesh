package core

import (
	"strings"
	"testing"

	"github.com/Poag/Intermesh/server/internal/meshwire"
	"github.com/Poag/Intermesh/server/internal/mfb"
	"github.com/Poag/Intermesh/server/internal/simmesh"
)

func asSim(n *simNode) *simmesh.Node { return &simmesh.Node{Priv: n.priv, Pub: n.pub, Num: n.num} }

func envelopes(t *testing.T, pubs []pub) []*meshwire.ServiceEnvelope {
	t.Helper()
	var out []*meshwire.ServiceEnvelope
	for _, p := range pubs {
		env, err := meshwire.UnmarshalServiceEnvelope(p.Payload)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, env)
	}
	return out
}

// everything the visited server sends to roamers must be accepted by the firmware's rules, under
// the default policy and under the balanced policy once the server is known as a signer.
func TestRoamerFirmwareAcceptsEverythingTheVisitedServerSends(t *testing.T) {
	for _, policy := range []string{simmesh.PolicyCompatible, simmesh.PolicyBalanced, simmesh.PolicyStrict} {
		policy := policy
		t.Run(policy, func(t *testing.T) {
			clk := newClock()
			home, away, roamer, pktID := registered(t, clk, 3, nil)
			_ = pktID
			r := simmesh.NewReceiver(asSim(roamer), map[string][]byte{"InterRoam": away.roamKey()})
			r.Policy = policy
			// the roamer's node holds the visited server's key as it would after hearing the
			// server's signed NodeInfo announcement (bootstraps trust) ...
			away.gw.clear()
			away.eng.Announce()
			for _, env := range envelopes(t, away.gw.all()) {
				if env.ChannelID == "InterRoam" {
					if _, err := r.Hears(env); err != nil {
						t.Fatalf("the server's announcement was dropped: %v", err)
					}
				}
			}
			if _, ok := r.Known[away.serverNum()]; !ok || !r.Signers[away.serverNum()] {
				t.Fatal("the announcement did not teach the node the server's key")
			}
			// ... and now everything the server broadcasts must be heard
			away.gw.clear()
			away.eng.SendBeacon()
			// a refusal (to another node) and a registration confirmation for this roamer
			other := newSimNode()
			register(t, away, other, "deadbeef", true, 0) // UH, broadcast on the roaming channel
			member := newSimNode()
			for _, n := range []int{5, 60, 150, 300} { // sealed downlink parts of several sizes, up to the maximum
				home.uplink("Home", member.channelUplink(t, "Home", home.home.Key, home.gwID, meshwire.PortText, []byte(strings.Repeat("x", n)), meshwire.BroadcastNum, true, 0))
			}
			eventually(t, "sealed downlink reaches the visited server's gateway", func() bool {
				var n int
				for _, env := range envelopes(t, away.gw.all()) {
					if env.ChannelID == "InterRoam" {
						n++
					}
				}
				return n >= 6
			})
			var heardBeacon, heardRefusal, heardSealed bool
			for _, env := range envelopes(t, away.gw.all()) {
				if env.ChannelID != "InterRoam" {
					continue
				}
				d, err := r.Hears(env)
				if err != nil {
					t.Fatalf("the firmware would drop a packet the server sent: %v (to %08x, %d bytes)", err, env.Packet.To, len(env.Packet.Encrypted))
				}
				switch m, _ := mfb.Parse(string(d.Payload)); m.(type) {
				case *mfb.Beacon:
					heardBeacon = true
				case *mfb.Refusal:
					heardRefusal = true
				case *mfb.Sealed:
					heardSealed = true
				}
			}
			if !heardBeacon || !heardRefusal || !heardSealed {
				t.Fatalf("beacon %v refusal %v sealed %v", heardBeacon, heardRefusal, heardSealed)
			}
		})
	}
}

func TestAChannelTextAddressedToANodeIsDroppedByTheFirmware(t *testing.T) {
	clk := newClock()
	s := newSite(t, clk, "Away", nil)
	n := newSimNode()
	s.gw.clear()
	// what the first version of the server did: a text addressed to the roamer
	s.eng.sendChannel(s.eng.roamChannel(), n.num, meshwire.PortText, []byte("MFB1 K"), true, s.eng.gatewaysFor("InterRoam", "", ""))
	envs := envelopes(t, s.gw.all())
	if len(envs) != 1 {
		t.Fatal("expected one packet")
	}
	r := simmesh.NewReceiver(asSim(n), map[string][]byte{"InterRoam": s.roamKey()})
	if _, err := r.Hears(envs[0]); err == nil || !strings.Contains(err.Error(), "legacy DM") {
		t.Fatalf("a text addressed to a non-licensed node must be dropped, got %v", err)
	}
	r.Licensed = true
	if _, err := r.Hears(envs[0]); err != nil {
		t.Fatalf("licensed nodes are exempt: %v", err)
	}
}

func TestNothingIsHeardWhenIgnoreMQTTIsOn(t *testing.T) {
	clk := newClock()
	_, away, roamer, _ := registered(t, clk, 3, nil)
	away.eng.SendBeacon()
	r := simmesh.NewReceiver(asSim(roamer), map[string][]byte{"InterRoam": away.roamKey()})
	r.IgnoreMQTT = true // the firmware's default in duty-cycle limited regions such as EU_868
	var n int
	for _, env := range envelopes(t, away.gw.all()) {
		if env.ChannelID == "InterRoam" {
			n++
			if _, err := r.Hears(env); err == nil {
				t.Fatal("a node with Ignore MQTT on heard a downlinked packet")
			}
		}
	}
	if n == 0 {
		t.Fatal("nothing was downlinked")
	}
}

func TestMemberFirmwareHearsEnrolmentRepliesAndHomeTraffic(t *testing.T) {
	clk := newClock()
	s := newSite(t, clk, "Home", func(c *Config) { c.Enrolment = EnrolPublic })
	m := newSimNode()
	r := simmesh.NewReceiver(asSim(m), map[string][]byte{"Home": s.home.Key})
	r.Policy = simmesh.PolicyBalanced
	// the member imported the server contact (node id and key)
	r.Known[s.serverNum()] = s.serverPub()
	s.uplink("Home", m.nodeInfoUplink(t, "Home", s.home.Key, s.gwID))
	s.gw.clear()
	s.uplink("PKI", m.dmUplink(t, s.serverNum(), s.serverPub(), "MFB1 E -", s.gwID))
	var gotK bool
	for _, env := range envelopes(t, s.gw.all()) {
		d, err := r.Hears(env)
		if err != nil {
			t.Fatalf("the firmware would drop the enrolment reply: %v", err)
		}
		gotK = gotK || string(d.Payload) == "MFB1 K"
	}
	if !gotK {
		t.Fatal("no enrolment reply")
	}
	// without the server's key the reply cannot be read
	r2 := simmesh.NewReceiver(asSim(m), map[string][]byte{"Home": s.home.Key})
	s.gw.clear()
	s.uplink("PKI", m.dmUplink(t, s.serverNum(), s.serverPub(), "MFB1 E -", s.gwID)) // enrolling again, new packet id: the server replies again
	envs := envelopes(t, s.gw.all())
	if len(envs) != 1 {
		t.Fatalf("expected one reply, got %d", len(envs))
	}
	if _, err := r2.Hears(envs[0]); err == nil || !strings.Contains(err.Error(), "does not hold the sender's public key") {
		t.Fatalf("a node without the server's key must not be able to read the reply: %v", err)
	}
}

func TestHomeChannelBroadcastsFromTheServerAreHeardUnderBalanced(t *testing.T) {
	clk := newClock()
	home, away, roamer, pktID := registered(t, clk, 3, nil)
	member := newSimNode()
	r := simmesh.NewReceiver(asSim(member), map[string][]byte{"Home": home.home.Key})
	r.Policy = simmesh.PolicyBalanced
	home.gw.clear()
	home.eng.Announce()
	for _, env := range envelopes(t, home.gw.all()) {
		if env.ChannelID == "Home" {
			if _, err := r.Hears(env); err != nil {
				t.Fatalf("announcement dropped: %v", err)
			}
		}
	}
	// a roamer's sealed message appears on the home channel as text from the server
	ch := home.home
	key, _ := mfb.DeriveKey(ch.Key, home.eng.HomeTag(), roamer.num, pktID, ch.Name, mfb.ToHome)
	for _, text := range []string{"hi", strings.Repeat("y", 70)} {
		parts, _, _ := mfb.SealText(key, roamer.num, ch.Number, uint64(len(text)), text, mfb.BroadcastLineBudget, 3)
		home.gw.clear()
		for _, p := range parts {
			away.uplink("InterRoam", roamer.channelUplink(t, "InterRoam", away.roamKey(), away.gwID, meshwire.PortText, []byte(p.String()), meshwire.BroadcastNum, true, 0))
		}
		eventually(t, "delivered to the home channel", func() bool {
			for _, env := range envelopes(t, home.gw.all()) {
				if env.ChannelID == "Home" {
					return true
				}
			}
			return false
		})
		for _, env := range envelopes(t, home.gw.all()) {
			if env.ChannelID != "Home" {
				continue
			}
			d, err := r.Hears(env)
			if err != nil {
				t.Fatalf("the firmware would drop the delivery of a roamer's message: %v", err)
			}
			if !strings.Contains(string(d.Payload), text) {
				t.Fatalf("%q", d.Payload)
			}
		}
	}
}
