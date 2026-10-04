package core

import (
	"time"

	"github.com/Poag/Intermesh/server/internal/meshwire"
	"github.com/Poag/Intermesh/server/internal/mfb"
	"github.com/Poag/Intermesh/server/internal/state"
)

// BeaconLine returns the current beacon text: "MFB1 B <tag> <node> <state> <slots> <days>".
func (e *Engine) BeaconLine() string {
	free := e.cfg.RoamingSlots - e.st.SlotsInUse()
	if free < 0 {
		free = 0
	}
	return (&mfb.Beacon{HomeTag: e.HomeTag(), Node: e.serverNum, Open: e.cfg.RoamingOpen, Slots: free, Days: e.cfg.DefaultDays}).String()
}

// maybeBeacon sends a beacon unless one was sent within the admin's minimum gap. The gap caps
// the new-node trigger (suggested 3 Oct 2026); there is no fixed floor in the spec.
func (e *Engine) maybeBeacon(trigger bool) {
	e.mu.Lock()
	if !e.lastBeacon.IsZero() && e.now().Sub(e.lastBeacon) < e.cfg.Beacon.MinGap {
		e.mu.Unlock()
		return
	}
	e.lastBeacon = e.now()
	e.mu.Unlock()
	e.SendBeacon()
}

// SendBeacon downlinks a beacon, signed with the server's key, on the roaming channel through
// every connected gateway granted it.
func (e *Engine) SendBeacon() {
	rc := e.roamChannel()
	e.sendChannel(rc, meshwire.BroadcastNum, meshwire.PortText, []byte(e.BeaconLine()), true, e.gatewaysFor(rc.Name, "", ""))
}

// Announce downlinks a signed NodeInfo for the server's own identity on every channel that has
// downlink on. Gateways only transmit a PKI direct message when their node database already
// holds both nodes, and nodes only trust a signed packet from a sender whose key they hold; a
// NodeInfo whose node number is the CRC-32 of its key is how the firmware bootstraps both.
func (e *Engine) Announce() {
	user := &meshwire.User{ID: e.serverID, LongName: truncateUTF8(e.cfg.Name, 40), ShortName: shortName(e.HomeTag()), PublicKey: e.meshPub}
	for _, ch := range e.st.Channels() {
		ch := ch
		if !ch.Downlink {
			continue
		}
		e.sendChannel(&ch, meshwire.BroadcastNum, meshwire.PortNodeInfo, user.Marshal(), true, e.gatewaysFor(ch.Name, "", ""))
	}
	e.mu.Lock()
	e.lastAnnounce = e.now()
	e.mu.Unlock()
}

func shortName(tag string) string {
	if len(tag) >= 4 {
		return tag[:4]
	}
	return tag
}

var _ = state.Channel{}
var _ = time.Second
