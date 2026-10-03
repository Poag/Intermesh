package core

import (
	"context"
	"time"

	"github.com/Poag/Intermesh/server/internal/ap"
	"github.com/Poag/Intermesh/server/internal/mfb"
	"github.com/Poag/Intermesh/server/internal/state"
)

// Run performs the periodic work until ctx is cancelled: expiring registrations, pruning
// replay memory, dropping partial sealed messages, announcing the server's NodeInfo, sending
// beacons and the daily Introduce.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	var lastIntroduce time.Time
	e.Tick(&lastIntroduce)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.Tick(&lastIntroduce)
		}
	}
}

// Tick runs one round of the periodic work.
func (e *Engine) Tick(lastIntroduce *time.Time) {
	now := e.now()

	// Visited side: tell the home server when an accepted registration expires, and refuse
	// registrations the home server never answered.
	for _, v := range e.st.Visits() {
		if !v.Accepted && now.Sub(v.Started) >= e.cfg.PendingTimeout {
			e.roamUndeliverable(v.Node, e.pendingID(v.Node))
			e.st.EndVisit(v.Node)
		}
	}
	for _, v := range e.st.ExpireVisits(e.cfg.PendingTimeout) {
		if peer, ok := e.st.Peer(v.HomeActor); ok {
			e.sendUndo(*peer, v.Node)
		}
	}
	e.st.ExpireRegistrations()
	e.st.Prune(state.MaxRegistrationDays*24*time.Hour+e.cfg.ReplayMargin, ap.DefaultMaxAge*2)
	for _, l := range e.up.Expire(now, e.cfg.PartWait) {
		e.log.Info("sealed message dropped: a part never arrived", "node", nodeHex(l.Node), "have", l.Have, "total", l.Total)
	}

	e.mu.Lock()
	needAnnounce := e.cfg.AnnounceInterval > 0 && now.Sub(e.lastAnnounce) >= e.cfg.AnnounceInterval
	needBeacon := e.cfg.Beacon.Enabled && e.cfg.Beacon.Interval > 0 && now.Sub(e.lastBeacon) >= e.cfg.Beacon.Interval
	e.mu.Unlock()
	if needAnnounce {
		e.Announce()
	}
	if needBeacon {
		e.maybeBeacon(false)
	}
	if lastIntroduce != nil && now.Sub(*lastIntroduce) >= 24*time.Hour {
		*lastIntroduce = now
		e.IntroduceAll()
	}
}

func (e *Engine) pendingID(node uint32) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.pending[node]
}

var _ = mfb.Tag
