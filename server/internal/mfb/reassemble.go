package mfb

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrReplay       = errors.New("mfb: counter already seen or too old")
	ErrTooManyParts = errors.New("mfb: more parts than the limit")
)

// ReplayWindow accepts each counter once. It tolerates reordering of up to 64
// counters, which is as far back as it remembers.
type ReplayWindow struct {
	highest uint64
	bits    uint64 // bit i set means highest-i has been seen
	started bool
}

// Check reports whether ctr would be accepted, without recording it.
func (w *ReplayWindow) Check(ctr uint64) bool {
	if !w.started || ctr > w.highest {
		return true
	}
	d := w.highest - ctr
	return d < 64 && w.bits&(1<<d) == 0
}

// Commit records ctr as seen. Call it only after the part authenticated, so a
// forged counter cannot advance the window.
func (w *ReplayWindow) Commit(ctr uint64) {
	if !w.started {
		w.started, w.highest, w.bits = true, ctr, 1
		return
	}
	if ctr > w.highest {
		shift := ctr - w.highest
		if shift >= 64 {
			w.bits = 0
		} else {
			w.bits <<= shift
		}
		w.highest = ctr
		w.bits |= 1
		return
	}
	if d := w.highest - ctr; d < 64 {
		w.bits |= 1 << d
	}
}

// Lost describes a partial message that was dropped after the wait elapsed.
type Lost struct {
	Node  uint32
	Ch    byte
	Have  int
	Total int
}

type partialKey struct {
	node  uint32
	ch    byte
	first uint64
	total int
}

type partial struct {
	parts [][]byte
	have  int
	since time.Time
}

// Reassembler joins the numbered parts of sealed messages travelling in one
// direction. Parts of one message have consecutive counters, so a part's group is
// identified by its counter minus its part index.
type Reassembler struct {
	mu       sync.Mutex
	maxParts int
	partials map[partialKey]*partial
	replay   map[uint32]*ReplayWindow
}

// NewReassembler creates a reassembler that refuses messages of more than maxParts parts.
func NewReassembler(maxParts int) *Reassembler {
	return &Reassembler{maxParts: maxParts, partials: map[partialKey]*partial{}, replay: map[uint32]*ReplayWindow{}}
}

// Add authenticates a part with key and returns the whole text once every part has arrived.
func (r *Reassembler) Add(now time.Time, key []byte, s *Sealed) (string, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.Total > r.maxParts {
		return "", false, ErrTooManyParts
	}
	w := r.replay[s.Node]
	if w == nil {
		w = &ReplayWindow{}
		r.replay[s.Node] = w
	}
	if !w.Check(s.Ctr) {
		return "", false, ErrReplay
	}
	plain, err := OpenPart(key, s)
	if err != nil {
		return "", false, err
	}
	w.Commit(s.Ctr)
	if s.Total == 1 {
		return string(plain), true, nil
	}
	pk := partialKey{s.Node, s.Ch, s.Ctr - uint64(s.Part-1), s.Total}
	p := r.partials[pk]
	if p == nil {
		p = &partial{parts: make([][]byte, s.Total), since: now}
		r.partials[pk] = p
	}
	if p.parts[s.Part-1] == nil {
		p.parts[s.Part-1] = plain
		p.have++
	}
	if p.have < s.Total {
		return "", false, nil
	}
	var out []byte
	for _, b := range p.parts {
		out = append(out, b...)
	}
	delete(r.partials, pk)
	return string(out), true, nil
}

// Expire drops partial messages older than wait and reports them so the caller
// can tell the user that part of a message was lost.
func (r *Reassembler) Expire(now time.Time, wait time.Duration) []Lost {
	r.mu.Lock()
	defer r.mu.Unlock()
	var lost []Lost
	for k, p := range r.partials {
		if now.Sub(p.since) >= wait {
			lost = append(lost, Lost{Node: k.node, Ch: k.ch, Have: p.have, Total: k.total})
			delete(r.partials, k)
		}
	}
	return lost
}
