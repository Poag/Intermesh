package core

import (
	"context"

	"github.com/Poag/Intermesh/server/internal/ap"
	"github.com/Poag/Intermesh/server/internal/state"
)

type apFederation struct {
	out *ap.Outbox
	srv *ap.Server
}

// NewFederation connects the engine to the ActivityPub outbox and server.
func NewFederation(out *ap.Outbox, srv *ap.Server) Federation { return apFederation{out, srv} }

func (f apFederation) Enqueue(ctx context.Context, inbox string, act *ap.Activity, onDrop func(error)) {
	f.out.EnqueueWith(ctx, inbox, act, onDrop)
}

func (f apFederation) Learn(ctx context.Context, actor string, manual bool) (*state.Peer, error) {
	return f.srv.Learn(ctx, actor, manual)
}
