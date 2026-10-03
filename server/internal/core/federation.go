package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/Poag/Intermesh/server/internal/ap"
	"github.com/Poag/Intermesh/server/internal/state"
)

// maxIntroduced caps the entries sent in, and read from, one Introduce.
const maxIntroduced = 100

// HandleActivity is the federation handler: it receives each authenticated, fresh activity
// from an unblocked peer.
func (e *Engine) HandleActivity(ctx context.Context, from state.Peer, act *ap.Activity) error {
	switch act.Type {
	case ap.TypeRoam:
		return e.handleRoam(from, act)
	case ap.TypeAccept, ap.TypeReject:
		return e.handleAnswerOrFollow(from, act)
	case ap.TypeRelay:
		return e.handleRelay(from, act)
	case ap.TypeUndo:
		return e.handleUndo(from, act)
	case ap.TypeIntroduce:
		return e.handleIntroduce(from, act)
	case ap.TypeRename:
		return e.handleRename(from, act)
	case ap.TypeFollow:
		return e.handleFollow(from, act)
	}
	return nil // unknown activity types are ignored
}

func (e *Engine) handleAnswerOrFollow(from state.Peer, act *ap.Activity) error {
	var ref ap.UndoObject
	if err := act.DecodeObject(&ref); err == nil && ref.Type == ap.TypeFollow {
		e.mu.Lock()
		ours := e.outbound[ref.ID]
		delete(e.outbound, ref.ID)
		e.mu.Unlock()
		if ours && act.Type == ap.TypeAccept {
			e.event("new-server", "link to "+from.Actor+" accepted")
			e.sendIntroduce(from)
		}
		return nil
	}
	return e.handleAnswer(from, act)
}

// ---- Introduce ----------------------------------------------------------------------------

func (e *Engine) sendIntroduce(to state.Peer) {
	peers := e.st.Peers()
	sort.Slice(peers, func(i, j int) bool { return peers[i].LastHeard.After(peers[j].LastHeard) })
	var list []ap.IntroducedServer
	for _, p := range peers {
		if p.Blocked || p.Actor == to.Actor || p.HomeTag == "" {
			continue
		}
		list = append(list, ap.IntroducedServer{Actor: p.Actor, HomeTag: p.HomeTag, LastHeard: p.LastHeard.UTC().Format(time.RFC3339)})
		if len(list) >= maxIntroduced {
			break
		}
	}
	act, err := ap.Build(e.baseURL(), e.self.ActorURL, ap.TypeIntroduce, []string{to.Actor}, e.now(), ap.IntroduceObject{Servers: list}, nil)
	if err == nil {
		e.fed.Enqueue(backgroundCtx(), to.Inbox, act, nil)
	}
}

var learnSem = make(chan struct{}, 4)

// handleIntroduce adds the servers an Introduce lists, after fetching each one's actor to
// confirm it answers. Learned servers are trusted by default; the admin can block them.
func (e *Engine) handleIntroduce(from state.Peer, act *ap.Activity) error {
	var o ap.IntroduceObject
	if err := act.DecodeObject(&o); err != nil {
		return &ap.BadActivity{Reason: "bad introduce"}
	}
	if len(o.Servers) > maxIntroduced {
		o.Servers = o.Servers[:maxIntroduced]
	}
	var todo []string
	for _, s := range o.Servers {
		if s.Actor == "" || s.Actor == e.self.ActorURL || e.st.IsBlocked(s.Actor) {
			continue
		}
		if _, known := e.st.Peer(s.Actor); known {
			continue
		}
		if u, err := url.Parse(s.Actor); err != nil || u.Host == "" {
			continue
		}
		todo = append(todo, s.Actor)
	}
	if len(todo) == 0 {
		return nil
	}
	// The handler answers at once; fetching the listed actors happens in the background.
	go func() {
		var wg sync.WaitGroup
		for _, actor := range todo {
			actor := actor
			wg.Add(1)
			learnSem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-learnSem }()
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				p, err := e.fed.Learn(ctx, actor, false)
				if err != nil {
					e.log.Info("introduced server did not answer", "actor", actor, "err", err)
					return
				}
				e.sendIntroduce(*p) // first contact: introduce ourselves and what we know
			}()
		}
		wg.Wait()
	}()
	return nil
}

// IntroduceAll sends an Introduce to every unblocked peer (done once a day).
func (e *Engine) IntroduceAll() {
	for _, p := range e.st.Peers() {
		if !p.Blocked && p.Inbox != "" {
			e.sendIntroduce(p)
		}
	}
}

// OnNewPeer is called the first time a server is learned: the admin console shows it, and
// we introduce ourselves to it (first contact).
func (e *Engine) OnNewPeer(p state.Peer) {
	e.event("new-server", "learned server "+p.Actor+" (tag "+p.HomeTag+")")
}

// OnPeer is called whenever a peer's actor document has been fetched. It resolves a tag
// clash: when two servers hold the same tag the newer one renames (decided 3 Oct 2026).
func (e *Engine) OnPeer(p state.Peer, doc *ap.ActorDoc) {
	if p.Actor == e.self.ActorURL || doc.HomeTag != e.HomeTag() {
		return
	}
	id := e.st.Identity()
	weAreNewer := id.Created.After(p.Created) || (id.Created.Equal(p.Created) && e.self.ActorURL > p.Actor)
	if !weAreNewer {
		return // the other server is newer and will rename
	}
	e.renameSelf(p)
}

func (e *Engine) renameSelf(clash state.Peer) {
	taken := map[string]bool{e.HomeTag(): true}
	for _, q := range e.st.Peers() {
		taken[q.HomeTag] = true
		for _, a := range q.Aliases {
			taken[a] = true
		}
	}
	var tag string
	for {
		b := make([]byte, 4)
		rand.Read(b)
		tag = hex.EncodeToString(b)
		if !taken[tag] {
			break
		}
	}
	id := e.st.Identity()
	old := id.HomeTag
	id.HomeTag = tag
	id.Renamed = append(id.Renamed, old)
	if err := e.st.SetIdentity(id); err != nil {
		e.log.Error("rename failed", "err", err)
		return
	}
	e.st.QueueRenameNotices(tag)
	e.event("warning", "community tag "+old+" clashed with "+clash.Actor+"; this server is newer, so it changed its tag to "+tag)
	for _, p := range e.st.Peers() {
		if p.Blocked || p.Inbox == "" {
			continue
		}
		act, err := ap.Build(e.baseURL(), e.self.ActorURL, ap.TypeRename, []string{p.Actor}, e.now(),
			ap.RenameObject{OldTag: old, NewTag: tag, Server: e.self.ActorURL}, nil)
		if err == nil {
			e.fed.Enqueue(backgroundCtx(), p.Inbox, act, nil)
		}
	}
}

// handleRename accepts a signed Rename only from the server already known as holding the old tag.
func (e *Engine) handleRename(from state.Peer, act *ap.Activity) error {
	var o ap.RenameObject
	if err := act.DecodeObject(&o); err != nil || o.Server != from.Actor {
		return &ap.BadActivity{Reason: "bad rename"}
	}
	if from.HomeTag == o.NewTag {
		return nil // we already hold the new tag (we fetched the actor after the rename)
	}
	if err := e.st.ApplyRename(from.Actor, o.OldTag, o.NewTag); err != nil {
		return &ap.BadActivity{Reason: err.Error()}
	}
	return nil
}

// ---- Admin link-up (Follow, Accept, Undo) --------------------------------------------------

// LinkUp links this server to another by hand: it fetches the other server's actor to confirm
// it answers, then sends a standard Follow. The other server accepts unless it has blocked us;
// no second-admin approval is needed (decided 3 Oct 2026).
func (e *Engine) LinkUp(ctx context.Context, actorURL string) (*state.Peer, error) {
	p, err := e.fed.Learn(ctx, actorURL, true)
	if err != nil {
		return nil, err
	}
	obj, _ := json.Marshal(p.Actor)
	act, err := ap.Build(e.baseURL(), e.self.ActorURL, ap.TypeFollow, []string{p.Actor}, e.now(), nil, nil)
	if err != nil {
		return nil, err
	}
	act.Object = obj
	e.mu.Lock()
	e.outbound[act.ID] = true
	e.mu.Unlock()
	e.fed.Enqueue(ctx, p.Inbox, act, nil)
	e.event("new-server", "linked by hand to "+p.Actor)
	return p, nil
}

// Unlink ends an admin-made link with Undo and forgets the server if it was linked by hand.
func (e *Engine) Unlink(actorURL string) {
	p, ok := e.st.Peer(actorURL)
	if !ok {
		return
	}
	act, err := ap.Build(e.baseURL(), e.self.ActorURL, ap.TypeUndo, []string{p.Actor}, e.now(), ap.UndoObject{Type: ap.TypeFollow}, nil)
	if err == nil {
		e.fed.Enqueue(backgroundCtx(), p.Inbox, act, nil)
	}
	if p.Manual {
		e.st.RemovePeer(actorURL)
	}
}

func (e *Engine) handleFollow(from state.Peer, act *ap.Activity) error {
	var target string
	if err := json.Unmarshal(act.Object, &target); err != nil || target != e.self.ActorURL {
		return &ap.BadActivity{Reason: "follow is not addressed to this server"}
	}
	// The inbox already refused blocked senders silently, so reaching here means accept.
	out, err := ap.Build(e.baseURL(), e.self.ActorURL, ap.TypeAccept, []string{from.Actor}, e.now(),
		ap.UndoObject{Type: ap.TypeFollow, ID: act.ID}, nil)
	if err != nil {
		return err
	}
	e.fed.Enqueue(backgroundCtx(), from.Inbox, out, nil)
	e.event("new-server", "server "+from.Actor+" linked to us by hand")
	e.sendIntroduce(from)
	return nil
}
