package ap

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// ContextURL is the extension context published from the spec repository. It assumes the
// default branch is "main" (see InterMesh Assumptions).
const ContextURL = "https://raw.githubusercontent.com/Poag/Intermesh/main/context/v1.jsonld"

// ASContext is the ActivityStreams context.
const ASContext = "https://www.w3.org/ns/activitystreams"

// ContentType of every delivery.
const ContentType = "application/activity+json"

// Activity types.
const (
	TypeRoam      = "Roam"
	TypeRelay     = "Relay"
	TypeIntroduce = "Introduce"
	TypeRename    = "Rename"
	TypeFollow    = "Follow"
	TypeAccept    = "Accept"
	TypeReject    = "Reject"
	TypeUndo      = "Undo"
)

// Activity is the envelope shared by every activity. Object and Result stay raw until the
// handler knows the type.
type Activity struct {
	Context   any             `json:"@context,omitempty"`
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Actor     string          `json:"actor"`
	To        []string        `json:"to,omitempty"`
	Published string          `json:"published,omitempty"`
	Object    json.RawMessage `json:"object,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
}

// RoamObject is the object of a Roam (visited server to home server inbox).
type RoamObject struct {
	Node     string `json:"node"`     // roamer's node id, 8 lowercase hex
	HomeTag  string `json:"homeTag"`  // home community tag, 8 lowercase hex
	PacketID uint32 `json:"packetId"` // the registration broadcast's packet id
	Days     int    `json:"days"`     // 0 means the home community default... see Handler
	Packet   string `json:"packet"`   // base64 of the MeshPacket protobuf as received from the gateway
}

// AcceptResult is the result of an Accept answering a Roam.
type AcceptResult struct {
	Expires   string `json:"expires"`             // RFC 3339
	Days      int    `json:"days"`                // granted days
	PublicKey string `json:"publicKey,omitempty"` // base64 Curve25519 key of the roamer, vouched for by the home server
}

// RejectResult is the result of a Reject answering a Roam.
type RejectResult struct {
	Code string `json:"code"`
	Text string `json:"text,omitempty"`
}

// UndoObject names the registration an Undo ends.
type UndoObject struct {
	Type string `json:"type"`           // Roam
	ID   string `json:"id,omitempty"`   // id of the Roam activity
	Node string `json:"node,omitempty"` // roamer's node id
}

// Relay kinds and directions.
const (
	KindSealed = "sealed"
	KindPacket = "packet"
	DirUp      = "up"
	DirDown    = "down"
)

// RelayObject is the object of a Relay. For kind sealed, Ch and Part carry the
// fields of the on-air S message that the base spec's example omitted.
type RelayObject struct {
	Node      string `json:"node"`
	Direction string `json:"direction"`
	Kind      string `json:"kind"`
	Ch        string `json:"ch,omitempty"`     // 2 hex, home channel number (sealed)
	Ctr       uint64 `json:"ctr,omitempty"`    // sealed
	Part      string `json:"part,omitempty"`   // "2/3" (sealed)
	Data      string `json:"data,omitempty"`   // base64url ciphertext and tag (sealed)
	Packet    string `json:"packet,omitempty"` // base64 MeshPacket protobuf (packet, down only)
}

// IntroducedServer is one entry of an Introduce.
type IntroducedServer struct {
	Actor     string `json:"actor"`
	HomeTag   string `json:"homeTag"`
	LastHeard string `json:"lastHeard"`
}

// IntroduceObject is the object of an Introduce.
type IntroduceObject struct {
	Servers []IntroducedServer `json:"servers"`
}

// RenameObject is the object of a Rename.
type RenameObject struct {
	OldTag string `json:"oldTag"`
	NewTag string `json:"newTag"`
	Server string `json:"server"`
}

// NewID returns a fresh activity id under base.
func NewID(base string) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base + "/activities/" + hex.EncodeToString(b)
}

// Build creates an activity from this server to the given actors. object and result may be nil.
func Build(base, actor, typ string, to []string, now time.Time, object, result any) (*Activity, error) {
	a := &Activity{
		Context:   []string{ASContext, ContextURL},
		ID:        NewID(base),
		Type:      typ,
		Actor:     actor,
		To:        to,
		Published: now.UTC().Format(time.RFC3339),
	}
	var err error
	if object != nil {
		if a.Object, err = json.Marshal(object); err != nil {
			return nil, err
		}
	}
	if result != nil {
		if a.Result, err = json.Marshal(result); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// DecodeObject unmarshals the activity's object into v.
func (a *Activity) DecodeObject(v any) error {
	if len(a.Object) == 0 {
		return errors.New("ap: activity has no object")
	}
	return json.Unmarshal(a.Object, v)
}

// DecodeResult unmarshals the activity's result into v.
func (a *Activity) DecodeResult(v any) error {
	if len(a.Result) == 0 {
		return errors.New("ap: activity has no result")
	}
	return json.Unmarshal(a.Result, v)
}

// PublicKeyDoc is the publicKey member of an actor document.
type PublicKeyDoc struct {
	ID                 string `json:"id"`
	Owner              string `json:"owner"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
	ValidUntil         string `json:"validUntil,omitempty"` // only on a previous key during a rotation overlap
}

// ActorDoc is the actor document each community server publishes.
type ActorDoc struct {
	Context           any           `json:"@context,omitempty"`
	ID                string        `json:"id"`
	Type              string        `json:"type"`
	Name              string        `json:"name,omitempty"`
	Inbox             string        `json:"inbox"`
	HomeTag           string        `json:"homeTag"`
	Published         string        `json:"published,omitempty"`
	PublicKey         PublicKeyDoc  `json:"publicKey"`
	PreviousPublicKey *PublicKeyDoc `json:"previousPublicKey,omitempty"`
}
