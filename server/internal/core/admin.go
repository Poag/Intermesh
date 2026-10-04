package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Poag/Intermesh/server/internal/ap"
	"github.com/Poag/Intermesh/server/internal/broker"
	"github.com/Poag/Intermesh/server/internal/meshcrypto"
	"github.com/Poag/Intermesh/server/internal/meshwire"
	"github.com/Poag/Intermesh/server/internal/state"
)

// MaxChannelNameLen is the longest channel name a node can hold: the protobuf options give
// ChannelSettings.name max_size 12, which counts the terminator.
const MaxChannelNameLen = 11

// Contact is the server contact the admin hands out so members can enrol: the server's node
// id and public key (a Meshtastic shared contact, or typed in by hand).
type Contact struct {
	NodeID       string `json:"nodeId"`
	NodeNum      uint32 `json:"nodeNum"`
	PublicKeyB64 string `json:"publicKeyBase64"`
	PublicKeyHex string `json:"publicKeyHex"`
	Fingerprint  string `json:"fingerprint"` // first 8 bytes of SHA-256 of the key, to check a typed key
	// URL is a shared-contact link. The Android and Apple apps import it from a QR code made from
	// it, from NFC, or pasted in; both read https://meshtastic.org/v/# followed by the base64url of
	// a SharedContact (read from their source on 4 Oct 2026; not tried on a phone).
	URL string `json:"url"`
}

// SharedContactURLPrefix is the prefix both mobile apps recognise for a shared contact.
const SharedContactURLPrefix = "https://meshtastic.org/v/#"

// PublicKeyBase64 returns the public key in base64.
func (c Contact) PublicKeyBase64() string { return c.PublicKeyB64 }

// ServerContact returns the contact details.
func (e *Engine) ServerContact() Contact {
	sum := sha256.Sum256(e.meshPub)
	sc := &meshwire.SharedContact{NodeNum: e.serverNum, ManuallyVerified: false, User: &meshwire.User{
		ID: e.serverID, LongName: truncateUTF8(e.cfg.Name, 40), ShortName: shortName(e.HomeTag()), PublicKey: e.meshPub}}
	return Contact{URL: SharedContactURLPrefix + base64.RawURLEncoding.EncodeToString(sc.Marshal()), NodeID: e.serverID, NodeNum: e.serverNum, PublicKeyB64: base64.StdEncoding.EncodeToString(e.meshPub),
		PublicKeyHex: hex.EncodeToString(e.meshPub), Fingerprint: hex.EncodeToString(sum[:8])}
}

// Status is a summary for the admin console.
type Status struct {
	Name        string  `json:"name"`
	HomeTag     string  `json:"homeTag"`
	Contact     Contact `json:"contact"`
	Enrolment   string  `json:"enrolment"`
	RoamingOpen bool    `json:"roamingOpen"`
	SlotsInUse  int     `json:"slotsInUse"`
	Slots       int     `json:"slots"`
	Members     int     `json:"members"`
	Pending     int     `json:"pendingMembers"`
	Peers       int     `json:"peers"`
	Visitors    int     `json:"visitors"`
	Roamers     int     `json:"roamers"`
}

// Status summarises the server.
func (e *Engine) Status() Status {
	pending := 0
	members := e.st.Members()
	for _, m := range members {
		if m.Pending {
			pending++
		}
	}
	return Status{Name: e.cfg.Name, HomeTag: e.HomeTag(), Contact: e.ServerContact(), Enrolment: e.cfg.Enrolment,
		RoamingOpen: e.cfg.RoamingOpen, SlotsInUse: e.st.SlotsInUse(), Slots: e.cfg.RoamingSlots,
		Members: len(members) - pending, Pending: pending, Peers: len(e.st.Peers()),
		Visitors: len(e.st.Visits()), Roamers: len(e.st.Registrations())}
}

// AddGateway creates a gateway credential limited to the named channels and returns the
// generated password, which is shown once. Every channel must exist.
func (e *Engine) AddGateway(username string, channels []string) (string, error) {
	if username == "" || strings.ContainsAny(username, " /#+") {
		return "", errors.New("gateway name must be a single plain word")
	}
	if len(channels) == 0 {
		return "", errors.New("a gateway needs at least one channel")
	}
	for _, c := range channels {
		if _, ok := e.st.Channel(c); !ok {
			return "", fmt.Errorf("channel %q is not defined", c)
		}
	}
	pw := make([]byte, 16)
	rand.Read(pw)
	password := strings.ToLower(hex.EncodeToString(pw))
	salt := make([]byte, 16)
	rand.Read(salt)
	if err := e.st.SetGateway(state.Gateway{Username: username, Salt: salt, PassHash: broker.HashPassword(salt, password),
		Channels: channels, Created: e.now()}); err != nil {
		return "", err
	}
	return password, nil
}

// SetChannel adds or changes a channel. psk is the channel's stored PSK (empty, one byte for
// the firmware shorthand, 16 or 32 bytes); it is expanded the way the firmware does.
func (e *Engine) SetChannel(name string, psk []byte, scope string, uplink, downlink, roaming bool, number int, retentionHours int) error {
	if name == "" || len(name) > MaxChannelNameLen {
		return fmt.Errorf("channel names are 1 to %d characters", MaxChannelNameLen)
	}
	if strings.ContainsAny(name, "/#+") {
		return errors.New("channel names cannot contain / # or +")
	}
	switch scope {
	case "":
		scope = ScopeMesh // the narrowest is the default
	case ScopeMesh, ScopeCommunity, ScopeFederated, ScopePublic:
	default:
		return fmt.Errorf("unknown scope %q", scope)
	}
	key, err := meshcrypto.ExpandPSK(psk)
	if err != nil {
		return err
	}
	if number < 0 || number > 255 {
		return errors.New("channel number must be 0 to 255")
	}
	if roaming {
		for _, c := range e.st.Channels() {
			if c.Roaming && c.Number == uint8(number) && !strings.EqualFold(c.Name, name) {
				return fmt.Errorf("channel number %02x is already used by %s", number, c.Name)
			}
		}
	}
	return e.st.SetChannel(state.Channel{Name: name, Number: uint8(number), Roaming: roaming, Key: key, Scope: scope,
		Uplink: uplink, Downlink: downlink, RetentionHours: retentionHours})
}

// RotateAPKey makes a new ActivityPub signing key. The new key is published on the actor at
// once and the old one stays valid for overlap (admin-triggered rotation, suggested 3 Oct 2026).
func (e *Engine) RotateAPKey(client *ap.Client, overlap time.Duration) error {
	id := e.st.Identity()
	oldPub := ed25519.NewKeyFromSeed(id.APPriv).Public().(ed25519.PublicKey)
	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	n := 2
	if i := strings.LastIndex(id.APKeyID, "#key-"); i >= 0 {
		fmt.Sscanf(id.APKeyID[i+5:], "%d", &n)
		n++
	}
	id.OldAPPub, id.OldAPKeyID, id.OldAPUntil = oldPub, id.APKeyID, e.now().Add(overlap)
	id.APPriv, id.APKeyID = seed, e.self.ActorURL+fmt.Sprintf("#key-%d", n)
	if err := e.st.SetIdentity(id); err != nil {
		return err
	}
	client.SetKey(id.APKeyID, ed25519.NewKeyFromSeed(seed))
	e.event("warning", "ActivityPub signing key rotated; the previous key stays valid until "+id.OldAPUntil.UTC().Format(time.RFC3339))
	return nil
}
