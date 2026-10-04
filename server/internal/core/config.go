// Package core is the community server's engine. It receives packets uplinked by border
// nodes, runs enrolment and roaming, and relays sealed traffic between servers. It talks
// to the mesh through a Gateways interface (the MQTT broker) and to other servers through
// a Federation interface (the ActivityPub outbox), so both can be replaced in tests.
package core

import "time"

// Enrolment modes (suggested 3 Oct 2026: the admin chooses).
const (
	EnrolPublic = "public" // any node can enrol; no PSK needed
	EnrolPSK    = "psk"    // a valid PSK is required
	EnrolManual = "manual" // a valid PSK enrols; a request without one waits for the admin
	EnrolClosed = "closed" // no new enrolments (refusal code EC)
)

// Channel scopes (SPEC.md section 1). The default, if none is set, is the narrowest.
const (
	ScopeMesh      = "mesh"
	ScopeCommunity = "community"
	ScopeFederated = "federated"
	ScopePublic    = "public"
)

// BeaconConfig holds the beacon settings. Beacons are off by default (suggested 3 Oct 2026).
type BeaconConfig struct {
	Enabled   bool
	Interval  time.Duration // periodic beacon; zero means no periodic beacon
	MinGap    time.Duration // minimum gap between any two beacons; caps the new-node trigger
	OnNewNode bool          // beacon when a node not seen before is heard
}

// Config is the admin-set behaviour of a community server.
type Config struct {
	Name        string // community name, shown in registration confirmations (24 characters at most)
	BaseURL     string // public https base URL, e.g. https://mesh.example.org
	RoamChannel string // roaming channel name, InterRoam
	Enrolment   string // public, psk, manual or closed

	RoamingOpen      bool          // accept roamers from other communities
	RoamingSlots     int           // concurrent accepted roaming registrations
	MaxPendingVisits int           // registrations waiting for a home server
	PendingTimeout   time.Duration // how long to wait for a home server's answer
	DefaultDays      int           // default registration period, 1 to 7
	RatePerNode      int           // registration attempts per node per RateWindow
	RatePerTag       int           // registration attempts per home tag per RateWindow
	RateWindow       time.Duration
	RelayPerMinute   int // sealed parts relayed per roamer per minute

	MaxParts     int           // maximum parts of a sealed message (default 3)
	PartWait     time.Duration // wait before a partial sealed message is dropped (default 2 minutes)
	ReplayMargin time.Duration // added to one week when remembering accepted registration packet IDs
	PeerCap      int           // cap on the shared server list (default 500)
	HopLimit     uint32        // hop limit on packets the server downlinks (default 3)
	// AnnounceInterval is how often the server downlinks a signed NodeInfo for its own
	// identity so gateways and nodes learn its public key. Zero disables it.
	AnnounceInterval time.Duration

	Beacon BeaconConfig
}

// DefaultConfig returns the defaults suggested in the design.
func DefaultConfig() Config {
	return Config{
		Name:             "Community",
		RoamChannel:      "InterRoam",
		Enrolment:        EnrolManual,
		RoamingOpen:      false,
		RoamingSlots:     10,
		MaxPendingVisits: 50,
		PendingTimeout:   10 * time.Minute,
		DefaultDays:      3,
		RatePerNode:      5,
		RatePerTag:       30,
		RateWindow:       10 * time.Minute,
		RelayPerMinute:   30,
		MaxParts:         3,
		PartWait:         2 * time.Minute,
		ReplayMargin:     24 * time.Hour,
		PeerCap:          500,
		HopLimit:         3,
		AnnounceInterval: 6 * time.Hour,
		Beacon:           BeaconConfig{MinGap: 10 * time.Minute},
	}
}
