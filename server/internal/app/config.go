// Package app assembles the community server: state, the MQTT broker for border nodes,
// the federation HTTP server, the engine and the local admin API.
package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Poag/Intermesh/server/internal/core"
)

// FileConfig is the JSON configuration file. Durations are plain numbers with the unit in
// the name so the file is easy to write by hand.
type FileConfig struct {
	Name        string `json:"name"`
	BaseURL     string `json:"baseUrl"` // public https URL of this server, e.g. https://mesh.example.org
	DataDir     string `json:"dataDir"`
	HTTPListen  string `json:"httpListen"`  // federation listener, default :8443
	MQTTListen  string `json:"mqttListen"`  // border node listener, default :8883
	AdminListen string `json:"adminListen"` // local admin API, default 127.0.0.1:8081
	TLSCert     string `json:"tlsCert"`
	TLSKey      string `json:"tlsKey"`
	MQTTRoot    string `json:"mqttRoot"` // topic root the gateways use, default msh

	Enrolment         string `json:"enrolment"` // public, psk, manual or closed
	RoamingOpen       bool   `json:"roamingOpen"`
	RoamingSlots      int    `json:"roamingSlots"`
	DefaultDays       int    `json:"defaultDays"`
	MaxParts          int    `json:"maxParts"`
	PartWaitSeconds   int    `json:"partWaitSeconds"`
	ReplayMarginHours int    `json:"replayMarginHours"`
	PeerCap           int    `json:"peerCap"`
	HopLimit          int    `json:"hopLimit"`
	AnnounceMinutes   int    `json:"announceMinutes"` // 0 turns the NodeInfo announcement off
	Beacon            struct {
		Enabled         bool `json:"enabled"`
		IntervalMinutes int  `json:"intervalMinutes"`
		MinGapMinutes   int  `json:"minGapMinutes"`
		OnNewNode       bool `json:"onNewNode"`
	} `json:"beacon"`

	ActivityMaxAgeSeconds int `json:"activityMaxAgeSeconds"` // replay window for signed deliveries, default 300
	MaxActivityBytes      int `json:"maxActivityBytes"`      // default 65536
	KeyOverlapHours       int `json:"keyOverlapHours"`       // old signing key stays valid this long after a rotation

	// AllowPrivate and AllowHTTP exist for tests and private-network federation only.
	AllowPrivate bool `json:"allowPrivate"`
	AllowHTTP    bool `json:"allowHttp"`
}

// DefaultFileConfig returns the defaults.
func DefaultFileConfig() FileConfig {
	d := core.DefaultConfig()
	f := FileConfig{
		Name: d.Name, DataDir: "data", HTTPListen: ":8443", MQTTListen: ":8883", AdminListen: "127.0.0.1:8081", MQTTRoot: "msh",
		Enrolment: d.Enrolment, RoamingSlots: d.RoamingSlots, DefaultDays: d.DefaultDays, MaxParts: d.MaxParts,
		PartWaitSeconds: int(d.PartWait / time.Second), ReplayMarginHours: int(d.ReplayMargin / time.Hour), PeerCap: d.PeerCap,
		HopLimit: int(d.HopLimit), AnnounceMinutes: int(d.AnnounceInterval / time.Minute),
		ActivityMaxAgeSeconds: 300, MaxActivityBytes: 64 << 10, KeyOverlapHours: 24,
	}
	f.Beacon.MinGapMinutes = int(d.Beacon.MinGap / time.Minute)
	return f
}

// LoadConfig reads a config file, applying defaults for anything missing.
func LoadConfig(path string) (FileConfig, error) {
	f := DefaultFileConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, fmt.Errorf("%s: %w", path, err)
	}
	if !filepath.IsAbs(f.DataDir) {
		f.DataDir = filepath.Join(filepath.Dir(path), f.DataDir)
	}
	return f, f.Validate()
}

// Validate checks the values that would otherwise fail later.
func (f FileConfig) Validate() error {
	if f.BaseURL == "" {
		return errors.New("config: baseUrl is required (the public https URL of this server)")
	}
	if f.Name == "" || len(f.Name) > 24 {
		return errors.New("config: name must be 1 to 24 characters")
	}
	switch f.Enrolment {
	case core.EnrolPublic, core.EnrolPSK, core.EnrolManual, core.EnrolClosed:
	default:
		return fmt.Errorf("config: enrolment %q must be public, psk, manual or closed", f.Enrolment)
	}
	if f.DefaultDays < 1 || f.DefaultDays > 7 {
		return errors.New("config: defaultDays must be 1 to 7")
	}
	if f.MaxParts < 1 || f.MaxParts > 9 {
		return errors.New("config: maxParts must be 1 to 9")
	}
	return nil
}

// Core converts the file configuration to the engine's.
func (f FileConfig) Core() core.Config {
	c := core.DefaultConfig()
	c.Name, c.BaseURL, c.Enrolment = f.Name, f.BaseURL, f.Enrolment
	c.RoamingOpen, c.RoamingSlots, c.DefaultDays, c.MaxParts = f.RoamingOpen, f.RoamingSlots, f.DefaultDays, f.MaxParts
	c.PartWait = time.Duration(f.PartWaitSeconds) * time.Second
	c.ReplayMargin = time.Duration(f.ReplayMarginHours) * time.Hour
	c.PeerCap, c.HopLimit = f.PeerCap, uint32(f.HopLimit)
	c.AnnounceInterval = time.Duration(f.AnnounceMinutes) * time.Minute
	c.Beacon = core.BeaconConfig{Enabled: f.Beacon.Enabled, Interval: time.Duration(f.Beacon.IntervalMinutes) * time.Minute,
		MinGap: time.Duration(f.Beacon.MinGapMinutes) * time.Minute, OnNewNode: f.Beacon.OnNewNode}
	return c
}
