package ap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Self is what a server needs to know about itself to sign deliveries.
type Self struct {
	ActorURL string
	InboxURL string
	KeyID    string
	Priv     ed25519.PrivateKey
}

// DefaultSchedule is the proposed retry gap schedule: growing gaps adding up to just under
// 24 hours (the cumulative total is 22 hours 21 minutes 15 seconds). The spec leaves the
// schedule open, so this is a proposal.
var DefaultSchedule = []time.Duration{
	15 * time.Second, time.Minute, 5 * time.Minute, 15 * time.Minute,
	time.Hour, 3 * time.Hour, 6 * time.Hour, 12 * time.Hour,
}

// GiveUpAfter is how long a delivery is retried before it is dropped (decided 3 Oct 2026).
const GiveUpAfter = 24 * time.Hour

// MaxActorBytes caps an actor document fetch.
const MaxActorBytes = 64 << 10

// Client delivers activities and fetches actor documents.
type Client struct {
	HTTP *http.Client
	Self Self
	Now  func() time.Time
	Log  *slog.Logger
	// AllowPrivate permits requests to loopback and private addresses. It is for tests and
	// for communities that deliberately federate over a private network; the default refuses
	// them so an Introduce cannot make the server probe its own network.
	AllowPrivate bool
	// AllowHTTP permits plain http URLs (tests only).
	AllowHTTP bool
}

// NewClient returns a client with a hardened HTTP transport.
func NewClient(self Self, allowPrivate, allowHTTP bool) *Client {
	c := &Client{Self: self, Now: time.Now, Log: slog.Default(), AllowPrivate: allowPrivate, AllowHTTP: allowHTTP}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if !allowPrivate {
		dialer.Control = func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return err
			}
			if isPrivate(ip) {
				return fmt.Errorf("ap: refusing to connect to non-public address %s", ip)
			}
			return nil
		}
	}
	c.HTTP = &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			MaxIdleConns:          20,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c
}

func isPrivate(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || ip.Is4() && ip.As4()[0] == 100 && ip.As4()[1]&0xc0 == 0x40
}

func (c *Client) checkURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("ap: bad url %q", raw)
	}
	if u.Scheme != "https" && !(c.AllowHTTP && u.Scheme == "http") {
		return nil, fmt.Errorf("ap: %q must be https", raw)
	}
	return u, nil
}

// FetchActor retrieves and validates an actor document. It checks that the document's id is
// the URL asked for, that the inbox is on the same host, and that the key belongs to the actor.
func (c *Client) FetchActor(ctx context.Context, actorURL string) (*ActorDoc, error) {
	u, err := c.checkURL(actorURL)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Header.Set("Accept", ContentType)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ap: %s answered %d", actorURL, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxActorBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxActorBytes {
		return nil, errors.New("ap: actor document too large")
	}
	var d ActorDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("ap: actor document: %w", err)
	}
	return &d, ValidateActor(&d, actorURL, c.AllowHTTP)
}

// ValidateActor checks an actor document fetched from actorURL.
func ValidateActor(d *ActorDoc, actorURL string, allowHTTP bool) error {
	if d.ID != actorURL {
		return fmt.Errorf("ap: actor id %q is not %q", d.ID, actorURL)
	}
	if !isLowerHex8(d.HomeTag) {
		return errors.New("ap: actor has no valid homeTag")
	}
	iu, err := url.Parse(d.Inbox)
	au, _ := url.Parse(actorURL)
	if err != nil || iu.Host != au.Host || iu.Scheme != au.Scheme {
		return errors.New("ap: inbox must be on the actor's own origin")
	}
	if d.PublicKey.Owner != d.ID || !strings.HasPrefix(d.PublicKey.ID, d.ID+"#") {
		return errors.New("ap: key does not belong to the actor")
	}
	if _, err := DecodeEd25519Multikey(d.PublicKey.PublicKeyMultibase); err != nil {
		return err
	}
	if p := d.PreviousPublicKey; p != nil {
		if p.Owner != d.ID || !strings.HasPrefix(p.ID, d.ID+"#") {
			return errors.New("ap: previous key does not belong to the actor")
		}
		if _, err := DecodeEd25519Multikey(p.PublicKeyMultibase); err != nil {
			return err
		}
		if _, err := time.Parse(time.RFC3339, p.ValidUntil); err != nil {
			return errors.New("ap: previous key needs validUntil")
		}
	}
	return nil
}

func isLowerHex8(s string) bool {
	if len(s) != 8 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && s == strings.ToLower(s)
}

// PermanentError marks a delivery failure that retrying cannot fix.
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// Send makes one delivery attempt, signing the request afresh with the current time.
func (c *Client) Send(ctx context.Context, inbox string, act *Activity) error {
	u, err := c.checkURL(inbox)
	if err != nil {
		return &PermanentError{err}
	}
	body, err := json.Marshal(act)
	if err != nil {
		return &PermanentError{err}
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("Accept", ContentType)
	nonce := make([]byte, 8)
	rand.Read(nonce)
	if err := SignRequest(req, body, c.Self.KeyID, c.Self.Priv, c.Now(), hex.EncodeToString(nonce)); err != nil {
		return &PermanentError{err}
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fmt.Errorf("ap: %s answered %d", inbox, resp.StatusCode)
	default:
		return &PermanentError{fmt.Errorf("ap: %s refused the delivery with %d", inbox, resp.StatusCode)}
	}
}

// Outbox delivers activities with retries. Deliveries are held in memory only: a restart
// forgets them, a documented limitation of this version.
type Outbox struct {
	Client   *Client
	Schedule []time.Duration
	GiveUp   time.Duration
	Sleep    func(ctx context.Context, d time.Duration) error

	wg      sync.WaitGroup
	mu      sync.Mutex
	pending int
	Dropped func(inbox string, act *Activity, err error) // called when a delivery is abandoned
}

// NewOutbox returns an outbox using the default schedule and 24 hour limit.
func NewOutbox(c *Client) *Outbox {
	return &Outbox{Client: c, Schedule: DefaultSchedule, GiveUp: GiveUpAfter, Sleep: sleepCtx}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Enqueue starts delivering act to inbox in the background.
func (o *Outbox) Enqueue(ctx context.Context, inbox string, act *Activity) {
	o.mu.Lock()
	o.pending++
	o.mu.Unlock()
	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		defer func() { o.mu.Lock(); o.pending--; o.mu.Unlock() }()
		o.deliver(ctx, inbox, act)
	}()
}

func (o *Outbox) deliver(ctx context.Context, inbox string, act *Activity) {
	start := o.Client.Now()
	var waited time.Duration
	var err error
	for attempt := 0; ; attempt++ {
		if err = o.Client.Send(ctx, inbox, act); err == nil {
			return
		}
		var perm *PermanentError
		if errors.As(err, &perm) || ctx.Err() != nil {
			break
		}
		if attempt >= len(o.Schedule) {
			break
		}
		gap := o.Schedule[attempt]
		if waited+gap > o.GiveUp {
			break
		}
		if o.Sleep(ctx, gap) != nil {
			break
		}
		waited += gap
		_ = start
	}
	o.Client.Log.Warn("delivery abandoned", "inbox", inbox, "type", act.Type, "id", act.ID, "err", err)
	if o.Dropped != nil {
		o.Dropped(inbox, act, err)
	}
}

// Wait blocks until every queued delivery has finished or been abandoned (tests).
func (o *Outbox) Wait() { o.wg.Wait() }

// Pending reports how many deliveries are still being attempted.
func (o *Outbox) Pending() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.pending
}
