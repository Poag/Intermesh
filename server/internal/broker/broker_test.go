package broker

import (
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"

	"github.com/Poag/Intermesh/server/internal/state"
)

type env struct {
	b    *Broker
	st   *state.State
	addr string
	mu   sync.Mutex
	got  []Uplink
}

func (e *env) uplinks() []Uplink {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Uplink(nil), e.got...)
}

func addGateway(t *testing.T, st *state.State, user, pass string, channels ...string) {
	t.Helper()
	salt := make([]byte, 16)
	rand.Read(salt)
	if err := st.SetGateway(state.Gateway{Username: user, Salt: salt, PassHash: HashPassword(salt, pass), Channels: channels, Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, _ := state.Open("", nil)
	addGateway(t, st, "gw1", "pw1", "Home", "InterRoam")
	addGateway(t, st, "gw2", "pw2", "Home", "InterRoam")
	addGateway(t, st, "gw3", "pw3", "Other")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	e := &env{st: st, addr: addr}
	b, err := New(st, "msh", "!00000001", func(u Uplink) { e.mu.Lock(); e.got = append(e.got, u); e.mu.Unlock() }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	e.b = b
	if err := b.Listen(addr, nil); err != nil {
		t.Fatal(err)
	}
	if err := b.Serve(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return e
}

func (e *env) connect(t *testing.T, id, user, pass string) (paho.Client, bool) {
	t.Helper()
	opts := paho.NewClientOptions().AddBroker("tcp://" + e.addr).SetClientID(id).SetUsername(user).SetPassword(pass).
		SetAutoReconnect(false).SetConnectRetry(false).SetConnectTimeout(2 * time.Second)
	c := paho.NewClient(opts)
	tok := c.Connect()
	if !tok.WaitTimeout(3*time.Second) || tok.Error() != nil {
		return c, false
	}
	t.Cleanup(func() { c.Disconnect(10) })
	return c, true
}

func (e *env) waitUplinks(n int) []Uplink {
	for i := 0; i < 100; i++ {
		if u := e.uplinks(); len(u) >= n {
			return u
		}
		time.Sleep(20 * time.Millisecond)
	}
	return e.uplinks()
}

func TestAuthentication(t *testing.T) {
	e := newEnv(t)
	if _, ok := e.connect(t, "!a1b2c3d4", "gw1", "pw1"); !ok {
		t.Fatal("valid gateway refused")
	}
	if _, ok := e.connect(t, "!a1b2c3d5", "gw1", "wrong"); ok {
		t.Fatal("wrong password accepted")
	}
	if _, ok := e.connect(t, "!a1b2c3d6", "nobody", "pw1"); ok {
		t.Fatal("unknown user accepted")
	}
	if _, ok := e.connect(t, "laptop", "gw1", "pw1"); ok {
		t.Fatal("client id that is not a node id accepted")
	}
	g, _ := e.st.Gateway("gw1")
	if g.NodeID != "!a1b2c3d4" {
		t.Fatalf("gateway node id not recorded: %q", g.NodeID)
	}
}

func TestUplinkACL(t *testing.T) {
	e := newEnv(t)
	c, _ := e.connect(t, "!a1b2c3d4", "gw1", "pw1")
	pub := func(topic string, retain bool) {
		c.Publish(topic, 0, retain, []byte("env")).WaitTimeout(time.Second)
	}
	pub("msh/2/e/InterRoam/!a1b2c3d4", false)  // allowed
	pub("msh/2/e/Home/!a1b2c3d4", false)       // allowed
	pub("msh/2/e/PKI/!a1b2c3d4", false)        // allowed
	pub("msh/2/e/Other/!a1b2c3d4", false)      // channel not granted
	pub("msh/2/e/Home/!ffffffff", false)       // someone else's gateway id
	pub("msh/2/map/", false)                   // map reports are not accepted
	pub("elsewhere/2/e/Home/!a1b2c3d4", false) // wrong root
	pub("msh/2/e/interroam/!a1b2c3d4", false)  // case differs: the firmware's own name lookup is case-insensitive
	got := e.waitUplinks(4)
	time.Sleep(150 * time.Millisecond)
	got = e.uplinks()
	var chans []string
	for _, u := range got {
		chans = append(chans, u.Channel)
		if u.GatewayID != "!a1b2c3d4" || u.Username != "gw1" {
			t.Fatalf("wrong attribution %+v", u)
		}
	}
	want := map[string]int{"InterRoam": 1, "Home": 1, "PKI": 1, "interroam": 1}
	have := map[string]int{}
	for _, c := range chans {
		have[c]++
	}
	if len(have) != len(want) {
		t.Fatalf("accepted channels %v", chans)
	}
	for k, v := range want {
		if have[k] != v {
			t.Fatalf("accepted channels %v", chans)
		}
	}
}

func TestSubscriptionACL(t *testing.T) {
	e := newEnv(t)
	c, _ := e.connect(t, "!a1b2c3d4", "gw1", "pw1")
	res := func(filter string) byte {
		tok := c.Subscribe(filter, 0, nil)
		tok.WaitTimeout(time.Second)
		st := tok.(*paho.SubscribeToken).Result()
		return st[filter]
	}
	for _, ok := range []string{"msh/2/e/InterRoam/+", "msh/2/e/Home/+", "msh/2/e/PKI/+"} {
		if res(ok) == 0x80 {
			t.Errorf("%s refused", ok)
		}
	}
	for _, bad := range []string{"msh/2/e/Other/+", "msh/2/e/#", "msh/2/e/+/+", "#", "msh/2/e/Home/#", "msh/2/map/"} {
		if res(bad) != 0x80 {
			t.Errorf("%s granted", bad)
		}
	}
}

func TestDownlinkReachesOnlyTheServerChosenGateway_AndGatewaysNeverHearEachOther(t *testing.T) {
	e := newEnv(t)
	c1, _ := e.connect(t, "!a1b2c3d4", "gw1", "pw1")
	c2, _ := e.connect(t, "!a1b2c3d5", "gw2", "pw2")
	var mu sync.Mutex
	var got1, got2 [][]byte
	c1.Subscribe("msh/2/e/Home/+", 0, func(_ paho.Client, m paho.Message) { mu.Lock(); got1 = append(got1, m.Payload()); mu.Unlock() }).WaitTimeout(time.Second)
	c2.Subscribe("msh/2/e/Home/+", 0, func(_ paho.Client, m paho.Message) { mu.Lock(); got2 = append(got2, m.Payload()); mu.Unlock() }).WaitTimeout(time.Second)

	// gw1 uplinks; gw2 must not hear it, the server must.
	c1.Publish("msh/2/e/Home/!a1b2c3d4", 0, false, []byte("from-gw1")).WaitTimeout(time.Second)
	if u := e.waitUplinks(1); len(u) != 1 || string(u[0].Payload) != "from-gw1" {
		t.Fatalf("server did not receive the uplink: %+v", u)
	}
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	if len(got2) != 0 || len(got1) != 0 {
		t.Fatalf("gateways heard uplink: gw1 %d gw2 %d", len(got1), len(got2))
	}
	mu.Unlock()

	// the server downlinks to every gateway on the channel
	if err := e.b.Publish("Home", "", []byte("downlink")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		mu.Lock()
		n := len(got1) + len(got2)
		mu.Unlock()
		if n == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	if len(got1) != 1 || len(got2) != 1 || string(got1[0]) != "downlink" {
		t.Fatalf("downlink delivery: gw1 %d gw2 %d", len(got1), len(got2))
	}
	mu.Unlock()

	// a targeted downlink reaches only the named gateway
	if err := e.b.Publish("Home", "!a1b2c3d5", []byte("just-gw2")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(got1) != 1 || len(got2) != 2 || string(got2[1]) != "just-gw2" {
		t.Fatalf("targeted downlink: gw1 %d gw2 %d", len(got1), len(got2))
	}
}

func TestRetainedPublishIsNotKept(t *testing.T) {
	e := newEnv(t)
	c1, _ := e.connect(t, "!a1b2c3d4", "gw1", "pw1")
	c1.Publish("msh/2/e/Home/!a1b2c3d4", 0, true, []byte("retain-me")).WaitTimeout(time.Second)
	e.waitUplinks(1)
	c2, _ := e.connect(t, "!a1b2c3d5", "gw2", "pw2")
	var n int
	var mu sync.Mutex
	c2.Subscribe("msh/2/e/Home/+", 0, func(paho.Client, paho.Message) { mu.Lock(); n++; mu.Unlock() }).WaitTimeout(time.Second)
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if n != 0 {
		t.Fatal("a retained message was replayed to a new subscriber")
	}
}

func TestOversizePublishRejected(t *testing.T) {
	e := newEnv(t)
	c, _ := e.connect(t, "!a1b2c3d4", "gw1", "pw1")
	c.Publish("msh/2/e/Home/!a1b2c3d4", 0, false, make([]byte, MaxPayload+1)).WaitTimeout(time.Second)
	time.Sleep(200 * time.Millisecond)
	if len(e.uplinks()) != 0 {
		t.Fatal("oversize publish accepted")
	}
}
