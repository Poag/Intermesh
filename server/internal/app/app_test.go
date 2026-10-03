package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"

	"github.com/Poag/Intermesh/server/internal/meshcrypto"
	"github.com/Poag/Intermesh/server/internal/meshwire"
	"github.com/Poag/Intermesh/server/internal/mfb"
	"github.com/Poag/Intermesh/server/internal/simmesh"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

type instance struct {
	t    *testing.T
	app  *App
	cfg  FileConfig
	home []byte // key of the Home channel
	mu   sync.Mutex
	got  []paho.Message
	gw   paho.Client
	gwID string
}

func start(t *testing.T, name string, mod func(*FileConfig)) *instance {
	t.Helper()
	f := DefaultFileConfig()
	f.Name = name
	f.DataDir = t.TempDir()
	f.HTTPListen, f.MQTTListen, f.AdminListen = freeAddr(t), freeAddr(t), freeAddr(t)
	f.BaseURL = "http://" + f.HTTPListen
	f.AllowHTTP, f.AllowPrivate = true, true
	f.Enrolment = "public"
	f.RoamingOpen = true
	f.AnnounceMinutes = 0
	if mod != nil {
		mod(&f)
	}
	a, err := Start(context.Background(), f, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return &instance{t: t, app: a, cfg: f, gwID: "!aabbcc01"}
}

func (i *instance) api(method, path string, in any) (int, map[string]any) {
	i.t.Helper()
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "http://"+i.cfg.AdminListen+path, body)
	req.Header.Set("Authorization", "Bearer "+i.app.AdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		i.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// provision defines the Home channel and a gateway, connects the gateway over MQTT and
// subscribes it the way the firmware does.
func (i *instance) provision() {
	i.t.Helper()
	i.home = make([]byte, 16)
	rand.Read(i.home)
	if c, out := i.api("POST", "/api/channels", map[string]any{"name": "Home", "psk": base64.StdEncoding.EncodeToString(i.home),
		"scope": "community", "uplink": true, "downlink": true, "roaming": true, "number": 1}); c != 204 {
		i.t.Fatalf("channel: %d %v", c, out)
	}
	c, out := i.api("POST", "/api/gateways", map[string]any{"name": "gw", "channels": []string{"Home", "InterRoam"}})
	if c != 201 {
		i.t.Fatalf("gateway: %d %v", c, out)
	}
	pw := out["password"].(string)
	opts := paho.NewClientOptions().AddBroker("tcp://" + i.cfg.MQTTListen).SetClientID(i.gwID).SetUsername("gw").SetPassword(pw).
		SetAutoReconnect(false).SetConnectTimeout(3 * time.Second)
	i.gw = paho.NewClient(opts)
	if tok := i.gw.Connect(); !tok.WaitTimeout(4*time.Second) || tok.Error() != nil {
		i.t.Fatalf("gateway connect: %v", tok.Error())
	}
	i.t.Cleanup(func() { i.gw.Disconnect(10) })
	handler := func(_ paho.Client, m paho.Message) { i.mu.Lock(); i.got = append(i.got, m); i.mu.Unlock() }
	for _, ch := range []string{"Home", "InterRoam", "PKI"} {
		tok := i.gw.Subscribe("msh/2/e/"+ch+"/+", 0, handler)
		tok.WaitTimeout(2 * time.Second)
		if r := tok.(*paho.SubscribeToken).Result()["msh/2/e/"+ch+"/+"]; r == 0x80 {
			i.t.Fatalf("gateway subscription to %s refused", ch)
		}
	}
}

func (i *instance) uplink(channel string, payload []byte) {
	i.t.Helper()
	i.gw.Publish("msh/2/e/"+channel+"/"+i.gwID, 0, false, payload).WaitTimeout(2 * time.Second)
}

func (i *instance) downlinks() []*meshwire.ServiceEnvelope {
	i.mu.Lock()
	defer i.mu.Unlock()
	var out []*meshwire.ServiceEnvelope
	for _, m := range i.got {
		if env, err := meshwire.UnmarshalServiceEnvelope(m.Payload()); err == nil {
			out = append(out, env)
		}
	}
	return out
}

func (i *instance) serverPub() []byte { return i.app.Engine.ServerPublicKey() }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for k := 0; k < 300; k++ {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func TestEnrolmentThroughRealMQTTAndAdminAPI(t *testing.T) {
	s := start(t, "Kent Mesh", func(f *FileConfig) { f.Enrolment = "psk" })
	s.provision()
	node := simmesh.NewNode()
	serverNum, _ := s.app.Engine.ServerNode()

	// the node's NodeInfo reaches the server through the gateway, then it enrols with a PSK
	s.uplink("Home", node.NodeInfoUplink(t, "Home", s.home, s.gwID))
	_, psk := s.api("POST", "/api/psks", map[string]any{"kind": "single-use", "label": "alice"})
	secret := psk["secret"].(string)
	s.uplink("PKI", node.DMUplink(t, serverNum, s.serverPub(), "MFB1 E "+secret, s.gwID))

	var reply string
	waitFor(t, "an enrolment reply on the gateway's PKI subscription", func() bool {
		for _, env := range s.downlinks() {
			if env.ChannelID == meshwire.PKIChannelID && env.Packet.To == node.Num {
				if text, err := node.OpenPKI(env, s.serverPub()); err == nil {
					reply = text
					return true
				}
			}
		}
		return false
	})
	if reply != "MFB1 K" {
		t.Fatalf("reply %q", reply)
	}
	_, members := s.api("GET", "/api/status", nil)
	if members["members"].(float64) != 1 {
		t.Fatalf("status %v", members)
	}
	// the admin API refuses a request without the token
	req, _ := http.NewRequest("GET", "http://"+s.cfg.AdminListen+"/api/status", nil)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("admin API without a token: %d", resp.StatusCode)
	}
}

func TestRoamingBetweenTwoRunningServers(t *testing.T) {
	home := start(t, "Kent Mesh", nil)
	away := start(t, "Away Group", nil)
	home.provision()
	away.provision()

	if c, out := away.api("POST", "/api/peers/link", map[string]string{"actor": home.cfg.BaseURL + "/actor"}); c != 204 {
		t.Fatalf("link: %d %v", c, out)
	}
	waitFor(t, "home knows away", func() bool {
		_, out := home.api("GET", "/api/status", nil)
		return out["peers"].(float64) >= 1
	})

	// the roamer is a member of the home community: enrol over MQTT
	roamer := simmesh.NewNode()
	homeNum, _ := home.app.Engine.ServerNode()
	home.uplink("Home", roamer.NodeInfoUplink(t, "Home", home.home, home.gwID))
	home.uplink("PKI", roamer.DMUplink(t, homeNum, home.serverPub(), "MFB1 E -", home.gwID))
	waitFor(t, "roamer enrolled at home", func() bool { _, ok := home.app.State.Member(roamer.Num); return ok })

	// ... then registers with the visited community by a signed broadcast on the roaming channel
	rc, _ := away.app.State.Channel("InterRoam")
	const pktID = 0x00c0ffee
	line := (&mfb.Roam{HomeTag: home.app.Engine.HomeTag(), Days: 1}).String()
	away.uplink("InterRoam", roamer.ChannelUplink(t, "InterRoam", rc.Key, away.gwID, meshwire.PortText, []byte(line), meshwire.BroadcastNum, true, pktID))

	var confirm *mfb.Confirm
	waitFor(t, "the roamer is told it is registered, over the visited server's MQTT downlink", func() bool {
		for _, env := range away.downlinks() {
			if env.Packet.To != roamer.Num || env.ChannelID != "InterRoam" {
				continue
			}
			d, err := simmesh.OpenChannel(env, rc.Key)
			if err != nil {
				continue
			}
			if m, err := mfb.Parse(string(d.Payload)); err == nil {
				if c, ok := m.(*mfb.Confirm); ok {
					confirm = c
				}
			}
		}
		return confirm != nil
	})
	if confirm.Name != "Away Group" || confirm.Days != 1 || confirm.HomeTag != home.app.Engine.HomeTag() {
		t.Fatalf("%+v", confirm)
	}
	_, vis := away.api("GET", "/api/status", nil)
	if vis["slotsInUse"].(float64) != 1 {
		t.Fatalf("slots in use: %v", vis["slotsInUse"])
	}

	// a sealed message goes up through the visited server to the home channel
	hc, _ := home.app.State.Channel("Home")
	key, _ := mfb.DeriveKey(hc.Key, home.app.Engine.HomeTag(), roamer.Num, pktID, "Home", mfb.ToHome)
	parts, _, _ := mfb.SealText(key, roamer.Num, 1, 0, "hello over two servers and two brokers", mfb.BroadcastLineBudget, 3)
	for _, p := range parts {
		away.uplink("InterRoam", roamer.ChannelUplink(t, "InterRoam", rc.Key, away.gwID, meshwire.PortText, []byte(p.String()), meshwire.BroadcastNum, true, 0))
	}
	want := fmt.Sprintf("%08x: hello over two servers and two brokers", roamer.Num)
	waitFor(t, "the message appears on the home gateway's Home subscription", func() bool {
		for _, env := range home.downlinks() {
			if env.ChannelID != "Home" || env.Packet.From != homeNum {
				continue
			}
			if d, err := simmesh.OpenChannel(env, home.home); err == nil && string(d.Payload) == want {
				return true
			}
		}
		return false
	})
}

func TestGatewayCannotReadAnotherGatewaysUplinkOrWriteOffItsChannels(t *testing.T) {
	s := start(t, "Kent Mesh", nil)
	s.provision()
	// a second gateway limited to one channel
	c, out := s.api("POST", "/api/gateways", map[string]any{"name": "gw2", "channels": []string{"Home"}})
	if c != 201 {
		t.Fatal(c, out)
	}
	opts := paho.NewClientOptions().AddBroker("tcp://" + s.cfg.MQTTListen).SetClientID("!aabbcc02").SetUsername("gw2").SetPassword(out["password"].(string)).SetAutoReconnect(false)
	g2 := paho.NewClient(opts)
	if tok := g2.Connect(); !tok.WaitTimeout(3*time.Second) || tok.Error() != nil {
		t.Fatal("gw2 connect")
	}
	defer g2.Disconnect(10)
	var mu sync.Mutex
	var topics []string
	g2.Subscribe("msh/2/e/Home/+", 0, func(_ paho.Client, m paho.Message) { mu.Lock(); topics = append(topics, m.Topic()); mu.Unlock() }).WaitTimeout(time.Second)
	if r := g2.Subscribe("msh/2/e/InterRoam/+", 0, nil); true {
		r.WaitTimeout(time.Second)
		if r.(*paho.SubscribeToken).Result()["msh/2/e/InterRoam/+"] != 0x80 {
			t.Fatal("gw2 could subscribe to a channel it was not granted")
		}
	}
	n := simmesh.NewNode()
	s.uplink("Home", n.ChannelUplink(t, "Home", s.home, s.gwID, meshwire.PortText, []byte("hi"), meshwire.BroadcastNum, true, 0))
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	// Home is community scope, so the server relays the packet to gw2 itself. That arrives on the
	// server's own downlink topic, targeted at gw2. The broker never delivers gw's uplink topic.
	serverNum, _ := s.app.Engine.ServerNode()
	wantSuffix := fmt.Sprintf("/!%08x.!aabbcc02", serverNum)
	if len(topics) != 1 || !strings.HasSuffix(topics[0], wantSuffix) {
		t.Fatalf("gw2 received %v, want exactly one server relay ending %s", topics, wantSuffix)
	}
	for _, tp := range topics {
		if strings.HasSuffix(tp, "/!aabbcc01") {
			t.Fatal("gw2 received another gateway's uplink topic directly")
		}
	}
}

func TestConfigValidationAndTokenPersistence(t *testing.T) {
	f := DefaultFileConfig()
	if f.Validate() == nil {
		t.Fatal("a config without baseUrl accepted")
	}
	f.BaseURL = "https://x.example"
	f.Name = strings.Repeat("n", 25)
	if f.Validate() == nil {
		t.Fatal("a 25 character name accepted")
	}
	f.Name = "ok"
	f.Enrolment = "whenever"
	if f.Validate() == nil {
		t.Fatal("unknown enrolment mode accepted")
	}
	f.Enrolment = "manual"
	f.DefaultDays = 9
	if f.Validate() == nil {
		t.Fatal("nine default days accepted")
	}
	f.DefaultDays = 3
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	a, _ := adminToken(dir)
	b, _ := adminToken(dir)
	if a == "" || a != b {
		t.Fatal("admin token must be stable across runs")
	}
	if st, _ := os.Stat(filepath.Join(dir, "admin-token")); st.Mode().Perm() != 0o600 {
		t.Fatalf("admin token mode %v", st.Mode().Perm())
	}
	// node ids derived the same way the engine does it
	_ = meshcrypto.NodeID
}
