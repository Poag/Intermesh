// Command intermeshd is the reference community server for Intermesh.
//
//	intermeshd init -dir ./mesh -url https://mesh.example.org -name "Kent Mesh"
//	intermeshd run  -config ./mesh/config.json
//	intermeshd ctl  -config ./mesh/config.json status
//
// See SPEC.md and server/README.md. This is a draft reference implementation: nothing
// here has run on real hardware.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Poag/Intermesh/server/internal/app"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "init":
		cmdInit(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	case "ctl":
		cmdCtl(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  intermeshd init -dir DIR -url https://your.host -name "Community name"
  intermeshd run  -config DIR/config.json
  intermeshd ctl  -config DIR/config.json VERB [ARGS]

ctl verbs:
  status | contact | events | beacon | beacon-send | announce
  gateways | gateway-add NAME CHANNEL... | gateway-rm NAME
  channels | channel-add NAME [default|BASE64KEY] [scope=mesh|community|federated|public] [uplink] [downlink] [roaming=N]
  psks | psk-add KIND [LABEL] [hours=N]   (KIND: non-expiring, rotating, single-use, multi-use)
  psk-revoke ID
  members | member-approve NODE | member-rm NODE
  peers | peer-block URL | peer-unblock URL | link URL | unlink URL
  visits | roamers | rotate-key [HOURS]
`)
	os.Exit(2)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "intermeshd:", err)
	os.Exit(1)
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", "mesh", "directory for the config file and data")
	url := fs.String("url", "", "public https URL of this server")
	name := fs.String("name", "Community", "community name (24 characters at most)")
	fs.Parse(args)
	if *url == "" {
		fatal(fmt.Errorf("-url is required"))
	}
	f := app.DefaultFileConfig()
	f.BaseURL, f.Name, f.DataDir = *url, *name, "data"
	if err := f.Validate(); err != nil {
		fatal(err)
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		fatal(err)
	}
	path := filepath.Join(*dir, "config.json")
	if _, err := os.Stat(path); err == nil {
		fatal(fmt.Errorf("%s already exists", path))
	}
	b, _ := json.MarshalIndent(f, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		fatal(err)
	}
	fmt.Printf("wrote %s\nnext: edit it (TLS, ports, enrolment mode), then run: intermeshd run -config %s\n", path, path)
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "config.json", "config file")
	fs.Parse(args)
	f, err := app.LoadConfig(*cfgPath)
	if err != nil {
		fatal(err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	a, err := app.Start(ctx, f, log)
	if err != nil {
		fatal(err)
	}
	c := a.Engine.ServerContact()
	log.Info("community server running", "name", f.Name, "homeTag", a.Engine.HomeTag(), "nodeId", c.NodeID,
		"publicKey", c.PublicKeyBase64(), "fingerprint", c.Fingerprint, "mqtt", f.MQTTListen, "http", f.HTTPListen, "admin", f.AdminListen)
	<-ctx.Done()
	log.Info("shutting down")
	a.Close()
}

func cmdCtl(args []string) {
	fs := flag.NewFlagSet("ctl", flag.ExitOnError)
	cfgPath := fs.String("config", "config.json", "config file")
	fs.Parse(args)
	rest := fs.Args()
	if len(rest) == 0 {
		usage()
	}
	f, err := app.LoadConfig(*cfgPath)
	if err != nil {
		fatal(err)
	}
	tok, err := os.ReadFile(filepath.Join(f.DataDir, "admin-token"))
	if err != nil {
		fatal(fmt.Errorf("no admin token (has the server run yet?): %w", err))
	}
	method, path, body, err := ctlRequest(rest)
	if err != nil {
		fatal(err)
	}
	host := f.AdminListen
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	req, _ := http.NewRequest(method, "http://"+host+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		fatal(fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(out))))
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, out, "", "  ") == nil {
		fmt.Println(pretty.String())
	} else if len(out) > 0 {
		fmt.Println(string(out))
	}
}

func ctlRequest(a []string) (method, path string, body []byte, err error) {
	j := func(v any) []byte { b, _ := json.Marshal(v); return b }
	need := func(n int) error {
		if len(a) < n {
			return fmt.Errorf("%s needs %d argument(s)", a[0], n-1)
		}
		return nil
	}
	switch a[0] {
	case "status", "contact", "events", "beacon", "gateways", "channels", "psks", "members", "peers", "visits", "roamers":
		return "GET", "/api/" + a[0], nil, nil
	case "beacon-send":
		return "POST", "/api/beacon/send", nil, nil
	case "announce":
		return "POST", "/api/announce", nil, nil
	case "gateway-add":
		if err = need(3); err != nil {
			return
		}
		return "POST", "/api/gateways", j(map[string]any{"name": a[1], "channels": a[2:]}), nil
	case "gateway-rm":
		if err = need(2); err != nil {
			return
		}
		return "DELETE", "/api/gateways/" + a[1], nil, nil
	case "channel-add":
		if err = need(2); err != nil {
			return
		}
		m := map[string]any{"name": a[1]}
		for _, x := range a[2:] {
			switch {
			case x == "default":
				m["psk"] = "default"
			case x == "uplink":
				m["uplink"] = true
			case x == "downlink":
				m["downlink"] = true
			case strings.HasPrefix(x, "scope="):
				m["scope"] = strings.TrimPrefix(x, "scope=")
			case strings.HasPrefix(x, "roaming="):
				var n int
				fmt.Sscanf(strings.TrimPrefix(x, "roaming="), "%d", &n)
				m["roaming"], m["number"] = true, n
			default:
				m["psk"] = x
			}
		}
		return "POST", "/api/channels", j(m), nil
	case "psk-add":
		if err = need(2); err != nil {
			return
		}
		m := map[string]any{"kind": a[1]}
		for _, x := range a[2:] {
			if strings.HasPrefix(x, "hours=") {
				var n int
				fmt.Sscanf(strings.TrimPrefix(x, "hours="), "%d", &n)
				m["periodHours"], m["expiresHours"] = n, n
			} else {
				m["label"] = x
			}
		}
		return "POST", "/api/psks", j(m), nil
	case "psk-revoke":
		if err = need(2); err != nil {
			return
		}
		return "POST", "/api/psks/" + a[1] + "/revoke", nil, nil
	case "member-approve":
		if err = need(2); err != nil {
			return
		}
		return "POST", "/api/members/" + strings.TrimPrefix(a[1], "!") + "/approve", nil, nil
	case "member-rm":
		if err = need(2); err != nil {
			return
		}
		return "DELETE", "/api/members/" + strings.TrimPrefix(a[1], "!"), nil, nil
	case "peer-block", "peer-unblock", "link", "unlink":
		if err = need(2); err != nil {
			return
		}
		p := map[string]string{"peer-block": "block", "peer-unblock": "unblock", "link": "link", "unlink": "unlink"}[a[0]]
		return "POST", "/api/peers/" + p, j(map[string]string{"actor": a[1]}), nil
	case "rotate-key":
		m := map[string]any{}
		if len(a) > 1 {
			var n int
			fmt.Sscanf(a[1], "%d", &n)
			m["overlapHours"] = n
		}
		return "POST", "/api/rotate-key", j(m), nil
	}
	return "", "", nil, fmt.Errorf("unknown verb %q", a[0])
}
