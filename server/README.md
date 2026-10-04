# Reference server

A draft reference implementation of the community server in [../SPEC.md](../SPEC.md), written in Go. It runs the MQTT listener for border nodes, enrolment, roaming and sealed relay, and federates with other community servers over ActivityPub.

**Status.** It builds and its tests pass, including two running servers federating while real MQTT gateway clients connect to each. **It has not run against real Meshtastic hardware, firmware, or the mobile apps**, and it has had no independent security or cryptography review. Treat it as a design prototype, not something to expose to the internet.

## Build and test

Needs Go 1.26 (the module declares it; a newer toolchain is fetched automatically). From this directory:

    go build ./cmd/intermeshd
    go test ./...
    go test -race ./...

The cross-check of the XEdDSA code against the firmware's own cryptography library needs a native build of that library; see [internal/meshcrypto/testdata/README.md](internal/meshcrypto/testdata/README.md). That test is skipped unless `INTERMESH_XEDDSA_HARNESS` points at the built harness. Likewise the wire codec is compared against the firmware's nanopb by `internal/meshwire/nanopb_test.go`, skipped unless `INTERMESH_NANOPB_HARNESS` points at a build (see [internal/meshwire/testdata/README.md](internal/meshwire/testdata/README.md)).

## Run

    intermeshd init -dir ./mesh -url https://mesh.example.org -name "Kent Mesh"
    # edit ./mesh/config.json: TLS certificate and key, ports, enrolment mode
    intermeshd run -config ./mesh/config.json

The config file and its defaults are in `internal/app/config.go`. Without a TLS certificate the server warns and expects a TLS-terminating reverse proxy; put TLS on the MQTT listener before exposing it to the internet.

Administer it with `intermeshd ctl`, which talks to a local admin API protected by the bearer token in `data/admin-token`. The common first steps:

    intermeshd ctl -config ./mesh/config.json channel-add Home default scope=community uplink downlink roaming=1
    intermeshd ctl -config ./mesh/config.json gateway-add gw1 Home InterRoam     # prints the password once
    intermeshd ctl -config ./mesh/config.json contact                            # node ID, public key and a shared contact link for members (QR code from the url)
    intermeshd ctl -config ./mesh/config.json psk-add single-use alice
    intermeshd ctl -config ./mesh/config.json link https://other.example/actor   # link to another community

Run `intermeshd` with no arguments for every verb. Set `MQTT encryption` on for every gateway and name channels on the gateways exactly as on the server (see SPEC.md section 1).

## Layout

| Path | What it does |
| --- | --- |
| `internal/meshwire` | minimal protobuf codec for ServiceEnvelope, MeshPacket, Data, User |
| `internal/meshcrypto` | channel AES-CTR, PKI direct messages, XEdDSA, node numbers |
| `internal/mfb` | the MFB1 messages, sealed traffic, reassembly and replay window |
| `internal/state` | durable state in one JSON file: members, PSKs, visits, registrations, peers |
| `internal/ap` | RFC 9421 signatures, actor, inbox, delivery with retries |
| `internal/broker` | embedded MQTT broker with per-gateway credentials and isolation |
| `internal/core` | the engine: uplink handling, enrolment, roaming, relay, federation, beacons |
| `internal/app` | wiring, config file and the admin API |
| `internal/simmesh` | simulated nodes for tests |
| `cmd/intermeshd` | the command |

## What is implemented

- Gateway credentials limited to named channels, uplink only to a gateway's own topic, no gateway-to-gateway delivery, targeted downlink, retained publishes stripped.
- Enrolment by public, PSK, manual and closed modes, PSK kinds (non-expiring, rotating, single-use, multi-use with expiry), pending approval, the registry bound to full public keys.
- Roaming as visited and as home server with every refusal code, signature verification of the forwarded broadcast, replay memory, slots, pending cap, rate limits, early end when the roamer is heard at home.
- Sealed traffic in both directions (HKDF, ChaCha20-Poly1305, split parts, wait limit, replay window).
- Federation: signed deliveries, replay limit, silent blocking, key rotation overlap, Introduce, Rename with tag clash resolution, admin link-up, SSRF protections.
- Beacons (off by default, with a minimum gap and a new-node trigger) and a signed NodeInfo announcement.

## What is not implemented

- Persisted outbound deliveries (a restart forgets queued activities) and message retention (the setting is stored, no history is kept).
- Federated and public channel scopes crossing to other servers or to the public MQTT broker; they behave as community scope.
- A roaming-aware app. The server and the sealed format exist; nothing implements the roamer's side except the test simulator.
- Metrics, a web interface, high availability. None are planned.

## Dependencies

Go standard library plus the modules below. Licences were read from each module's LICENSE file in the module cache on 4 October 2026.

| Module | Used for | Licence file says |
| --- | --- | --- |
| `github.com/mochi-mqtt/server/v2` v2.7.9 | the MQTT broker | MIT |
| `golang.org/x/crypto` v0.57.0 | X25519 and ChaCha20-Poly1305 | BSD-3-Clause style |
| `filippo.io/edwards25519` v1.2.0 | XEdDSA signing | BSD-3-Clause style |
| `google.golang.org/protobuf` v1.36.12 | protobuf wire encoding | BSD-3-Clause style |
| `github.com/gorilla/websocket` v1.5.3 (pulled in by the broker) | not used directly | BSD-2-Clause style |
| `github.com/rs/xid` v1.4.0 (pulled in by the broker) | not used directly | MIT |
| `github.com/eclipse/paho.mqtt.golang` v1.5.1 | **tests only**, a client to drive the broker | EPL-2.0, with EDL-1.0 also accompanying |

MIT and BSD-style licences are generally regarded as compatible with GPL-3.0 as dependencies. EPL-2.0 is a different matter and is not generally regarded as compatible with GPL-3.0 on its own terms. paho is imported only by `_test.go` files and is not linked into `intermeshd`, but it is part of the module's dependency graph, so check it (and the others) properly before distributing anything. This is not legal advice.
