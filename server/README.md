# Reference server (planned)

Nothing is built here yet. The reference community server is planned in Go, small enough to run on a Raspberry Pi class device, with a built-in MQTT listener and no web interface. See [../SPEC.md](../SPEC.md) for what it has to do.

## Libraries under consideration

These notes come from package-page summaries on 3 October 2026 and have not been checked against the code. Re-read each library's repository and licence before relying on any of this.

- go-ap/activitypub and the wider go-ap organisation: reported as MIT. Reported to cover vocabulary types and client-to-server and server-to-server processing. Whether it handles RFC 9421 HTTP message signatures, or accepts custom activity types such as Roam and Relay, is open.
- go-fed/activity: reported as BSD-3-Clause, last release July 2020, appears archived.
- Mochi MQTT (mochi-mqtt/server v2): reported as MIT, with MQTT 3.0, 3.1.1 and 5, TLS listeners and per-client topic rules.

MIT and BSD-3-Clause are generally regarded as compatible with GPL-3.0 when used as dependencies. This is not legal advice; check the licence of every dependency and of any code copied rather than imported.
