# Intermesh

A draft design for replacing Meshtastic's MQTT uplink with a federation of local community ActivityPub servers.

Status: design draft, 3 October 2026. Nothing is built or tested on hardware. Every claim about Meshtastic firmware and every library note comes from summarising web pages or secondary sources, and must be re-read from the primary source before building. See [SPEC.md](SPEC.md).

## The idea

Each community runs its own small server, written in Go, with a built-in MQTT listener. A "border node" is an ordinary Meshtastic gateway pointed at that server over MQTT, so the firmware needs no changes beyond stock 2.8. The server holds the channel keys for the channels it bridges. Local traffic stays local: every channel has a scope (mesh only, community, federated or public), and the default is the narrowest.

People who travel keep their identity at home. A roamer registers with a visited community by sending a signed broadcast on a shared roaming channel (InterRoam, on the firmware default key). The visited server passes the signed packet to the roamer's home server, which checks the signature and accepts or refuses. Until the home server accepts, the visited server relays nothing. Home traffic then flows sealed, so the visited server never holds a key or a readable copy.

Servers federate with each other only, using custom ActivityPub activities (Roam, Relay, Introduce, Rename) signed with RFC 9421 HTTP message signatures.

## What is decided

The design decisions so far (enrolment modes, beacons, signing, replay limits, key rotation, retries, server discovery and more) are written into [SPEC.md](SPEC.md). Items still open are listed at the end of that file.

## What is not done

- No code yet. The reference server is planned in Go.
- Licence: GPL-3.0, chosen by the project owner; see [LICENSE](LICENSE). The licences of any reused code still need checking for compatibility. This is not legal advice.
- An independent cryptography review of the sealing scheme is still needed before the spec is locked.

## Contributing

Feedback on the design is welcome, especially from people who know Meshtastic firmware and the ActivityPub libraries in Go.
