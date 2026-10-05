# Intermesh

A draft design for replacing Meshtastic's MQTT uplink with a federation of local community ActivityPub servers.

Status: design draft with a prototype server, 4 October 2026. The Meshtastic firmware behaviour the design relies on was read from the firmware source (see section 8 of [SPEC.md](SPEC.md)), and a reference server in [server/](server/) implements the draft and passes its tests. **Nothing has been tested on real hardware, on the air, or with the Meshtastic mobile apps**, and nothing has had an independent security review.

## The idea

Each community runs its own small server, written in Go, with a built-in MQTT listener. A "border node" is an ordinary Meshtastic gateway pointed at that server over MQTT, so no firmware changes are needed beyond stock 2.8 and some settings (notably Ignore MQTT off, which the firmware turns on by default in regions with a duty cycle limit such as the UK; see section 1 of [SPEC.md](SPEC.md)). The server holds the channel keys for the channels it bridges. Local traffic stays local: every channel has a scope (mesh only, community, federated or public), and the default is the narrowest.

People who travel keep their identity at home. A roamer registers with a visited community by sending a signed broadcast on a shared roaming channel (InterRoam, on the firmware default key). The visited server passes the signed packet to the roamer's home server, which checks the signature and accepts or refuses. Until the home server accepts, the visited server relays nothing. Home traffic then flows sealed, so the visited server never holds a key or a readable copy.

Servers federate with each other only, using custom ActivityPub activities (Roam, Relay, Introduce, Rename) signed with RFC 9421 HTTP message signatures.

## What is suggested so far

The design suggestions so far, all open for comment (enrolment modes, beacons, signing, replay limits, key rotation, retries, server discovery and more) are written into [SPEC.md](SPEC.md). Items still open are listed at the end of that file. A worked example of a visitor roaming is in [EXAMPLE.md](EXAMPLE.md). The spec describes the minimal change method (stock firmware); a sketch of a possible optimal method, a dedicated roaming message format, is in [ROAMING-FORMAT.md](ROAMING-FORMAT.md).

## What is not done

- The reference server in [server/](server/) is a prototype. Persisted delivery queues, message retention, crossing federated channels to other servers and a roaming-aware app are not done.
- The Meshtastic mobile apps were read from source for contact import and beacon offers (section 8 of [SPEC.md](SPEC.md)) but nothing was tried on a phone, and how they display the server's broadcast status text was not checked.
- Licence: GPL-3.0, chosen by the project owner; see [LICENSE](LICENSE). The licences of any reused code still need checking for compatibility. This is not legal advice.
- An independent cryptography review of the sealing scheme is still needed before the spec is locked.

## Contributing

Feedback on the design is welcome, especially from people who know Meshtastic firmware and the ActivityPub libraries in Go.
