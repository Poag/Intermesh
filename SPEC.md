# Intermesh specification (draft)

Status: draft. Written 3 October 2026 and revised 4 October 2026.

What changed in the revision: the Meshtastic firmware and protobuf behaviour listed in section 8 was read directly from source (firmware `develop` at commit 3fdc613d7b8358355b5a8d8460618caa4e164461 and the release tag v2.8.1 at commit 8e6a88d06f44cad26f1e8d7cd402939ccacb9b4c; protobufs at commit 95c5f8c1c4223bb27faa81417b90560037f8ad31). Earlier drafts relied on summarising fetches. A reference server in `server/` implements this draft and passes its own tests, including tests against the firmware's published test vectors, but **nothing has been tested on real hardware, on the air, or with the Meshtastic mobile apps.** Field layouts, separators and codes are proposals unless marked decided. Items marked unverified were not checked.

## 1. Architecture in brief

- A community server (Go, small enough for a Raspberry Pi class device) with a built-in MQTT listener (TLS when exposed to the internet) and no web interface. Members use their mesh apps; admins use an admin console.
- A border node is any ordinary gateway pointed at the server over MQTT. The server issues per-gateway MQTT credentials limited to named channels, and holds the channel keys for the channels it bridges. A gateway node takes exactly one MQTT server address (read from the firmware), so a gateway pointed at a community server cannot also feed the public broker.
- Gateways must have MQTT encryption enabled (decided). The server drops traffic that arrives decoded and shows a warning in the admin console naming the gateway. If a gateway's permissions do not match a channel's settings, the server drops the traffic and logs an error naming the gateway and channel (decided); it does not message the gateway.
- Gateway requirements that follow from the firmware (verified from source):
  - The gateway must not have the CLIENT_MUTE role or rebroadcast mode NONE, or packets the server downlinks are never transmitted.
  - A channel name must be configured on the gateway exactly as the server spells it. The firmware finds the channel case-insensitively but then compares the topic's channel name case-sensitively, so `interroam` would not match `InterRoam`.
  - Gateways need uplink and downlink on for the channels the server bridges, and for downlink of direct messages at least one channel must have downlink on.
  - A gateway uplinks a packet it merely received only if it can decode it with a channel it holds, or if it is a PKI direct message (header channel byte 0) not addressed to the gateway. For decoded packets from other nodes it drops those without the OK to MQTT bit unless the server's address is a private one (192.168/16, 172.16/12, 10/8, 169.254/16, 100.64/10, 127.0.0.1). So with a community server on a public address, **every member node needs OK to MQTT turned on** for its packets, including the NodeInfo the server learns its key from, to reach the server.
- Channel scopes: mesh only, community, federated, public. Default is the narrowest. In the reference server a community, federated or public channel is relayed between the community's own gateways; federated and public do not yet cross to other servers or to the public MQTT broker.
- Servers federate with each other only, not with ordinary fediverse software (may be opened later).

## 2. Conventions for on-air messages

Every on-air message is one line of ASCII text starting `MFB1`, then a type letter, then space-separated fields. A receiver ignores any message whose tag or version it does not know. A known type with bad fields is malformed (refusal code BF).

- Node ID: 8 lowercase hex characters (no `!`).
- Home tag: 8 lowercase hex characters (32 bits), generated randomly by the home server. A server checks peers for a duplicate when it joins; the server whose identity is newer renames on a clash (decided), keeping the old tag as an alias.
- Days: a single digit, 1 to 7. The longest registration is one week.
- Roaming channel: name `InterRoam` (9 characters; the firmware limit is 11), firmware default key (the shorthand PSK value 1, which the firmware expands to `d4f1bb3a20290759f0bcffabcf4e6901`), position sharing off, uplink and downlink on at gateways. The roamer's node must use the same region, modem preset and frequency slot as the visited mesh (decided: the roamer sets this). Secondary channels use only the key and name and ignore radio settings, and the frequency slot is derived from the primary channel's name unless set explicitly; this came from the earlier summarising pass and was not re-read.
- Server identity: each server has a Curve25519 key pair and its node number is the CRC-32 (IEEE) of its public key, exactly as for any node. This is what lets nodes trust the server's signed NodeInfo and its signed beacon (see section 8). The admin hands out the node ID and public key as the server contact.
- Size budget (verified rule, estimate of the result): a node signs a broadcast only if the encoded Data message including a 64-byte signature field (66 bytes with the protobuf tag and length) fits 239 bytes, which is 255 minus the 16-byte header. That leaves roughly 160 bytes of text on a signed broadcast. Unsigned packets have more room (the payload limit is 233 bytes). An earlier draft double counted the header; this is the corrected rule. The reference codec budgets 166 bytes per signed line and 232 per unsigned line.

## 3. On-air messages

### Beacon (server, downlinked to the roaming channel, signed by the server)

`MFB1 B <tag> <node> <state> <slots> <days>`

- tag: the community's home tag. node: the server's own node ID, target for enrolment DMs (each server has its own, there is no fixed ID). state: `O` open or `C` closed to new roamers. slots: free roaming slots, decimal. days: default registration period.
- Off by default. The admin sets an interval, or a "new node detected" trigger, and a minimum gap between beacons. Example: `MFB1 B 9f3a07c2 a1b2c3d4 O 12 3`. A receiver ignores a beacon not signed by the node ID it names.
- The server signs the beacon (XEdDSA, as for any broadcast). A receiving node can only verify it if it holds the server's key, which it gets from the server's signed NodeInfo announcement (section 8). A receiver on the compatible policy accepts it unverified.
- Firmware 2.8 has its own Mesh Beacon module (port number 37, `MESH_BEACON_APP`) that broadcasts at most once an hour a message of up to 60 bytes plus an offered channel, region, preset and frequency slot, which listening apps cache but never apply automatically. It is not used by this draft. Whether to use it to advertise InterRoam and so help roamers on a different preset is an open design question.

### Roaming broadcast (roamer, signed by firmware 2.8)

`MFB1 R <hometag> <days>`

- `-` for days means the community's default. Unsigned registrations are refused (code US) because the default signature policy of a node is COMPATIBLE, which accepts unsigned packets, so an unsigned registration does reach the server and the server must refuse it itself. The roamer's node needs OK to MQTT on or gateways will not uplink it (the check applies to other nodes' packets when the broker address is not a private IP).

### Enrolment DM (member to server)

`MFB1 E <psk>`

- A PKI direct message to the server contact (node ID and public key, shared by the admin as a Meshtastic shared contact if apps support it; manual entry of both is the documented fallback; neither is verified). `-` for public enrolment or a request awaiting manual approval. Otherwise the PSK itself. Replies, also PKI direct messages: `MFB1 K` enrolled, `MFB1 P` pending admin approval, or a refusal (`MFB1 X <node> <code>`).
- Preconditions found in the firmware (verified): a node refuses to send a PKI message to a node whose public key it does not have, so the member's node must already hold the server's key (shared contact, or the server's announced NodeInfo). Gateways uplink the raw encrypted packet, which does not carry the sender's key, so the server can decrypt the DM only if it already knows the member's key, learned from a NodeInfo broadcast the member's node sent on a channel the server holds (accepted only if the key's CRC-32 equals the node number). For the server's reply to be transmitted, the gateway's node database must already hold both nodes, so the server announces itself.
- Enrolment modes (admin chooses): public; PSK by DM; manual (PSK or a console checkbox); closed (refusal EC). PSK types: non-expiring, rotating (admin-set period, default 7 days; only the current PSK is accepted after rotation), single-use, multi-use with expiry. The admin shares PSKs out of band. Revoking a PSK stops new enrolments but keeps enrolled nodes; admins remove nodes individually.
- The registry stores each node's number and full public key and refuses a different key for an enrolled node number. Public enrolment still binds the first key to a number, but a later claimant cannot replace it. Replay protection by packet ID applies to enrolment DMs.

### Registration confirmation (visited server, to the roamer)

`MFB1 C <node> <tag> <days> <name>`

- node: the roamer's node ID. Name is last, may contain spaces, set by the admin (limit 24 characters).
- Sent as a **broadcast** on the roaming channel, signed when the signed packet fits, naming the roamer in the text. It cannot be a text addressed to the roamer: the firmware refuses a channel-encrypted text message addressed to the node ("Rejecting legacy DM" in `perhapsDecode`, verified from source; licensed nodes are exempt). A PKI direct message would work only if the roamer's node held the visited server's key and the gateway held both nodes' records, which cannot be assumed. This departs from the earlier draft's "DM" and from its format, which had no node field. Anyone holding the public InterRoam key can read it, and it already shows who is roaming.

### Refusal notice (states the reason, admin may add text)

`MFB1 X <node> <code> [free text]`

- node: the node being refused. CL community closed; NS no free slots (also used when the per-home-tag rate limit is hit); BL home server blocked by this community; US registration not signed (firmware 2.8 required) or the signature does not verify; UH home server unknown or unreachable; HR home server refused (node not enrolled or not approved); RP repeated registration (also used when the per-node rate limit is hit); BF malformed message; EP enrolment PSK invalid, expired or used; EC enrolment closed.
- Registration refusals are broadcasts on the roaming channel, for the reason given under the confirmation. Enrolment refusals and the replies K and P are PKI direct messages, which work because the member's node holds the server's key (it had to, to send the enrolment) and the server's NodeInfo announcement lets the gateway hold both nodes. The mapping of rate limits to NS and RP is this draft's choice.

### Sealed traffic (home server and the roamer's roaming-aware app)

`MFB1 S <node> <ch> <ctr> <part> <data>`

- node: roamer's node ID. ch: 2-hex home channel number defined by the home server. ctr: per-direction counter in hex, advanced for every part, also the nonce. part: such as `2/3`, `1/1` when it fits one packet. data: ciphertext plus 16-byte tag, base64url without padding.
- Keys (pending independent cryptography review): for each registration and home channel, two keys by HKDF-SHA256 from the home channel key, salt empty, with the info string `intermesh/MFB1/seal/v1|<direction>|<home tag>|<node, 8 hex>|<accepted registration packet ID, 8 hex>|<home channel name>` where direction is `to-home` or `to-roamer`. Authenticated cipher: ChaCha20-Poly1305. The nonce is 4 zero bytes followed by the counter as 8 bytes big-endian. The associated data is the visible header `<node, 8 hex> <ch, 2 hex> <ctr, hex> <part>/<total>`, so a relay cannot renumber parts or move a part. The visited server never holds the keys.
- Delivery: sealed parts travel as **broadcasts** on the roaming channel in both directions (a text addressed to a node would be refused by the firmware, as above), signed when the signed packet fits and unsigned when it does not, which is exactly when a receiver on the balanced policy accepts an unsigned broadcast from a node it knows signs. Everyone in range of the visited gateway hears the sealed parts and cannot read them; the node field names the roamer.
- Capacity: 78 bytes of text per part on a signed broadcast line of 166 bytes, 128 bytes per part on an unsigned line (computed by the codec's tests; not measured on air). Long messages are split into numbered parts; the admin sets the maximum parts (default 3). A missing part is dropped after an admin-set wait (default 2 minutes) and the receiver can show a gap. No retransmission.
- Replay: each registration keeps a replay window of 64 counters per direction. Windows are kept per registration, because a re-registration derives new keys and restarts counters at zero.
- The sealed key derivation gives no forward secrecy and is not an audited design.

## 4. Roaming rules (decided)

- The visited server relays nothing until the home server accepts. Pending registrations take no slot.
- The visited server tells the roamer by broadcast (see the confirmation and refusal notice). It refuses what it can see itself: community closed, unsigned, no slots, unknown or blocked home tag, rate limits. Everything else is the home server's decision.
- The home server decrypts the forwarded packet with the InterRoam key, verifies the signature against the enrolled node's key, checks enrolment, and remembers accepted registration packet IDs for one week plus an admin-set margin, rejecting repeats.
- Slots are concurrent accepted registrations, set by the admin. Admin-set rate limits per node ID and per home tag.
- Registration ends early when the roamer is heard on the home mesh. If a roamer is registered with two communities, the home server replies through whichever relayed last.
- The home server notifies members by DM after a tag rename, the next time their node is heard at home. The notification text is free-form; no format is defined (open).
- Home channel traffic is delivered to a roamer sealed, and a roamer's sealed messages are posted to the home channel by the server, attributed with the roamer's node ID. The server cannot post as the roamer: a receiver on the balanced policy drops an unsigned broadcast from a node it knows signs.

## 5. Server-to-server

Delivery uses ActivityPub with RFC 9421 HTTP message signatures. The reference implementation signs with Ed25519 (`alg="ed25519"`), covers `@method`, `@target-uri`, `content-digest` (SHA-256) and `content-type`, and carries a signed `created` timestamp, a `keyid` of the form `<actor URL>#main-key` and a random nonce. The implementation's signature base construction was checked against the RFC's appendix B.2.6 Ed25519 test vector. Standard Follow, Accept, Reject and Undo are reused where they fit. The extension context is published from this repository at [context/v1.jsonld](context/v1.jsonld). The URL in the examples assumes the repository's default branch is `main` and that the file is merged there (unverified). The context file has not been tested with a JSON-LD processor or an ActivityPub library.

- Replay limit (decided): a server rejects a delivery whose signed timestamp is older than 5 minutes (admin-changeable) or more than a minute in the future, and remembers recent activity IDs inside the window. Maximum activity size 64 KB (admin-changeable). Retries use growing gaps for up to 24 hours, signing each attempt afresh, then drop. The gap schedule is a proposal: 15 s, 1 min, 5 min, 15 min, 1 h, 3 h, 6 h, 12 h (total 22 h 21 min 15 s). Deliveries are held in memory, so a restart forgets them.
- Key rotation (decided): admin-triggered; the new key is published on the actor and the old key is published as `previousPublicKey` with `validUntil` and accepted until then.
- Actor document: `id`, `type` (Service), `name`, `inbox` (same origin as the actor), `homeTag`, `published` (when the identity was created, used to decide which of two servers sharing a tag is newer), `publicKey` (`id`, `owner`, `publicKeyMultibase` as an Ed25519 multikey) and optionally `previousPublicKey`.
- Learned servers are trusted by default; an admin can block them. Blocking is silent: a blocked server's deliveries are acknowledged with a bare 202 and discarded. The console shows each new server. The shared server list is capped by the admin (default 500); when full, the least recently heard unblocked server is dropped (blocked servers are kept so a block is not undone).
- Safeguards in the reference server: actor and delivery URLs must be https, requests to loopback, private and link-local addresses are refused, redirects are not followed, actor documents are capped at 64 KB, and lookups triggered by unauthenticated requests are limited to one per actor per ten seconds and sixty a minute.

### Roam (visited server to home server inbox)

```json
{
  "@context": ["https://www.w3.org/ns/activitystreams", "https://raw.githubusercontent.com/Poag/Intermesh/main/context/v1.jsonld"],
  "type": "Roam",
  "id": "https://b.example/activities/123",
  "actor": "https://b.example/actor",
  "to": ["https://a.example/actor"],
  "published": "2026-10-03T12:00:00Z",
  "object": {
    "node": "c0ffee01",
    "homeTag": "4be10c77",
    "packetId": 123456789,
    "days": 3,
    "packet": "<base64 of the MeshPacket protobuf as received from the gateway, still encrypted>"
  }
}
```

`days` is the period the visited server resolved (the roamer's choice, or its own default). The home server grants at most the roamer's own choice. It decrypts `packet` with the InterRoam key, so the visited server forwards what it received and nothing it re-encoded.

Answered by Accept or Reject, whose object names the Roam, and ended by Undo from either side:

```json
{ "type": "Accept", "actor": "https://a.example/actor", "object": { "type": "Roam", "id": "https://b.example/activities/123", "node": "c0ffee01" },
  "result": { "expires": "2026-10-06T12:00:00Z", "days": 3, "publicKey": "<base64 Curve25519 public key of the roamer>" } }
{ "type": "Reject", "actor": "https://a.example/actor", "object": { "type": "Roam", "id": "https://b.example/activities/123", "node": "c0ffee01" },
  "result": { "code": "HR", "text": "node not enrolled" } }
{ "type": "Undo", "actor": "https://a.example/actor", "object": { "type": "Roam", "node": "c0ffee01" } }
```

The Accept result carries the roamer's public key, which the home server vouches for and the visited server accepts only if its CRC-32 equals the node number. This is an addition to the earlier draft. A server holding a registration is told to forget it by Undo when the roamer is heard at home or the registration expires.

### Relay (either direction)

```json
{
  "type": "Relay",
  "actor": "https://b.example/actor",
  "object": { "node": "c0ffee01", "direction": "up", "kind": "sealed", "ch": "01", "ctr": 7, "part": "1/2", "data": "<base64url ciphertext and tag>" }
}
```

Kind `sealed` carries one part of sealed traffic (`ch` and `part` are additions to the earlier draft's example, needed to rebuild the on-air message). Kind `packet` (down only) carries a complete pre-encrypted MeshPacket in `packet` for downlink as is, the fallback for stock apps. A visited server relays down only for an accepted registration whose home server is the sender, and relays up only for the registration it holds.

### Introduce, Rename and link-up

```json
{ "type": "Introduce", "actor": "https://a.example/actor",
  "object": { "servers": [ { "actor": "https://c.example/actor", "homeTag": "9d2f01aa", "lastHeard": "2026-10-02T08:00:00Z" } ] } }

{ "type": "Rename", "actor": "https://b.example/actor",
  "object": { "oldTag": "4be10c77", "newTag": "4be10c78", "server": "https://b.example/actor" } }
```

- Introduce: sent on first contact with another server, then once a day, at most 100 entries. A receiver fetches each listed server's actor and confirms it answers before adding it; the tag published on the actor wins over the listed one. Fetching is done in the background and limited to four at once.
- Rename: accepted only if signed and sent by the server already known as holding the old tag, naming itself. A Rename for a tag the receiver never knew is acknowledged without effect if the receiver already holds the new tag.
- Admin link-up: the admin enters the other server's address; the server fetches its actor, sends a standard Follow (object is the target's actor URL); the other server accepts with an Accept naming the Follow unless the sender is blocked (silent), with no second-admin approval; both then send Introduce. Undo of the Follow ends the link and forgets a server linked by hand.

## 6. Security notes

- Signing relies on firmware 2.8 XEdDSA signatures on broadcasts. A signed broadcast binds sender, packet ID, destination, port number, request and reply IDs, emoji, the bitfield and the payload, but nothing time-based, hence the packet ID memory above.
- A node's number is the CRC-32 of its public key. CRC-32 is not collision resistant, so a key pair can be ground to match a chosen node number with about 2 to the 32 attempts, which is feasible. The registry therefore binds the full key to the number and refuses a different key. This also affects the firmware's own first-contact trust and is for the independent review and the Meshtastic project to consider.
- A signed registration broadcast names the home community but not the visited one, so a recorded broadcast can be replayed at a different visited server. The home server's packet ID memory accepts it only once, so an attacker who wins the race between the legitimate visited gateway and their own could redirect one registration to a server of their choosing. The consequence is denial of service for that roamer (sealed traffic stays unreadable), not disclosure. A proposed fix is to include the visited server's tag in the signed message; that changes a decided format and is listed for review in the design notes, not applied.
- Enrolment DMs are PKI direct messages encrypted to the server's own key. They are uplinked only with MQTT encryption on.
- No forward secrecy for sealed traffic if a home channel key later leaks. Retention is an admin-set limit per channel (stored by the reference server, not yet enforced because it keeps no message history); admins are responsible for data protection compliance such as UK GDPR. Not legal advice.
- The roamer's status messages and the sealed parts are broadcasts on the roaming channel, so anyone holding the public InterRoam key can read the status text, see that a node is roaming and where, and see the sealed parts (not read them).
- Gateways never see one another's uplink: the broker enforces per-gateway credentials and delivers a gateway only what the server chooses to send it.

## 7. Open items

- App behaviour, none of which was checked: whether apps show a broadcast text on the InterRoam channel that names the node, shared contact import and manual entry of a node ID and key in stock apps, and whether a roaming-aware app exists or who builds it.
- Real on-air behaviour: nothing has run on hardware. Sealed message capacity and beacon airtime are computed, not measured.
- Whether LOCAL_ONLY and KNOWN_ONLY rebroadcast modes also stop a downlinked packet (only NONE and the mute role were checked).
- Whether a gateway accepts a downlinked NodeInfo from a node it does not know and whether a node verifies the server's signed beacon after learning its key; the code was read but nothing was run.
- Whether the chosen Go libraries support the custom activities was settled by writing the ActivityPub layer from the standard library; no ActivityPub library is used.
- Independent cryptography review (the sealing scheme and key derivation); InterRoam name clash check; encryption rules in licensed amateur mode and other legal and regional questions (not legal advice).
- Final wording and field order for beacon and refusal messages; the notification text after a tag rename; whether a hand-made server link is marked differently in the console; whether to use the firmware's Mesh Beacon module.
- Persisting queued deliveries across restarts; enforcing channel retention; crossing federated and public channels to other servers and the public broker.
- Contact with the Meshtastic project, and moving the spec to their repository if they adopt it.

## 8. Firmware facts this draft rests on (read from source)

Read on 3 and 4 October 2026 from the revisions named at the top. Files are under `src/` in the firmware repository. v2.8.1 and develop agree on all of these.

- Uplink topic is `<root>/2/e/<channel>/<gateway id>` with the channel `PKI` for PKI direct messages (`mqtt/MQTT.cpp`). Uplink queue 16 entries, drops the oldest. One server address per node. Client ID is the node ID.
- Downlink accepts a packet only if its channel ID equals a configured channel name exactly and downlink is on; own packets are ignored; decoded payloads are ignored when MQTT encryption is on; admin packets are ignored. A downlinked PKI message is enqueued only if addressed to the gateway or both nodes are in its node database.
- A downlinked packet is rebroadcast like any received packet if its hop limit is above zero, it is not to or from the gateway, its next hop is unset, its destination is not the no-LoRa broadcast address, and the gateway's role is not CLIENT_MUTE with rebroadcast mode not NONE (`mesh/NextHopRouter.cpp`, `mesh/FloodingRouter.cpp`).
- Channel crypto: AES-CTR; IV is packet ID (8 bytes little-endian), sender node number (4 bytes little-endian) and four zero bytes. Channel hash is the XOR of the name bytes and key bytes (further XOR 0xAE for AEAD channels). The default key and shorthand rules are in section 2 (`mesh/Channels.cpp`, `mesh/CryptoEngine.cpp`). A per-channel `use_aead` setting exists; this draft does not use it.
- PKI direct messages: key is SHA-256 of the X25519 shared secret; AES-CCM with an 8-byte tag and a 13-byte nonce made of packet ID, an extra nonce and the sender number; on the wire ciphertext, tag, then the 4-byte extra nonce (12 bytes overhead). The firmware's own test vector is reproduced by the reference code.
- A channel-encrypted text message addressed to the receiving node is rejected by a node that is not licensed (`mesh/Router.cpp`, "Rejecting legacy DM"). A received packet is uplinked by a gateway only if it decodes with a held channel, or is an undecodable direct message with header channel byte 0 not addressed to the gateway and MQTT encryption is on.
- Signing: described in sections 2 and 6. The signed buffer is version 0x01, then little-endian from, packet ID, to, port number, request ID, reply ID, emoji, bitfield, a flags byte, then the payload. Verification is plain Ed25519 against the sender's Curve25519 key converted to Ed25519 with the sign bit zero. The reference code was checked in both directions against the firmware's pinned Crypto library (meshtastic/Crypto commit 1c817c2f27aa4593e07d0f7e13b3dbf8d980bcae) built natively.
- Receivers verify only against a key they already hold, except that a NodeInfo whose node number is the CRC-32 of its key and whose signature verifies bootstraps the key. The default policy is COMPATIBLE.
- Packet IDs have a rolling 10-bit counter and 22 fresh random bits, so a recorded ID is not a collision risk.
- Node fields: long name 40 bytes, short name 5 bytes; there is no free-form field for a home tag.
- Not read: the Android and Apple apps.
