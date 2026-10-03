# Intermesh specification (draft)

Status: draft written 3 October 2026. Field layouts, separators and codes below are proposals unless marked decided. Nothing has been tested on hardware. Firmware behaviour was read through summarising fetches and secondary sources and must be re-read from the primary source before building.

## 1. Architecture in brief

- A community server (Go, small enough for a Raspberry Pi class device) with a built-in MQTT listener (TLS when exposed to the internet) and no web interface. Members use their mesh apps; admins use an admin console.
- A border node is any ordinary gateway pointed at the server over MQTT. The server issues per-gateway MQTT credentials limited to named channels, and holds the channel keys for the channels it bridges.
- Gateways must have MQTT encryption enabled (decided). The server warns the admin in the console when a gateway looks misconfigured, for example unencrypted traffic or a channel without matching permissions, and does not message the gateway. If a gateway's permissions do not match a channel's settings, the server drops the traffic and logs an error naming the gateway and channel.
- Channel scopes: mesh only, community, federated, public. Default is the narrowest.
- Optional per-channel republishing by the server to the public MQTT broker, within scope rules. Assumes a gateway's MQTT module takes one server address (unverified).
- Servers federate with each other only, not with ordinary fediverse software (may be opened later).

## 2. Conventions for on-air messages

Every on-air message is one line of ASCII text starting `MFB1`, then a type letter, then space-separated fields. A receiver ignores any message whose tag or version it does not know.

- Node ID: 8 lowercase hex characters (no `!`).
- Home tag: 8 lowercase hex characters (32 bits), generated randomly by the home server. A server checks peers for a duplicate when it joins, and the newer server renames on a clash.
- Days: a single digit, 1 to 7. The longest registration is one week.
- Roaming channel: name `InterRoam`, firmware default key, position sharing off, uplink and downlink on at gateways. The roamer's node must use the same region, modem preset and frequency slot as the visited mesh. Secondary channels ignore their own radio settings and the frequency slot comes from the primary channel's name unless set explicitly, so roamers on meshes with different primary names must set the slot by hand.
- Size budget (estimate): a signed packet must satisfy canonical size + 66 + 16 within 239 bytes, leaving about 150 bytes of text. Unverified.

## 3. On-air messages

### Beacon (server, downlinked to the roaming channel, signed by the server)

`MFB1 B <tag> <node> <state> <slots> <days>`

- tag: the community's home tag. node: the server's own node ID, target for enrolment DMs (each server has its own, there is no fixed ID). state: `O` open or `C` closed to new roamers. slots: free roaming slots, decimal. days: default registration period.
- Off by default. The admin sets an interval, or a "new node detected" trigger, and a minimum gap between beacons. Example: `MFB1 B 9f3a07c2 a1b2c3d4 O 12 3`. A receiver ignores a beacon not signed by the node ID it names.

### Roaming broadcast (roamer, signed by firmware 2.8)

`MFB1 R <hometag> <days>`

- `-` for days means the community's default. Unsigned registrations are refused; firmware 2.8 is required. The roamer's node needs OK to MQTT on or gateways will not uplink it.

### Enrolment DM (member to server)

`MFB1 E <psk>`

- A PKI direct message to the server contact (node ID and public key, shared by the admin as a Meshtastic shared contact if apps support it; manual entry of both is the documented fallback). `-` for public enrolment or a request awaiting manual approval. Otherwise the PSK itself. Replies, also DMs: `MFB1 K` enrolled, `MFB1 P` pending admin approval, or a refusal.
- Enrolment modes (admin chooses): public; PSK by DM; manual (PSK or a console checkbox). PSK types: non-expiring, rotating (admin-set period, default 7 days; only the current PSK is accepted after rotation), single-use, multi-use with expiry. The admin shares PSKs out of band. Revoking a PSK stops new enrolments but keeps enrolled nodes; admins remove nodes individually.
- The registry stores each node's number and public key. Risk: with public enrolment, whoever enrols a node number first binds their key to it.

### Registration confirmation (visited server to roamer, DM)

`MFB1 C <tag> <days> <name>`

- Name is last, may contain spaces, set by the admin (proposed limit 24 characters).

### Refusal notice (DM, states the reason, admin may add text)

`MFB1 X <code> [free text]`

- CL community closed; NS no free slots; BL home server blocked by this community; US registration not signed (firmware 2.8 required); UH home server unknown or unreachable; HR home server refused; RP repeated registration; BF malformed message; EP enrolment PSK invalid, expired or used; EC enrolment closed.

### Sealed traffic (home server and the roamer's roaming-aware app)

`MFB1 S <node> <ch> <ctr> <part> <data>`

- node: roamer's node ID. ch: 2-hex home channel number. ctr: per-direction counter in hex, advanced for every part, also the nonce. part: such as `2/3`, `1/1` when it fits one packet. data: ciphertext plus 16-byte tag, base64url.
- Keys: for each registration and home channel, two keys by HKDF-SHA256 from the home channel key, with the home tag, node number, accepted registration packet ID and channel name as context and a direction label. Authenticated cipher (ChaCha20-Poly1305 or AES-GCM). The visited server never holds the keys. Pending independent cryptography review.
- Capacity is about 75 bytes of text per packet (estimate). Long messages are split into numbered parts. The admin sets the maximum parts (default 3). A missing part is dropped after an admin-set wait (default 2 minutes) and the app shows a gap. No retransmission.

## 4. Roaming rules (decided)

- The visited server relays nothing until the home server accepts.
- The home server verifies the signed packet the visited server forwards, checks enrolment, and remembers accepted registration packet IDs for one week plus an admin-set margin, rejecting repeats.
- Slots are concurrent accepted registrations, set by the admin; pending registrations take no slot. Admin-set rate limits per node ID and per home tag.
- Registration ends early when the roamer is heard at home. If a roamer is registered with two communities, the home server replies through whichever relayed last.
- The home server notifies members by DM after a tag rename.

## 5. Server-to-server

Delivery uses ActivityPub with RFC 9421 HTTP message signatures. Standard Follow, Accept, Reject and Undo are reused where they fit. The extension context is published from this repository at [context/v1.jsonld](context/v1.jsonld). The URL in the examples assumes the repository's default branch is `main` and that the file is merged there (unverified; to be re-checked once the branch exists). The context file is a first draft of term definitions and has not been tested with a JSON-LD processor or an ActivityPub library.

- Signed timestamp on each activity; a server rejects one older than 5 minutes (admin-changeable) and remembers recent activity IDs. Maximum activity size 64 KB (admin-changeable). Retries use growing gaps for up to 24 hours, signing each attempt afresh, then drop. Key rotation is admin-triggered: the new key is published on the actor and the old key accepted for an admin-set overlap.
- Learned servers are trusted by default; an admin can block them. Blocking is silent (the blocked server is not answered). The console shows each new server. The shared server list is capped by the admin (default 500); when full, the least recently heard is dropped.

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
    "packet": "<base64 of the signed mesh packet as received>"
  }
}
```

Answered by Accept (granted expiry in the result) or Reject (a refusal code). Undo ends a registration early from either side.

### Relay (either direction)

```json
{
  "type": "Relay",
  "actor": "https://b.example/actor",
  "object": { "node": "c0ffee01", "direction": "up", "kind": "sealed", "ctr": 7, "data": "<base64url ciphertext and tag>" }
}
```

Kind `sealed` carries sealed traffic. Kind `packet` (down only) carries a complete pre-encrypted packet for downlink as is, the fallback for stock apps.

### Introduce and Rename (proposed)

```json
{ "type": "Introduce", "actor": "https://a.example/actor",
  "object": { "servers": [ { "actor": "https://c.example/actor", "homeTag": "9d2f01aa", "lastHeard": "2026-10-02T08:00:00Z" } ] } }

{ "type": "Rename", "actor": "https://b.example/actor",
  "object": { "oldTag": "4be10c77", "newTag": "4be10c78", "server": "https://b.example/actor" } }
```

- Introduce: sent on first contact with another server, then once a day. A receiver fetches each listed server's actor and confirms it answers before adding it.
- Rename: accepted only if signed and sent by the server already known as holding the old tag.
- Admin link-up (proposed): the admin enters the other server's address; the server fetches its actor, sends a standard Follow; the other server accepts with Accept unless the sender is blocked (silent), no second-admin approval; both then send Introduce. Undo ends the link.

## 6. Security notes

- Signing relies on firmware 2.8 XEdDSA signatures on broadcasts. A signed broadcast binds sender, packet ID and payload but nothing time-based, hence the packet ID memory above.
- Enrolment DMs are PKI direct messages encrypted to the server's own key. They are uplinked only with MQTT encryption on.
- No forward secrecy for sealed traffic if a home channel key later leaks. Retention is an admin-set limit per channel; admins are responsible for data protection compliance such as UK GDPR. Not legal advice.

## 7. Open items

- Firmware and library claims need a direct read of the primary source: signature fit and survival through MQTT uplink, signing on by default in a stable 2.8, whether nodes accept a downlinked packet signed by the server, node IDs derived from the public key, whether the sender's public key arrives in an uplinked DM, queue size, shared contact import and manual entry in stock apps, default signature policy (sources disagree between balanced and compatible).
- Whether the chosen Go libraries support RFC 9421 and the custom activity types. Candidates surveyed: go-ap (MIT), go-fed/activity (BSD-3-Clause, appears archived), Mochi MQTT (MIT).
- Independent cryptography review; InterRoam name clash check; encryption rules in licensed amateur mode and other legal and regional questions (not legal advice).
- Final wording and field order for beacon and refusal messages; retry gap schedule; whether a hand-made server link is marked differently in the console.
- Contact with the Meshtastic project, and moving the spec to their repository if they adopt it.
