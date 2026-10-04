# Roaming message format proposal (sketch)

Status: sketch for discussion, written 4 October 2026. This is the "optimal method" mentioned at the top of [SPEC.md](SPEC.md). Nothing here is implemented, nothing has been proposed to the Meshtastic project, and none of it has been tried on hardware or in an app. Names, field numbers and sizes are illustrations. Facts about the firmware are marked with the file they were read from; everything else is a proposal or unverified.

"Suggested" in this document means proposed and open for comment.

## 1. Why a new format

The minimal change method in the main spec runs entirely on stock firmware, and that costs it three things:

1. **Keys arrive by side channels.** A node's public key never appears in a channel packet. The visited server only learns it if the node was heard sending a NodeInfo on a channel the server holds, and a member's node only learns the server's key from a shared contact or a heard NodeInfo (section 8 of the spec). Enrolment therefore has a hidden precondition, and the visited server must then vouch for the key to the home server on trust.
2. **Everything is text.** Registration, status and sealed traffic are short lines of text with separators, inside a text-message port. Sealed bytes are encoded into text, which costs capacity, and the lines have to be parsed out of chat.
3. **Replies are broadcasts.** The firmware drops a channel-encrypted text message addressed to a node that is not licensed (`mesh/Router.cpp`, "Rejecting legacy DM"), so server replies go out as broadcasts that name the roamer. That spends airtime for everyone on the roaming channel and makes status text public.

A dedicated format on its own port number can fix all three. The rest of this document sketches one.

## 2. What is already true in the firmware (read from source, firmware `develop` at 3fdc613d)

- The legacy DM rejection applies only to the text message port: the condition is `!owner.is_licensed && isToUs(p) && portnum == TEXT_MESSAGE_APP` (`mesh/Router.cpp`, around line 1078). A channel-encrypted packet on another port addressed to a node is not rejected by that rule. Whether anything else on the receive path would drop it was not traced.
- The Data message carries a port number, a payload of bytes and routing fields; ports 256 to 511 are reserved for private use, and `PRIVATE_APP` is 256 (`meshtastic/portnums.proto` at protobufs commit 95c5f8c1). A permanent port would have to be allocated by the Meshtastic project. Port 37 is already the Mesh Beacon module.
- A signed broadcast must fit 239 bytes of Data including a 66-byte signature field, and the signed buffer covers sender, packet ID, destination, port, request and reply IDs, emoji, bitfield, a flags byte and the payload (section 6 of the spec, confirmed against the firmware's Crypto library).
- A node's number is the CRC-32 of its public key; a NodeInfo whose number matches and whose signature verifies bootstraps the key (`mesh/NodeDB.cpp`, `mesh/Router.cpp`).
- Whether stock firmware silently ignores a channel packet on a port it has no module for, and whether the mobile apps can send an arbitrary port, were not checked. See section 8.

## 3. Idea in one paragraph

Put roaming on its own port, with a small protobuf payload. The roamer's registration carries the roamer's own public key and is signed by the roamer's mesh key. The visited server can verify that registration alone (key matches the node number by CRC-32, signature verifies against that key) with no earlier NodeInfo. It then forwards the **evidence**, meaning the signed packet's fields, to the home server, which checks the roamer's signature itself instead of trusting the visited server. The server's own key and node number travel in its offer message, so nodes can learn it from the air as well as from a contact. Replies and sealed downlink are addressed to the node on the new port, not named inside a broadcast text.

## 4. Message types (sketch)

One port, one outer message with a version and a body, so the format can grow:

```
message InterRoam {
  uint32 version = 1;            // 1
  oneof body {
    Offer    offer    = 2;       // server -> everyone, replaces the text beacon
    Register register = 3;       // roamer -> visited server
    Status   status   = 4;       // visited server -> roamer
    Sealed   sealed   = 5;       // either direction, both ways
  }
}
```

- **Offer** (server broadcast, signed): the server's mesh node number and public key, community tag, registration policy, roaming channel name and the radio settings a roamer would need (region, preset, slot), and optionally the open flag. Replaces the `MFB1 B` text beacon and carries the key that today needs a shared contact. A receiving app could show "join this community" with the key already attached. The firmware's Mesh Beacon module (port 37) already advertises a channel offer with radio settings; whether this offer should ride on that port instead is an open question (section 8).
- **Register** (roamer to visited server, signed broadcast on the roaming channel): home tag, days, the visited server's tag (this puts the target under the signature), the roamer's **public key**, and a nonce. Its size is the key (32 bytes plus tag and length) plus a few short fields, comfortably inside the signed budget (section 5).
- **Status** (visited server to roamer): accepted with an expiry, or a refusal code from the existing code list. Addressed to the node.
- **Sealed**: node, registration counter, home channel index, part and total, and the ciphertext as raw bytes. The sealing scheme (HKDF and ChaCha20-Poly1305 with the replay window) stays as designed; only the carrier changes.

## 5. Size estimate (computed, not measured)

The signed budget today is 166 bytes of text per line (`mfb.BroadcastLineBudget`), which is 239 bytes of signed Data minus the 66-byte signature field minus about 6 bytes of Data fields. A binary payload gets roughly the same 166 bytes. A Register message with a 34-byte key field and a handful of short fields should come to well under 100 bytes, so it fits signed with room to spare. A Sealed part needs a header for node, counter, channel and part numbers plus the 16-byte authentication tag, which Claude estimates at 35 to 40 bytes, leaving roughly 125 to 130 bytes of ciphertext against 78 bytes of text per part today, because the bytes no longer pass through a text encoding. Treat these as rough: they depend on the final field numbers and have not been run through the codec.

## 6. How keys travel through the servers

1. The roamer sends **Register**. The visited server checks: the sender's node number equals the CRC-32 of the key inside the message, and the packet's XEdDSA signature verifies against that key. It now holds an authenticated key for that node without a NodeInfo.
2. The visited server sends the home server a Roam activity carrying the roamer's key and the signed fields (sender, packet ID, destination, port, the payload bytes and the signature). The home server rebuilds the signed buffer and verifies the roamer's signature itself. The visited server cannot forge a registration, and a compromised or careless visited server can at worst fail to forward one.
3. The home server accepts only if the key matches the one it holds for that node (the registry is keyed on the full key, not the node number), or enrols it if the community policy allows.
4. The home server's Accept reaches the visited server over the existing server-to-server channel; the visited server tells the roamer with **Status**. If the roamer's node holds the visited server's key from the Offer, the Status could be a PKI message in future, otherwise a channel-encrypted unicast on the new port.

This removes the shared-contact and heard-NodeInfo preconditions on the server side, and it moves the trust decision from "the visited server says so" to "the roamer's own signature says so."

Limits that remain: the CRC-32 binding between key and node number is weak (about 2 to the 32 attempts to grind a key for a chosen number), so accepting a key announced on the air is trust on first use. For a community that wants stronger assurance, the shared contact link or a QR code stays as an out-of-band way to pin the server's key. This is for the independent cryptography review.

## 7. What it needs from others

- **Meshtastic project:** a port number, and agreement that this belongs in the protocol. Until then the format could run on `PRIVATE_APP` (256) for trials.
- **Nodes:** possibly nothing. If apps can send an arbitrary port and stock firmware relays it, the roamer's app builds and signs nothing itself beyond handing a packet to the node; the node does the signing as it does for any broadcast. If the app cannot, a small firmware module would be needed. Not checked.
- **Apps:** a screen to enter the home tag, show the Offer, and show Status. Without app support a roamer cannot use this at all, which is the main cost compared with the minimal method, where a roamer can type a text line into any app.
- **Gateways:** nothing new beyond the existing gateway requirements, since a downlinked packet on any port is rebroadcast the same way (`mesh/FloodingRouter.cpp`); the Ignore MQTT and duty-cycle constraints in section 8 of the spec apply unchanged.

## 8. Open questions (all unverified)

- Whether stock firmware drops, relays or logs a channel packet on a port it has no module for.
- Whether the Android and Apple apps can send an arbitrary port, and what they show for one they do not know.
- Whether a unicast on a new port is relayed and delivered normally for a non-licensed destination (the legacy DM rule is port-specific, but nothing else on the path was traced).
- Whether the Offer should reuse the Mesh Beacon module and its port or have its own.
- Whether to fold the visited server's tag into the signed registration of the current text format as well.
- Coexistence: servers would advertise support in the Offer and keep accepting the `MFB1` text lines, so unmodified nodes can still roam on the minimal method. How long to keep both is open.
- Independent cryptography review of the key-announcement and evidence-forwarding steps.
- Regional and licensed-mode legal questions for encrypted traffic (not legal advice).

## 9. Suggested path

1. Build the minimal method and try it on two gateways (the spec as written).
2. Prototype the new format on `PRIVATE_APP` in the reference server and the simulated node, behind the Offer's version field, so the two can be compared on size and on how much of the enrolment preconditions disappear.
3. If it holds up, take the comparison and a port request to the Meshtastic project.
