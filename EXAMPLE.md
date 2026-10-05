# Example: a visitor from the US in the Midlands

A worked example of how Intermesh is suggested to be used, using the minimal change method in [SPEC.md](SPEC.md). Names, tags and node IDs are made up. Everything here is a design walk-through: **nothing in it has been tried on real nodes, on the air, or in the mobile apps**, and one piece (the app that sends and reads the sealed messages) does not exist yet. Steps marked "check" depend on things the spec lists as open.

## The people

- **Sam** lives in Austin, Texas and belongs to the Austin community mesh. Austin runs its own Intermesh server (home tag `9f3a07c2`, shown here as an example).
- **The Midlands mesh** is a community in England that also runs a server, and has a border node (an ordinary gateway) in Birmingham. The two servers have been introduced to each other by their admins.
- Sam is visiting for a week and would like to keep up with the Austin channel and be known on the local mesh, without carrying a laptop or a second set of keys.

## Before leaving home

1. **Enrol with the Austin server.** Sam imports the Austin server's contact link (the admin shares it as a QR code or a link) into the Meshtastic app, then sends one enrolment message to the server from the node. Depending on how the Austin admin runs things, that is open enrolment, a pre-shared passphrase, or approval by the admin. The Austin server also needs to have heard Sam's node announce itself once on an Austin channel before it can read the enrolment. This is a one-off.
2. **Check the node.** Firmware 2.8 or later (it signs the registration), and OK to MQTT turned on, or the Midlands gateway will not pass the registration on.
3. **Get the home tag** from the Austin admin (8 characters, here `9f3a07c2`).
4. **Check the hardware for the trip.** The UK uses the 868 MHz band, the US 915 MHz. Whether Sam's board can run on 868 depends on the board variant, which is not something Intermesh can change (check the board before travelling).

## Arriving in the Midlands

5. **Match the local radio settings.** Sam sets the node's region to EU_868 (which covers the UK) and the modem preset and frequency slot the Midlands mesh uses, which the Midlands admin publishes (check: whether the beacon can carry them is an open item). Two firmware behaviours matter here: setting that region turns **Ignore MQTT on by default**, and Sam must turn it **off** or the node will discard what the gateway relays; and the region's duty-cycle limit applies to everything Sam's node sends.
6. **Add the roaming channel.** One extra channel named `InterRoam` using the firmware's default key (the shorthand key value 1), position sharing off. Every Intermesh community uses the same channel, which is why it is public by design.
7. **Register.** Sam sends one line on the InterRoam channel:

   `MFB1 R 9f3a07c2 7`

   That means "I am a member of community 9f3a07c2; register me here for 7 days". The firmware signs it with Sam's node key. An unsigned one is refused.
8. **Wait for the answer.** The Midlands server forwards the signed packet to Austin, whose server checks the signature and that Sam is enrolled. If it accepts, the Midlands server broadcasts a short signed line on InterRoam naming Sam's node, for example `MFB1 C a1b2c3d4 9f3a07c2 7 Austin`. If not, a line starting `MFB1 X` and a two-letter code says why (for instance `CL` the community is closed, `NS` no free slots, `HR` Austin refused). Until Austin accepts, the Midlands server relays nothing.

## What Sam gets

- **The Austin channel, sealed.** Messages posted on Austin's channel are delivered to Sam on InterRoam, encrypted so that the Midlands server and anyone in radio range cannot read them, and Sam's replies are posted to the Austin channel by the Austin server, labelled with Sam's node ID. The Midlands server never holds Austin's keys.
- **No key sharing.** Sam hands over no channel keys and no passwords to Midlands.
- **Control for both admins.** Midlands decides how many visitors it takes and can refuse; Austin decides who counts as a member and can refuse. The registration lapses after at most a week, or sooner when Sam is heard back on the Austin mesh.

## What it does not give Sam (today)

- **Reading and writing sealed messages needs a roaming-aware app, which does not exist yet.** With the standard apps Sam can send the registration line and read the confirmation as an ordinary chat message on the InterRoam channel, but cannot read the sealed Austin messages. How the standard apps display the confirmation text was not checked.
- Each sealed message part carries about 78 characters, up to 3 parts by default, with no retransmission, so long messages are cut and a lost part is a gap (computed, not measured on the air).
- Everyone in range of the Midlands gateway can see that Sam registered and that sealed traffic is flowing, though not what it says.
- Nothing here covers direct messages between Sam and other Austin members, or Midlands members reaching Sam.
- It depends on the Midlands gateway being set up as the spec describes (not a mute role, Ignore MQTT off, channel named exactly `InterRoam`).

## Without Intermesh

Sam would be an unknown node on the Midlands mesh with no route to Austin's channels short of handing Austin's channel keys to Midlands, which is exactly what this design avoids. With the proposed new roaming format ([ROAMING-FORMAT.md](ROAMING-FORMAT.md)) the registration step would also carry Sam's key, so the visited server would not need to have heard Sam's node first; that needs firmware and app changes and is not designed in detail.
