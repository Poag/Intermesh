// Drives the firmware's own protobuf code (nanopb plus the generated meshtastic types) so the Go
// codec can be checked against what the firmware would actually encode and decode.
// Commands (hex in, key=value lines out):
//   envdec HEX                      decode a ServiceEnvelope
//   envenc FROM TO CHANNEL ID HOPLIMIT HOPSTART PKI ENCRYPTEDHEX CHANNELID GATEWAYID
//   datadec HEX                     decode a Data
//   dataenc PORT PAYLOADHEX BITFIELD SIGHEX   (BITFIELD -1 for absent, SIGHEX "-" for none)
//   userdec HEX | userenc ID LONG SHORT KEYHEX
//   contactdec HEX | contactenc NODE ID LONG SHORT KEYHEX
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <pb_encode.h>
#include <pb_decode.h>
#include "meshtastic/mesh.pb.h"
#include "meshtastic/mqtt.pb.h"
#include "meshtastic/admin.pb.h"

static std::vector<uint8_t> unhex(const char *s) {
    std::vector<uint8_t> v;
    if (!strcmp(s, "-")) return v;
    for (size_t i = 0; s[i] && s[i + 1]; i += 2) { char b[3] = {s[i], s[i + 1], 0}; v.push_back((uint8_t)strtol(b, nullptr, 16)); }
    return v;
}
static void phex(const char *k, const uint8_t *b, size_t n) { printf("%s=", k); for (size_t i = 0; i < n; i++) printf("%02x", b[i]); printf("\n"); }

static void printData(const meshtastic_Data &d) {
    printf("portnum=%d\npayload_size=%u\n", (int)d.portnum, (unsigned)d.payload.size);
    phex("payload", d.payload.bytes, d.payload.size);
    printf("want_response=%d\ndest=%u\nsource=%u\nrequest_id=%u\nreply_id=%u\nemoji=%u\nhas_bitfield=%d\nbitfield=%u\nsig_size=%u\n",
           d.want_response, d.dest, d.source, d.request_id, d.reply_id, d.emoji, d.has_bitfield, d.bitfield, (unsigned)d.xeddsa_signature.size);
}

int main(int argc, char **argv) {
    std::string m = argc > 1 ? argv[1] : "";
    static uint8_t out[1024];
    if (m == "envdec") {
        auto in = unhex(argv[2]);
        meshtastic_ServiceEnvelope e = meshtastic_ServiceEnvelope_init_zero;
        pb_istream_t s = pb_istream_from_buffer(in.data(), in.size());
        bool ok = pb_decode(&s, &meshtastic_ServiceEnvelope_msg, &e);
        printf("ok=%d\n", ok);
        if (!ok) { printf("error=%s\n", PB_GET_ERROR(&s)); return 0; }
        printf("channel_id=%s\ngateway_id=%s\n", e.channel_id ? e.channel_id : "(null)", e.gateway_id ? e.gateway_id : "(null)");
        if (e.packet) {
            meshtastic_MeshPacket &p = *e.packet;
            printf("from=%u\nto=%u\nchannel=%u\nid=%u\nhop_limit=%u\nhop_start=%u\nwant_ack=%d\nvia_mqtt=%d\npki_encrypted=%d\nnext_hop=%u\nrelay_node=%u\nvariant=%s\n",
                   p.from, p.to, p.channel, p.id, p.hop_limit, p.hop_start, p.want_ack, p.via_mqtt, p.pki_encrypted, p.next_hop, p.relay_node,
                   p.which_payload_variant == meshtastic_MeshPacket_encrypted_tag ? "encrypted" : "decoded");
            if (p.which_payload_variant == meshtastic_MeshPacket_encrypted_tag) { printf("enc_size=%u\n", (unsigned)p.encrypted.size); phex("enc", p.encrypted.bytes, p.encrypted.size); }
            else printData(p.decoded);
            printf("public_key_size=%u\n", (unsigned)p.public_key.size);
        }
    } else if (m == "envenc") {
        meshtastic_MeshPacket p = meshtastic_MeshPacket_init_zero;
        p.from = strtoul(argv[2], 0, 10); p.to = strtoul(argv[3], 0, 10); p.channel = atoi(argv[4]); p.id = strtoul(argv[5], 0, 10);
        p.hop_limit = atoi(argv[6]); p.hop_start = atoi(argv[7]); p.pki_encrypted = atoi(argv[8]) != 0;
        auto enc = unhex(argv[9]);
        p.which_payload_variant = meshtastic_MeshPacket_encrypted_tag;
        p.encrypted.size = enc.size(); memcpy(p.encrypted.bytes, enc.data(), enc.size());
        meshtastic_ServiceEnvelope e = meshtastic_ServiceEnvelope_init_zero;
        e.packet = &p; e.channel_id = argv[10]; e.gateway_id = argv[11];
        pb_ostream_t s = pb_ostream_from_buffer(out, sizeof(out));
        if (!pb_encode(&s, &meshtastic_ServiceEnvelope_msg, &e)) { printf("error=%s\n", PB_GET_ERROR(&s)); return 0; }
        phex("bytes", out, s.bytes_written);
    } else if (m == "datadec") {
        auto in = unhex(argv[2]);
        meshtastic_Data d = meshtastic_Data_init_zero;
        pb_istream_t s = pb_istream_from_buffer(in.data(), in.size());
        bool ok = pb_decode(&s, &meshtastic_Data_msg, &d);
        printf("ok=%d\n", ok);
        if (ok) printData(d); else printf("error=%s\n", PB_GET_ERROR(&s));
    } else if (m == "dataenc") {
        meshtastic_Data d = meshtastic_Data_init_zero;
        d.portnum = (meshtastic_PortNum)atoi(argv[2]);
        auto pl = unhex(argv[3]); d.payload.size = pl.size(); memcpy(d.payload.bytes, pl.data(), pl.size());
        int bf = atoi(argv[4]); if (bf >= 0) { d.has_bitfield = true; d.bitfield = bf; }
        auto sig = unhex(argv[5]); d.xeddsa_signature.size = sig.size(); memcpy(d.xeddsa_signature.bytes, sig.data(), sig.size());
        size_t size = 0; pb_get_encoded_size(&size, &meshtastic_Data_msg, &d);
        pb_ostream_t s = pb_ostream_from_buffer(out, sizeof(out));
        if (!pb_encode(&s, &meshtastic_Data_msg, &d)) { printf("error=%s\n", PB_GET_ERROR(&s)); return 0; }
        printf("size=%u\n", (unsigned)size); phex("bytes", out, s.bytes_written);
    } else if (m == "userdec") {
        auto in = unhex(argv[2]);
        meshtastic_User u = meshtastic_User_init_zero;
        pb_istream_t s = pb_istream_from_buffer(in.data(), in.size());
        bool ok = pb_decode(&s, &meshtastic_User_msg, &u);
        printf("ok=%d\n", ok);
        if (ok) { printf("id=%s\nlong_name=%s\nshort_name=%s\n", u.id, u.long_name, u.short_name); phex("public_key", u.public_key.bytes, u.public_key.size); }
        else printf("error=%s\n", PB_GET_ERROR(&s));
    } else if (m == "userenc" || m == "contactenc") {
        int o = m == "contactenc" ? 3 : 2;
        meshtastic_User u = meshtastic_User_init_zero;
        strncpy(u.id, argv[o], sizeof(u.id) - 1); strncpy(u.long_name, argv[o + 1], sizeof(u.long_name) - 1); strncpy(u.short_name, argv[o + 2], sizeof(u.short_name) - 1);
        auto k = unhex(argv[o + 3]); u.public_key.size = k.size(); memcpy(u.public_key.bytes, k.data(), k.size());
        pb_ostream_t s = pb_ostream_from_buffer(out, sizeof(out));
        bool ok;
        if (m == "userenc") ok = pb_encode(&s, &meshtastic_User_msg, &u);
        else { meshtastic_SharedContact c = meshtastic_SharedContact_init_zero; c.node_num = strtoul(argv[2], 0, 10); c.has_user = true; c.user = u; ok = pb_encode(&s, &meshtastic_SharedContact_msg, &c); }
        if (!ok) { printf("error=%s\n", PB_GET_ERROR(&s)); return 0; }
        phex("bytes", out, s.bytes_written);
    } else if (m == "contactdec") {
        auto in = unhex(argv[2]);
        meshtastic_SharedContact c = meshtastic_SharedContact_init_zero;
        pb_istream_t s = pb_istream_from_buffer(in.data(), in.size());
        bool ok = pb_decode(&s, &meshtastic_SharedContact_msg, &c);
        printf("ok=%d\n", ok);
        if (ok) { printf("node_num=%u\nhas_user=%d\nid=%s\nlong_name=%s\nshort_name=%s\n", c.node_num, c.has_user, c.user.id, c.user.long_name, c.user.short_name); phex("public_key", c.user.public_key.bytes, c.user.public_key.size); }
        else printf("error=%s\n", PB_GET_ERROR(&s));
    }
    return 0;
}
