#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include "XEdDSA.h"
#include "Curve25519.h"

static std::vector<uint8_t> unhex(const char *s) {
    std::vector<uint8_t> v;
    for (size_t i = 0; s[i] && s[i+1]; i += 2) { char b[3] = {s[i], s[i+1], 0}; v.push_back((uint8_t)strtol(b, nullptr, 16)); }
    return v;
}
static void phex(const char *l, const uint8_t *b, size_t n) { printf("%s=", l); for (size_t i = 0; i < n; i++) printf("%02x", b[i]); printf("\n"); }

int main(int argc, char **argv) {
    // usage: sign <priv32hex> <z32hex> <msghex> | verify <edpub32hex> <sig64hex> <msghex>
    std::string mode = argv[1];
    if (mode == "sign") {
        auto priv = unhex(argv[2]); auto z = unhex(argv[3]); auto msg = unhex(argv[4]);
        uint8_t edpriv[32], edpub[32], sig[64];
        XEdDSA::priv_curve_to_ed_keys(priv.data(), edpriv, edpub);
        memcpy(sig, z.data(), 32);
        XEdDSA::sign(sig, edpriv, edpub, msg.data(), msg.size());
        phex("edpub", edpub, 32); phex("sig", sig, 64);
    } else {
        auto pub = unhex(argv[2]); auto sig = unhex(argv[3]); auto msg = unhex(argv[4]);
        printf("verify=%d\n", Ed25519::verify(sig.data(), pub.data(), msg.data(), msg.size()) ? 1 : 0);
    }
    return 0;
}
