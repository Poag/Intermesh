# XEdDSA cross-check harness

`xeddsa_harness.cpp` drives the real Meshtastic Crypto library so the Go XEdDSA code can be checked against it in both directions. It is only a test aid and is not part of the server.

Build (the library is pinned by the firmware at commit 1c817c2f27aa4593e07d0f7e13b3dbf8d980bcae of https://github.com/meshtastic/Crypto, as read from the firmware's `variants/esp32/esp32.ini` on 3 Oct 2026):

    git clone https://github.com/meshtastic/Crypto && cd Crypto
    git checkout 1c817c2f27aa4593e07d0f7e13b3dbf8d980bcae
    cp /path/to/testdata/xeddsa_harness.cpp /path/to/testdata/rngstub.cpp .
    g++ -std=c++17 -O1 -I. -Iutility -include stdint.h -include stddef.h -include string.h \
        xeddsa_harness.cpp rngstub.cpp XEdDSA.cpp Ed25519.cpp Curve25519.cpp BigNumberUtil.cpp SHA512.cpp Crypto.cpp Hash.cpp \
        -o harness

Run the Go cross-test with `INTERMESH_XEDDSA_HARNESS=/path/to/harness go test ./internal/meshcrypto -run Harness`. Without the variable the test is skipped. `rngstub.cpp` replaces the library's random number generator with a constant, which is acceptable only because the harness never generates keys.
