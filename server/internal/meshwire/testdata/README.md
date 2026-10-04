# nanopb cross-check harness

`nanopb_harness.cpp` drives the Meshtastic firmware's own protobuf code, so the Go codec in this package can be checked against what the firmware really encodes and decodes.

Pinned as the firmware pins it (read from `platformio.ini` on 4 Oct 2026): nanopb 0.4.9.2 (tag 0.4.92, commit 160d4f09e5fabb2b66aa2dea32d4f38ace2c4b3f), `-DPB_ENABLE_MALLOC=1 -DPB_VALIDATE_UTF8=1`, and the generated types in `src/mesh/generated` of the firmware repository (develop commit 3fdc613d7b8358355b5a8d8460618caa4e164461).

Build, with `$FW` the firmware checkout and `$NB` the nanopb checkout:

    mkdir b && cd b
    for f in $FW/src/mesh/generated/meshtastic/*.pb.cpp; do
      g++ -std=c++17 -c -DPB_ENABLE_MALLOC=1 -DPB_VALIDATE_UTF8=1 -I$NB -I$FW/src/mesh/generated $f -o $(basename $f .cpp).o
    done
    for f in pb_common pb_encode pb_decode; do gcc -c -DPB_ENABLE_MALLOC=1 -DPB_VALIDATE_UTF8=1 -I$NB $NB/$f.c -o $f.o; done
    rm -f deviceonly*.o        # these need callbacks that only exist inside the firmware
    g++ -std=c++17 -DPB_ENABLE_MALLOC=1 -DPB_VALIDATE_UTF8=1 -I$NB -I$FW/src/mesh/generated \
        /path/to/nanopb_harness.cpp *.o -o harness

Run: `INTERMESH_NANOPB_HARNESS=/path/to/b/harness go test ./internal/meshwire`. Without the variable the test is skipped.
