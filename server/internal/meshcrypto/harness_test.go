package meshcrypto

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func runHarness(t *testing.T, bin string, args ...string) map[string]string {
	t.Helper()
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		t.Fatalf("harness: %v", err)
	}
	m := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[k] = v
		}
	}
	return m
}

// Cross-checks the Go XEdDSA code against the firmware's own library, built from
// testdata (see testdata/README.md). Skipped unless INTERMESH_XEDDSA_HARNESS names the binary.
func TestXEdDSAAgainstFirmwareLibraryHarness(t *testing.T) {
	bin := os.Getenv("INTERMESH_XEDDSA_HARNESS")
	if bin == "" {
		t.Skip("INTERMESH_XEDDSA_HARNESS not set")
	}
	for i := 0; i < 50; i++ {
		priv := make([]byte, 32)
		z := make([]byte, 32)
		rand.Read(priv)
		rand.Read(z)
		msg := make([]byte, 1+i*5)
		rand.Read(msg)
		pub, _ := PublicKey(priv)
		goEd, _ := CurveToEdPublic(pub)

		// firmware signs, Go checks key conversion and verifies
		h := runHarness(t, bin, "sign", hex.EncodeToString(priv), hex.EncodeToString(z), hex.EncodeToString(msg))
		if h["edpub"] != hex.EncodeToString(goEd) {
			t.Fatalf("iteration %d: firmware public key %s, Go %x", i, h["edpub"], goEd)
		}
		sig, _ := hex.DecodeString(h["sig"])
		if !verifyRaw(goEd, msg, sig) {
			t.Fatalf("iteration %d: Go rejected a firmware signature", i)
		}

		// Go signs, firmware verifies
		gsig, _ := signRaw(priv, msg, z)
		v := runHarness(t, bin, "verify", hex.EncodeToString(goEd), hex.EncodeToString(gsig), hex.EncodeToString(msg))
		if v["verify"] != "1" {
			t.Fatalf("iteration %d: firmware rejected a Go signature", i)
		}
		gsig[10] ^= 0x01
		v = runHarness(t, bin, "verify", hex.EncodeToString(goEd), hex.EncodeToString(gsig), hex.EncodeToString(msg))
		if v["verify"] != "0" {
			t.Fatalf("iteration %d: firmware accepted a corrupted signature", i)
		}
	}
}
