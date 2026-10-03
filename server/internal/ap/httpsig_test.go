package ap

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"
)

// RFC 9421 appendix B.2.6 (Ed25519). The key is the RFC's test-key-ed25519.
func TestRFC9421Ed25519Vector(t *testing.T) {
	seed, _ := hex.DecodeString("9f8362f87a484a954e6e740c5b4c0e84229139a20aa8ab56ff66586f6a7d29c5")
	priv := ed25519.NewKeyFromSeed(seed)
	if got := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)); got != "JrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=" {
		t.Fatalf("public key %s", got)
	}
	req, _ := http.NewRequest("POST", "http://example.com/foo?param=Value&Pet=dog", strings.NewReader(`{"hello": "world"}`))
	req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "18")
	p := sigParams{components: []string{"date", "@method", "@path", "@authority", "content-type", "content-length"},
		created: 1618884473, keyID: "test-key-ed25519"}
	base, err := signatureBase(req, p)
	if err != nil {
		t.Fatal(err)
	}
	wantBase := "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@method\": POST\n\"@path\": /foo\n\"@authority\": example.com\n" +
		"\"content-type\": application/json\n\"content-length\": 18\n" +
		"\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\""
	if base != wantBase {
		t.Fatalf("signature base differs:\n%s", base)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(base)))
	if sig != "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==" {
		t.Fatalf("signature %s", sig)
	}
}

func newReq(t *testing.T, body string) (*http.Request, []byte) {
	t.Helper()
	req, _ := http.NewRequest("POST", "https://b.example/inbox", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/activity+json")
	return req, []byte(body)
}

func TestSignVerifyAndReplayLimit(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_800_000_000, 0)
	req, body := newReq(t, `{"type":"Roam"}`)
	if err := SignRequest(req, body, "https://a.example/actor#main-key", priv, now, "n1"); err != nil {
		t.Fatal(err)
	}
	if id, err := ParseKeyID(req); err != nil || id != "https://a.example/actor#main-key" {
		t.Fatal(id, err)
	}
	v, err := VerifyRequest(req, body, pub, now.Add(time.Second), 5*time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Created.Equal(now) {
		t.Fatal("created time lost")
	}
	if _, err := VerifyRequest(req, body, pub, now.Add(5*time.Minute+time.Second), 5*time.Minute, time.Minute); err == nil {
		t.Fatal("signature older than five minutes accepted")
	}
	if _, err := VerifyRequest(req, body, pub, now.Add(-2*time.Minute), 5*time.Minute, time.Minute); err == nil {
		t.Fatal("signature dated in the future accepted")
	}
	if _, err := VerifyRequest(req, []byte(`{"type":"Relay"}`), pub, now, 5*time.Minute, time.Minute); err == nil {
		t.Fatal("tampered body accepted")
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := VerifyRequest(req, body, other, now, 5*time.Minute, time.Minute); err == nil {
		t.Fatal("wrong key accepted")
	}
	// the covered target URI is signed: replaying to another path fails
	req2 := req.Clone(req.Context())
	req2.URL.Path = "/other"
	if _, err := VerifyRequest(req2, body, pub, now, 5*time.Minute, time.Minute); err == nil {
		t.Fatal("signature accepted for a different target")
	}
	req3 := req.Clone(req.Context())
	req3.Header.Set("Content-Type", "text/plain")
	if _, err := VerifyRequest(req3, body, pub, now, 5*time.Minute, time.Minute); err == nil {
		t.Fatal("signature accepted for a different content type")
	}
}

func TestRetryResignsWithFreshTimestamp(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	req, body := newReq(t, `{}`)
	SignRequest(req, body, "k", priv, time.Unix(1000, 0), "")
	first := req.Header.Get("Signature")
	SignRequest(req, body, "k", priv, time.Unix(1060, 0), "")
	if req.Header.Get("Signature") == first {
		t.Fatal("a later signing must carry a new timestamp")
	}
}

func TestVerifyRefusesWeakCoverageAndMalformedHeaders(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_800_000_000, 0)
	req, body := newReq(t, `{}`)
	SignRequest(req, body, "k", priv, now, "")
	good := req.Header.Get("Signature-Input")
	for name, in := range map[string]string{
		"no digest":   strings.Replace(good, ` "content-digest"`, "", 1),
		"no method":   strings.Replace(good, `"@method" `, "", 1),
		"no created":  strings.Replace(good, ";created=1800000000", "", 1),
		"wrong label": strings.Replace(good, "sig1=", "sig2=", 1),
		"wrong alg":   strings.Replace(good, `alg="ed25519"`, `alg="rsa-v1_5-sha256"`, 1),
		"garbage":     "nonsense",
		"empty":       "",
		"open string": `sig1=("@method;created=1`,
	} {
		r := req.Clone(req.Context())
		r.Header.Set("Signature-Input", in)
		if _, err := VerifyRequest(r, body, pub, now, time.Minute, time.Minute); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, sg := range map[string]string{"empty": "", "no colons": "sig1=abc", "bad base64": "sig1=:!!!:", "wrong label": "sigX=:AAAA:"} {
		r := req.Clone(req.Context())
		r.Header.Set("Signature", sg)
		if _, err := VerifyRequest(r, body, pub, now, time.Minute, time.Minute); err == nil {
			t.Errorf("signature %s: accepted", name)
		}
	}
}

// The literal did:key example string was not checked against a primary source, so this
// asserts the properties that matter: the well-known "z6Mk" prefix of Ed25519 multikeys
// (which depends on the 0xed01 multicodec prefix) and an exact round trip.
func TestMultikey(t *testing.T) {
	raw, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	got := EncodeEd25519Multikey(ed25519.PublicKey(raw))
	if !strings.HasPrefix(got, "z6Mk") || len(got) != 48 {
		t.Fatalf("got %s", got)
	}
	back, err := DecodeEd25519Multikey(got)
	if err != nil || hex.EncodeToString(back) != hex.EncodeToString(raw) {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "z", "m6Mk", "z0OIl", "z" + base58Encode([]byte{1, 2, 3})} {
		if _, err := DecodeEd25519Multikey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
