// Package ap implements the server-to-server side of the design: RFC 9421 HTTP
// message signatures with Ed25519, the actor document, the custom activities
// (Roam, Relay, Introduce, Rename) and delivery with retries.
package ap

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SigLabel is the signature label this implementation uses and requires.
const SigLabel = "sig1"

// RequestComponents are the covered components of every signed delivery. The signed
// "created" parameter carries the timestamp the replay limit checks.
var RequestComponents = []string{"@method", "@target-uri", "content-digest", "content-type"}

// ContentDigest returns the Content-Digest header value for body (RFC 9530, sha-256).
func ContentDigest(body []byte) string {
	h := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(h[:]) + ":"
}

func quote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// sigParams is the signature parameters list that follows the covered components.
type sigParams struct {
	components []string
	created    int64
	keyID      string
	alg        string
	nonce      string
}

// String renders the parameters as an inner list with parameters, in the order created,
// keyid, alg, nonce (the same text is the "@signature-params" line of the signature base
// and the value of the Signature-Input member).
func (p sigParams) String() string {
	var b strings.Builder
	b.WriteString("(")
	for i, c := range p.components {
		if i > 0 {
			b.WriteString(" ")
		}
		b.WriteString(quote(c))
	}
	b.WriteString(")")
	if p.created != 0 {
		b.WriteString(";created=" + strconv.FormatInt(p.created, 10))
	}
	if p.keyID != "" {
		b.WriteString(";keyid=" + quote(p.keyID))
	}
	if p.alg != "" {
		b.WriteString(";alg=" + quote(p.alg))
	}
	if p.nonce != "" {
		b.WriteString(";nonce=" + quote(p.nonce))
	}
	return b.String()
}

// componentValue returns the value of one covered component of a request (RFC 9421
// section 2.1 and 2.2). Only the derived components this implementation uses are supported.
func componentValue(req *http.Request, name string) (string, error) {
	switch name {
	case "@method":
		return strings.ToUpper(req.Method), nil
	case "@target-uri":
		return requestURL(req), nil
	case "@authority":
		return strings.ToLower(req.Host), nil
	case "@path":
		p := req.URL.EscapedPath()
		if p == "" {
			p = "/"
		}
		return p, nil
	case "@scheme":
		return schemeOf(req), nil
	case "@query":
		return "?" + req.URL.RawQuery, nil
	}
	if strings.HasPrefix(name, "@") {
		return "", fmt.Errorf("httpsig: unsupported derived component %q", name)
	}
	vals := req.Header.Values(name)
	if len(vals) == 0 {
		return "", fmt.Errorf("httpsig: header %q missing", name)
	}
	for i := range vals {
		vals[i] = strings.TrimSpace(vals[i])
	}
	return strings.Join(vals, ", "), nil
}

func schemeOf(req *http.Request) string {
	if req.URL.Scheme != "" {
		return req.URL.Scheme
	}
	if req.TLS != nil {
		return "https"
	}
	return "http"
}

func requestURL(req *http.Request) string {
	if req.URL.IsAbs() {
		return req.URL.String()
	}
	u := url.URL{Scheme: schemeOf(req), Host: req.Host, Path: req.URL.Path, RawPath: req.URL.RawPath, RawQuery: req.URL.RawQuery}
	return u.String()
}

// signatureBase builds the signature base (RFC 9421 section 2.5).
func signatureBase(req *http.Request, p sigParams) (string, error) {
	var b strings.Builder
	for _, c := range p.components {
		v, err := componentValue(req, c)
		if err != nil {
			return "", err
		}
		b.WriteString(quote(c) + ": " + v + "\n")
	}
	b.WriteString(`"@signature-params": ` + p.String())
	return b.String(), nil
}

// SignRequest signs req (whose body is body) with Ed25519 and sets Content-Digest,
// Signature-Input and Signature. created is the signing time; it is signed, so each
// retry that calls SignRequest again carries a fresh timestamp.
func SignRequest(req *http.Request, body []byte, keyID string, priv ed25519.PrivateKey, created time.Time, nonce string) error {
	req.Header.Set("Content-Digest", ContentDigest(body))
	p := sigParams{components: RequestComponents, created: created.Unix(), keyID: keyID, alg: "ed25519", nonce: nonce}
	base, err := signatureBase(req, p)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, []byte(base))
	req.Header.Set("Signature-Input", SigLabel+"="+p.String())
	req.Header.Set("Signature", SigLabel+"=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return nil
}

// VerifyError describes why a request signature was refused.
type VerifyError struct{ Reason string }

func (e *VerifyError) Error() string { return "httpsig: " + e.Reason }

func bad(format string, a ...any) error { return &VerifyError{fmt.Sprintf(format, a...)} }

// ParseKeyID returns the key ID from a request's Signature-Input without verifying it, so
// the receiver can fetch the right key.
func ParseKeyID(req *http.Request) (string, error) {
	p, err := parseSignatureInput(req.Header.Get("Signature-Input"))
	if err != nil {
		return "", err
	}
	if p.keyID == "" {
		return "", bad("no keyid")
	}
	return p.keyID, nil
}

// Verified is the outcome of a successful verification.
type Verified struct {
	KeyID   string
	Created time.Time
}

// VerifyRequest checks the Content-Digest against body and the Ed25519 signature against
// pub. It requires the covered components to include @method, @target-uri and
// content-digest, requires a created time, and refuses one older than maxAge or more than
// skew in the future (the replay limit: SPEC.md section 5).
func VerifyRequest(req *http.Request, body []byte, pub ed25519.PublicKey, now time.Time, maxAge, skew time.Duration) (*Verified, error) {
	p, err := parseSignatureInput(req.Header.Get("Signature-Input"))
	if err != nil {
		return nil, err
	}
	if p.alg != "" && p.alg != "ed25519" {
		return nil, bad("unsupported alg %q", p.alg)
	}
	have := map[string]bool{}
	for _, c := range p.components {
		have[c] = true
	}
	for _, need := range []string{"@method", "@target-uri", "content-digest"} {
		if !have[need] {
			return nil, bad("%s is not covered", need)
		}
	}
	if p.created == 0 {
		return nil, bad("no created parameter")
	}
	created := time.Unix(p.created, 0)
	if now.Sub(created) > maxAge {
		return nil, bad("signature is older than %v", maxAge)
	}
	if created.Sub(now) > skew {
		return nil, bad("signature is dated in the future")
	}
	want := ContentDigest(body)
	if subtle.ConstantTimeCompare([]byte(req.Header.Get("Content-Digest")), []byte(want)) != 1 {
		return nil, bad("content digest does not match the body")
	}
	sig, err := parseSignature(req.Header.Get("Signature"))
	if err != nil {
		return nil, err
	}
	base, err := signatureBase(req, p)
	if err != nil {
		return nil, err
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, []byte(base), sig) {
		return nil, bad("signature does not verify")
	}
	return &Verified{KeyID: p.keyID, Created: created}, nil
}

func parseSignature(h string) ([]byte, error) {
	label, rest, ok := strings.Cut(strings.TrimSpace(h), "=")
	if !ok || label != SigLabel {
		return nil, bad("signature label must be %s", SigLabel)
	}
	if len(rest) < 3 || rest[0] != ':' || rest[len(rest)-1] != ':' {
		return nil, bad("malformed signature value")
	}
	b, err := base64.StdEncoding.DecodeString(rest[1 : len(rest)-1])
	if err != nil {
		return nil, bad("signature is not base64")
	}
	return b, nil
}

// parseSignatureInput parses `sig1=("a" "b");created=1;keyid="k";alg="ed25519";nonce="n"`.
func parseSignatureInput(h string) (sigParams, error) {
	var p sigParams
	label, rest, ok := strings.Cut(strings.TrimSpace(h), "=")
	if !ok || label != SigLabel {
		return p, bad("signature input label must be %s", SigLabel)
	}
	if !strings.HasPrefix(rest, "(") {
		return p, bad("malformed signature input")
	}
	i := 1
	for {
		for i < len(rest) && rest[i] == ' ' {
			i++
		}
		if i >= len(rest) {
			return p, bad("unterminated component list")
		}
		if rest[i] == ')' {
			i++
			break
		}
		s, n, err := parseQuoted(rest[i:])
		if err != nil {
			return p, err
		}
		p.components = append(p.components, s)
		i += n
	}
	for i < len(rest) {
		if rest[i] != ';' {
			return p, bad("unexpected character in parameters")
		}
		i++
		j := i
		for j < len(rest) && rest[j] != '=' && rest[j] != ';' {
			j++
		}
		key := rest[i:j]
		if j >= len(rest) || rest[j] != '=' {
			return p, bad("parameter %q has no value", key)
		}
		i = j + 1
		var val string
		if i < len(rest) && rest[i] == '"' {
			s, n, err := parseQuoted(rest[i:])
			if err != nil {
				return p, err
			}
			val, i = s, i+n
		} else {
			j = i
			for j < len(rest) && rest[j] != ';' {
				j++
			}
			val, i = rest[i:j], j
		}
		switch key {
		case "created":
			n, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return p, bad("created is not an integer")
			}
			p.created = n
		case "keyid":
			p.keyID = val
		case "alg":
			p.alg = val
		case "nonce":
			p.nonce = val
		}
	}
	return p, nil
}

func parseQuoted(s string) (string, int, error) {
	if len(s) == 0 || s[0] != '"' {
		return "", 0, bad("expected a quoted string")
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
			if i >= len(s) {
				return "", 0, bad("bad escape")
			}
			b.WriteByte(s[i])
		case '"':
			return b.String(), i + 1, nil
		default:
			b.WriteByte(s[i])
		}
	}
	return "", 0, errors.New("httpsig: unterminated string")
}
