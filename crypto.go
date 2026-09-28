package goidentityproofing

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
)

// randomToken returns n bytes of cryptographic randomness, base64url encoded
// without padding. It is used for session IDs and credential IDs.
func randomToken(n int) string {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		// crypto/rand failing is not recoverable; fail loudly rather than
		// issuing predictable identifiers.
		panic(fmt.Errorf("proofing: cannot read crypto/rand: %w", err))
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func newSessionID() string    { return "sess_" + randomToken(18) }
func newCredentialID() string { return "cred_" + randomToken(18) }

// newChallenge issues a fresh single-use challenge plaintext. The value is
// high-entropy and is returned to the caller exactly once; only its keyed
// hash is retained server-side.
func newChallenge() string { return "ch_" + randomToken(24) }

// newSecret returns a 32-byte process-local HMAC key. Persisted records hold
// only keyed hashes, so an attacker with a dump of the store cannot verify
// guesses of low-entropy values (e.g. document numbers) offline. The key
// itself never leaves the process and is never written to the store or logs.
func newSecret() []byte {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(fmt.Errorf("proofing: cannot read crypto/rand: %w", err))
	}
	return key
}

// hmacHex returns the lowercase hex HMAC-SHA256 of data under key, with a
// domain-separation prefix so values from different namespaces never collide.
func hmacHex(key []byte, prefix string, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(prefix))
	mac.Write([]byte{0})
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// challengeHash is the persisted, keyed form of a challenge.
func challengeHash(key []byte, challenge string) string {
	return hmacHex(key, "proofing/challenge/v1", []byte(challenge))
}

// canonicalJSON encodes v with sorted object keys so the encoding is stable
// regardless of map iteration order.
func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, err
	}
	var buf []byte
	var encode func(any)
	encode = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			buf = append(buf, '{')
			for i, k := range keys {
				if i > 0 {
					buf = append(buf, ',')
				}
				kb, _ := json.Marshal(k)
				buf = append(buf, kb...)
				buf = append(buf, ':')
				encode(t[k])
			}
			buf = append(buf, '}')
		case []any:
			buf = append(buf, '[')
			for i, e := range t {
				if i > 0 {
					buf = append(buf, ',')
				}
				encode(e)
			}
			buf = append(buf, ']')
		default:
			b, _ := json.Marshal(x)
			buf = append(buf, b...)
		}
	}
	encode(decoded)
	return buf, nil
}

// applicantDigest is the frozen, keyed digest of the applicant information.
// The plaintext applicant fields never reach storage.
func applicantDigest(key []byte, a Applicant) (string, error) {
	canon, err := canonicalJSON(map[string]any{
		"full_name":       a.FullName,
		"document_number": a.DocumentNumber,
		"date_of_birth":   a.DateOfBirth,
		"country":         a.Country,
		"extra":           a.Extra,
	})
	if err != nil {
		return "", err
	}
	return hmacHex(key, "proofing/applicant/v1", canon), nil
}

// receiptFingerprint is the keyed, canonical fingerprint of the full receipt
// content. A replay must reproduce every field; otherwise it is a conflict.
// The plaintext challenge cannot be recovered from the fingerprint.
func receiptFingerprint(key []byte, r Receipt) (string, error) {
	canon, err := canonicalJSON(map[string]any{
		"receipt_no": r.ReceiptNo,
		"issuer":     r.Issuer,
		"session_id": r.SessionID,
		"proof":      string(r.Proof),
		"challenge":  r.Challenge,
		"success":    strconv.FormatBool(r.Success),
		"reason":     r.Reason,
		"issued_at":  strconv.FormatInt(r.IssuedAt, 10),
	})
	if err != nil {
		return "", err
	}
	return hmacHex(key, "proofing/receipt/v1", canon), nil
}

// equalHashes compares two hex digests in constant time.
func equalHashes(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
