package goidentityproofing

import (
	"sync"
)

// proofRecord is the stored outcome of one required proof. It is set exactly
// once: once a valid receipt decides the proof (success or failure), no later
// receipt may change it.
type proofRecord struct {
	typ       ProofType
	status    ProofStatus
	receiptNo string
	reason    string
}

// sessionRecord is the persisted session state. Sensitive material appears
// only as hashes/digests: there is no plaintext challenge and no applicant
// PII anywhere in this structure.
type sessionRecord struct {
	id            string
	state         State
	required      []ProofType
	applicantHash string
	deadline      int64
	createdAt     int64

	// challengeHash is the hash of the challenge the next receipt must
	// carry; it is empty after a receipt was accepted (the challenge was
	// consumed) until RotateChallenge issues a new one. pastChallengeHashes
	// records every previously issued hash so reused challenges are reported
	// as stale rather than unknown.
	challengeHash       string
	pastChallengeHashes map[string]struct{}
	challengeExpiresAt  int64
	challengeRotations  int
	// challengeTTL is the frozen per-session challenge lifetime in
	// seconds, so rotated challenges keep the TTL chosen at creation.
	challengeTTL int64

	proofs       map[ProofType]*proofRecord
	credentialID string
	audit        []AuditEvent
}

// receiptRecord preserves the first processing of a receipt number so that
// replays return the original outcome. The stored content is a fingerprint,
// never the plaintext challenge (the fingerprint is an unkeyed SHA-256 of
// content that includes the high-entropy challenge, so it cannot be used to
// verify guesses offline at meaningful cost — and the plaintext itself is
// never logged).
type receiptRecord struct {
	key         string
	receiptNo   string
	issuer      string
	sessionID   string
	proof       ProofType
	fingerprint string
	// accepted reports whether the first processing recorded a proof
	// outcome. Rejected receipts are persisted too, so their replays return
	// the same rejection instead of being silently re-evaluated.
	accepted bool
	// rejectCode is the code of the first rejection, so an identical replay
	// reproduces the same error (empty when accepted).
	rejectCode string
	// status is the proof status observed at first processing (empty for
	// pre-proof rejections).
	status ProofStatus
	// credentialID is the credential observed at first processing, if the
	// session was already/completed-as-part-of that processing.
	credentialID string
	processedAt  int64
}

// credentialRecord is the unique credential issued per completed session.
type credentialRecord struct {
	id            string
	sessionID     string
	subjectDigest string
	issuedAt      int64
}

// memData is the whole in-memory dataset, guarded by MemoryStore.mu.
type memData struct {
	sessions      map[string]*sessionRecord
	receipts      map[string]*receiptRecord
	credentials   map[string]*credentialRecord
	credBySession map[string]string
}

// MemoryStore is a concurrency-safe in-process implementation of the
// service's persistence boundary.
//
// Every service operation that moves state does so inside a single write
// critical section (see mutate), which is the in-memory analogue of a single
// serializable database transaction. A durable SQL backend would map each
// record to a row and enforce the same invariants with unique constraints:
//
//   - sessions(id PK, state, ...)
//   - session_proofs(session_id, proof_type, status, receipt_no,
//     PRIMARY KEY(session_id, proof_type)) — the inserted row pins the
//     outcome, so failures cannot be overwritten.
//   - receipts(receipt_no PK, issuer, session_id, proof_type, fingerprint,
//     accepted, reject_code) — replays and conflicts are detected by looking
//     up this row; the issuer is part of the fingerprint.
//   - credentials(id PK, session_id UNIQUE) — the unique session_id makes a
//     second credential impossible even under races.
//   - session_audit(session_id, seq, kind, detail) for append-only audit.
type MemoryStore struct {
	mu   sync.RWMutex
	data memData
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{data: memData{
		sessions:      make(map[string]*sessionRecord),
		receipts:      make(map[string]*receiptRecord),
		credentials:   make(map[string]*credentialRecord),
		credBySession: make(map[string]string),
	}}
}

// view runs fn under the read lock. fn must not mutate the dataset.
func (s *MemoryStore) view(fn func(*memData)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fn(&s.data)
}

// mutate runs fn atomically under the write lock. If fn returns an error,
// callers must treat the dataset as authoritative regardless (service code
// only appends/modifies state on success paths — see SubmitReceipt).
func (s *MemoryStore) mutate(fn func(*memData) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(&s.data)
}

// receipts is keyed by the issuer-reported receipt number alone: the task
// contract treats the receipt number as the idempotency key, so the same
// number from any issuer must replay or conflict rather than double-apply.
// The fingerprint (which includes the issuer) distinguishes the two cases.

// ---- clones: values leaving the store are independent copies so callers
// cannot mutate stored state without going through a transaction. ----

func cloneAudit(in []AuditEvent) []AuditEvent {
	if len(in) == 0 {
		return nil
	}
	out := make([]AuditEvent, len(in))
	copy(out, in)
	return out
}

func cloneRequired(in []ProofType) []ProofType {
	out := make([]ProofType, len(in))
	copy(out, in)
	return out
}
