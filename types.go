// Package goidentityproofing implements an identity proofing session composed of
// several required proofs (ID document, facial match, liveness, etc.).
//
// The package focuses on four safety properties:
//
//   - On creation, the required proof types, the applicant information digest
//     and the deadline are frozen, and a short-lived, single-use challenge is
//     issued. Challenges and sensitive credential material are only ever held
//     as SHA-256 hashes in storage; the plaintext challenge exists solely in
//     the SessionHandle returned to the caller at creation/rotation time.
//   - External verification receipts may arrive duplicated or out of order.
//     Replaying a receipt number with the same content returns the result of
//     the first processing; replaying it with different content is a conflict.
//     A receipt must match the session, the proof type and the current
//     challenge; receipts for expired challenges or old sessions are rejected.
//   - Verification completes at most once and only while the session is valid
//     and every required proof has succeeded, producing a single credential.
//     Concurrent arrivals of the last receipts cannot create multiple
//     credentials, and a failed proof can never be silently overwritten by a
//     later successful receipt.
//   - Cancellation, expiry and final completion race for a single terminal
//     state; exactly one wins. State transitions are audit-logged.
package goidentityproofing

import "errors"

// State is the lifecycle state of a proofing session.
type State string

const (
	// StateActive is the only state in which proofs may be submitted.
	StateActive State = "active"
	// StateCompleted means every required proof succeeded and exactly one
	// credential was issued.
	StateCompleted State = "completed"
	// StateCancelled means the session was cancelled explicitly before
	// completion or expiry.
	StateCancelled State = "cancelled"
	// StateExpired means the deadline passed (observed through a mutating
	// call or AdvanceExpirations) before completion.
	StateExpired State = "expired"
)

// IsTerminal reports whether s is a terminal state.
func (s State) IsTerminal() bool { return s != StateActive }

// ProofType identifies one required proof. Values are domain-defined
// strings; the package provides common identifiers for convenience.
type ProofType string

const (
	ProofIDDocument  ProofType = "id_document"
	ProofFacialMatch ProofType = "facial_match"
	ProofLiveness    ProofType = "liveness"
	ProofAddress     ProofType = "address"
)

// ProofStatus is the outcome of a single proof type.
type ProofStatus string

const (
	ProofPending ProofStatus = "pending"
	ProofSuccess ProofStatus = "success"
	ProofFailed  ProofStatus = "failed"
)

// Applicant carries the sensitive identity information asserted when the
// session is created. The plaintext value is never stored: only applicantDigest
// (a keyed SHA-256 over a canonical encoding) is persisted and exposed.
type Applicant struct {
	// FullName is the applicant's full legal name.
	FullName string
	// DocumentNumber is the sensitive ID-document number (e.g. passport).
	DocumentNumber string
	// DateOfBirth is the applicant's date of birth, e.g. "1990-01-31".
	DateOfBirth string
	// Country is the issuing country code, e.g. "CN".
	Country string
	// Extra holds any additional asserted attributes. Keys are sorted when
	// computing the digest, so map order does not matter.
	Extra map[string]string
}

// Clone returns a deep copy.
func (a Applicant) Clone() Applicant {
	out := a
	if a.Extra != nil {
		out.Extra = make(map[string]string, len(a.Extra))
		for k, v := range a.Extra {
			out.Extra[k] = v
		}
	}
	return out
}

// Receipt is an external verification result submitted for a session.
//
// A receipt is identified by ReceiptNo, which acts as the global idempotency
// key. Re-submitting the same ReceiptNo is idempotent when the content is
// byte-for-byte equivalent (ContentFingerprint) and a conflict otherwise —
// even if a different Issuer presents the number.
type Receipt struct {
	// ReceiptNo is the globally unique receipt identifier.
	ReceiptNo string
	// Issuer identifies the external verification provider. It is part of
	// the receipt content, so a replay from a different issuer is a conflict.
	Issuer string
	// SessionID must match the target session.
	SessionID string
	// Proof is the proof type the receipt pertains to.
	Proof ProofType
	// Challenge is the plaintext challenge the receipt was produced for.
	Challenge string
	// Success reports the provider's verification decision.
	Success bool
	// Reason is a short, NON-SENSITIVE failure reason (e.g. "no_match").
	// It must never contain document numbers or other PII; it is stored.
	Reason string
	// IssuedAt is the provider timestamp (informational; the service clock
	// decides expiry).
	IssuedAt int64
}

// ReceiptResult is what a successful receipt processing returns. Replays
// return the same values the first processing produced.
type ReceiptResult struct {
	// Accepted is true when the receipt was a new, valid, successful proof.
	Accepted bool
	// Replay is true when the receipt number had been processed before.
	Replay bool
	// ProofStatus is the recorded status of the proof after processing
	// ("success" or "failed"; rejected replays return the recorded status
	// too).
	ProofStatus ProofStatus
	// SessionStatus is the session state after processing.
	SessionStatus State
	// CredentialID is non-empty only when this processing (including a
	// replay of the completing receipt) observes a completed session.
	CredentialID string
}

// Credential is the unique identity credential issued when a session
// completes. It references hashes only — no applicant PII.
type Credential struct {
	ID            string
	SessionID     string
	SubjectDigest string
	IssuedAt      int64
}

// ProofView is the externally visible state of one proof.
type ProofView struct {
	Type   ProofType
	Status ProofStatus
	// ReceiptNo is the receipt number that decided the proof, if any.
	ReceiptNo string
	// Reason is the non-sensitive failure reason, if any.
	Reason string
}

// SessionView is a point-in-time, side-effect-free projection of a session.
type SessionView struct {
	ID              string
	State           State
	RequiredProofs  []ProofType
	ApplicantDigest string
	Deadline        int64
	CreatedAt       int64
	// ChallengeHash identifies the current challenge without revealing it.
	ChallengeHash string
	// ChallengeExpiresAt is the expiry instant of the current challenge.
	ChallengeExpiresAt int64
	// ChallengeRotations counts how many times a new challenge was issued;
	// the first challenge is rotation 0.
	ChallengeRotations int
	Proofs             []ProofView
	CredentialID       string
	Audit              []AuditEvent
}

// AuditEvent records one state-relevant occurrence. Audit entries never
// contain plaintext challenges or applicant data: only hashes/digests,
// receipt numbers (opaque issuer identifiers) and short reason codes.
type AuditEvent struct {
	At        int64
	Kind      AuditKind
	Detail    string
	ReceiptNo string
}

// AuditKind enumerates audited occurrences.
type AuditKind string

const (
	AuditSessionCreated   AuditKind = "session_created"
	AuditReceiptAccepted  AuditKind = "receipt_accepted"
	AuditReceiptFailed    AuditKind = "receipt_failed"
	AuditReceiptRejected  AuditKind = "receipt_rejected"
	AuditReceiptReplay    AuditKind = "receipt_replay"
	AuditReceiptConflict  AuditKind = "receipt_conflict"
	AuditChallengeRotated AuditKind = "challenge_rotated"
	AuditCompleted        AuditKind = "session_completed"
	AuditCancelled        AuditKind = "session_cancelled"
	AuditExpired          AuditKind = "session_expired"
)

// Sentinel errors. Messages are deliberately generic: they must never carry
// plaintext challenges, document numbers or applicant PII. All of these are
// safe to surface to callers or write to logs.
var (
	// ErrNotFound is returned for unknown sessions or credentials.
	ErrNotFound = errors.New("proofing: session not found")
	// ErrTerminal is returned when a mutating operation targets a session
	// that is already in a terminal state.
	ErrTerminal = errors.New("proofing: session already in terminal state")
	// ErrExpired is returned when the session deadline or the challenge
	// deadline has passed.
	ErrExpired = errors.New("proofing: session or challenge expired")
	// ErrChallengeMismatch is returned when a receipt does not carry the
	// session's current challenge (a wrong/forged challenge).
	ErrChallengeMismatch = errors.New("proofing: challenge does not match")
	// ErrStaleChallenge is returned when a receipt carries a previously
	// issued (consumed or rotated-away) challenge.
	ErrStaleChallenge = errors.New("proofing: stale challenge")
	// ErrNoChallenge is returned when the session's single-use challenge was
	// already consumed by an accepted receipt and no new challenge has been
	// issued yet (RotateChallenge).
	ErrNoChallenge = errors.New("proofing: outstanding challenge already consumed")
	// ErrUnknownProof is returned when a receipt's proof type is not among
	// the frozen required proofs.
	ErrUnknownProof = errors.New("proofing: proof type not required by session")
	// ErrProofDecided is returned when a receipt arrives for a proof whose
	// outcome is already recorded. A recorded failure can never be
	// overwritten, and a success is already terminal for that proof.
	ErrProofDecided = errors.New("proofing: proof outcome already recorded")
	// ErrConflict is returned when the same receipt number is replayed with
	// different content.
	ErrConflict = errors.New("proofing: receipt number reused with different content")
	// ErrInvalidArgument is returned for malformed requests.
	ErrInvalidArgument = errors.New("proofing: invalid argument")
	// ErrIncomplete is returned by Complete when required proofs are not
	// all successful.
	ErrIncomplete = errors.New("proofing: not all required proofs succeeded")
)
