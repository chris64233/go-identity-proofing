package goidentityproofing

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Logger is the minimal logging surface used by the service. Implementations
// may be nil (logging disabled). The service never formats plaintext
// challenges, applicant PII or document numbers into log lines.
type Logger interface {
	Printf(format string, args ...any)
}

// Config configures a Service.
type Config struct {
	// ChallengeTTL is how long an issued challenge stays valid. It is
	// clamped to the session deadline. Default 5 minutes when zero.
	ChallengeTTL time.Duration
	// Logger receives operational, non-sensitive log lines. Nil disables.
	Logger Logger
}

// CreateSessionRequest is the input to CreateSession.
type CreateSessionRequest struct {
	// Applicant is the asserted identity. Only a digest is retained.
	Applicant Applicant
	// RequiredProofs freezes the proof types the session needs. Order and
	// duplicates are normalized (sorted, de-duplicated).
	RequiredProofs []ProofType
	// TTL is the session lifetime from creation. Must be positive.
	TTL time.Duration
	// ChallengeTTL optionally overrides Config.ChallengeTTL for this
	// session. Zero means use the configured default.
	ChallengeTTL time.Duration
}

// SessionHandle is returned by CreateSession and RotateChallenge. It is the
// ONLY place the plaintext challenge appears. Callers must transport it over
// a confidential channel; the service can never show it again.
type SessionHandle struct {
	ID                 string
	State              State
	RequiredProofs     []ProofType
	ApplicantDigest    string
	Deadline           int64
	CreatedAt          int64
	Challenge          string
	ChallengeHash      string
	ChallengeExpiresAt int64
	ChallengeRotations int
}

// rejectCode is the short, non-sensitive code persisted on a rejected receipt
// so identical replays reproduce the first rejection.
type rejectCode string

const (
	rejTerminal       rejectCode = "terminal"
	rejExpired        rejectCode = "expired"
	rejChallengeMiss  rejectCode = "challenge_mismatch"
	rejStaleChallenge rejectCode = "stale_challenge"
	rejNoChallenge    rejectCode = "no_challenge"
	rejUnknownProof   rejectCode = "unknown_proof"
	rejProofDecided   rejectCode = "proof_decided"
)

func rejectError(c rejectCode) error {
	switch c {
	case rejTerminal:
		return ErrTerminal
	case rejExpired:
		return ErrExpired
	case rejChallengeMiss:
		return ErrChallengeMismatch
	case rejStaleChallenge:
		return ErrStaleChallenge
	case rejNoChallenge:
		return ErrNoChallenge
	case rejUnknownProof:
		return ErrUnknownProof
	case rejProofDecided:
		return ErrProofDecided
	default:
		return fmt.Errorf("proofing: receipt rejected (%s)", string(c))
	}
}

// Service implements the proofing-session workflow over a Store.
type Service struct {
	store *MemoryStore
	ttl   time.Duration
	log   Logger
	// secret keys the persisted HMACs of challenges, applicant data and
	// receipt content. It is generated per process, never exported and never
	// persisted.
	secret []byte

	mu  sync.Mutex
	now func() int64
}

// NewService builds a service over store.
func NewService(store *MemoryStore, cfg Config) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidArgument)
	}
	ttl := cfg.ChallengeTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Service{
		store:  store,
		ttl:    ttl,
		log:    cfg.Logger,
		secret: newSecret(),
		now:    func() int64 { return time.Now().Unix() },
	}, nil
}

// NewDefaultService builds a service over a fresh in-memory store with the
// default challenge TTL.
func NewDefaultService() *Service {
	svc, err := NewService(NewMemoryStore(), Config{})
	if err != nil {
		panic(err)
	}
	return svc
}

// setClock overrides the time source. Test-only (same package).
func (s *Service) setClock(now func() int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

func (s *Service) unixNow() int64 {
	s.mu.Lock()
	fn := s.now
	s.mu.Unlock()
	return fn()
}

func (s *Service) logf(format string, args ...any) {
	if s.log != nil {
		s.log.Printf(format, args...)
	}
}

func appendAudit(sess *sessionRecord, now int64, kind AuditKind, detail, receiptNo string) {
	sess.audit = append(sess.audit, AuditEvent{At: now, Kind: kind, Detail: detail, ReceiptNo: receiptNo})
}

// normalizeProofs sorts and de-duplicates the required proofs, rejecting
// empties.
func normalizeProofs(in []ProofType) ([]ProofType, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("%w: at least one required proof is needed", ErrInvalidArgument)
	}
	out := make([]ProofType, 0, len(in))
	seen := make(map[ProofType]struct{}, len(in))
	for _, p := range in {
		if strings.TrimSpace(string(p)) == "" {
			return nil, fmt.Errorf("%w: empty proof type", ErrInvalidArgument)
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// CreateSession freezes the required proofs, the applicant digest and the
// deadline, and issues the first short-lived single-use challenge.
func (s *Service) CreateSession(ctx context.Context, req CreateSessionRequest) (*SessionHandle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Applicant.FullName) == "" ||
		strings.TrimSpace(req.Applicant.DocumentNumber) == "" {
		return nil, fmt.Errorf("%w: applicant full name and document number are required", ErrInvalidArgument)
	}
	if req.TTL <= 0 {
		return nil, fmt.Errorf("%w: session TTL must be positive", ErrInvalidArgument)
	}
	proofs, err := normalizeProofs(req.RequiredProofs)
	if err != nil {
		return nil, err
	}
	digest, err := applicantDigest(s.secret, req.Applicant.Clone())
	if err != nil {
		return nil, fmt.Errorf("%w: cannot digest applicant", ErrInvalidArgument)
	}

	now := s.unixNow()
	deadline := now + int64(req.TTL/time.Second)
	challengeTTL := s.ttl
	if req.ChallengeTTL > 0 {
		challengeTTL = req.ChallengeTTL
	}
	challengeExp := now + int64(challengeTTL/time.Second)
	if challengeExp > deadline {
		challengeExp = deadline
	}

	id := newSessionID()
	challenge := newChallenge()
	chHash := challengeHash(s.secret, challenge)

	proofMap := make(map[ProofType]*proofRecord, len(proofs))
	for _, p := range proofs {
		proofMap[p] = &proofRecord{typ: p, status: ProofPending}
	}
	sess := &sessionRecord{
		id:                  id,
		state:               StateActive,
		required:            proofs,
		applicantHash:       digest,
		deadline:            deadline,
		createdAt:           now,
		challengeHash:       chHash,
		pastChallengeHashes: map[string]struct{}{},
		challengeExpiresAt:  challengeExp,
		challengeRotations:  0,
		proofs:              proofMap,
	}
	appendAudit(sess, now, AuditSessionCreated, fmt.Sprintf("proofs=%d", len(proofs)), "")

	err = s.store.mutate(func(d *memData) error {
		if _, exists := d.sessions[id]; exists {
			// 18-byte random IDs make this astronomically unlikely.
			return fmt.Errorf("proofing: session id collision")
		}
		d.sessions[id] = sess
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.logf("session created id=%s proofs=%d deadline=%d challenge_expires=%d",
		id, len(proofs), deadline, challengeExp)

	return &SessionHandle{
		ID:                 id,
		State:              StateActive,
		RequiredProofs:     cloneRequired(proofs),
		ApplicantDigest:    digest,
		Deadline:           deadline,
		CreatedAt:          now,
		Challenge:          challenge,
		ChallengeHash:      chHash,
		ChallengeExpiresAt: challengeExp,
	}, nil
}

// expireLocked transitions an active session past its deadline. Caller holds
// the write transaction and has decided the session is active.
func expireLocked(sess *sessionRecord, now int64) {
	sess.state = StateExpired
	appendAudit(sess, now, AuditExpired, "deadline_exceeded", "")
}

// terminalError returns the error describing an already-terminal session.
func terminalError(sess *sessionRecord) error {
	if sess.state == StateExpired {
		return ErrExpired
	}
	return ErrTerminal
}

// SubmitReceipt processes an external verification receipt. See the package
// documentation for the idempotency/conflict and matching rules.
func (s *Service) SubmitReceipt(ctx context.Context, r Receipt) (*ReceiptResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(r.ReceiptNo) == "" || strings.TrimSpace(r.Issuer) == "" ||
		strings.TrimSpace(r.SessionID) == "" || strings.TrimSpace(string(r.Proof)) == "" ||
		strings.TrimSpace(r.Challenge) == "" {
		return nil, fmt.Errorf("%w: receipt_no, issuer, session_id, proof and challenge are required", ErrInvalidArgument)
	}
	fp, err := receiptFingerprint(s.secret, r)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot fingerprint receipt", ErrInvalidArgument)
	}
	key := r.ReceiptNo

	var res *ReceiptResult
	err = s.store.mutate(func(d *memData) error {
		now := s.unixNow()
		// 1) Idempotency / conflict is decided first, purely by receipt
		//    number: same number + same content replays the first outcome;
		//    same number + different content is a conflict, regardless of
		//    the session's current state.
		if prior, ok := d.receipts[key]; ok {
			if sess := d.sessions[prior.sessionID]; sess != nil {
				if !equalHashes(prior.fingerprint, fp) {
					appendAudit(sess, now, AuditReceiptConflict, "receipt_no_reuse", r.ReceiptNo)
				} else {
					appendAudit(sess, now, AuditReceiptReplay, "identical", r.ReceiptNo)
				}
			}
			if !equalHashes(prior.fingerprint, fp) {
				s.logf("receipt conflict issuer=%s receipt_no=%s session=%s", r.Issuer, r.ReceiptNo, prior.sessionID)
				return ErrConflict
			}
			sess := d.sessions[prior.sessionID]
			if !prior.accepted {
				return rejectError(rejectCode(prior.rejectCode))
			}
			out := &ReceiptResult{
				Accepted:      true,
				Replay:        true,
				ProofStatus:   prior.status,
				SessionStatus: stateOf(sess),
			}
			if sess != nil {
				if p := sess.proofs[ProofType(prior.proof)]; p != nil && p.status != "" {
					out.ProofStatus = p.status
				}
				out.CredentialID = sess.credentialID
			} else {
				out.CredentialID = prior.credentialID
			}
			res = out
			return nil
		}

		// 2) New receipt number: validate against the session.
		sess, ok := d.sessions[r.SessionID]
		if !ok {
			// Receipts for unknown sessions are not persisted (there is
			// nowhere to attach them) and reveal nothing but existence.
			return ErrNotFound
		}

		// Helper for a rejected-but-persisted receipt: the rejection is
		// recorded so an identical replay reproduces it.
		reject := func(code rejectCode, detail string, cause error) error {
			d.receipts[key] = &receiptRecord{
				key:         key,
				receiptNo:   r.ReceiptNo,
				issuer:      r.Issuer,
				sessionID:   r.SessionID,
				proof:       r.Proof,
				fingerprint: fp,
				accepted:    false,
				status:      "",
				rejectCode:  string(code),
				processedAt: now,
			}
			appendAudit(sess, now, AuditReceiptRejected, detail, r.ReceiptNo)
			s.logf("receipt rejected session=%s proof=%s code=%s", r.SessionID, r.Proof, code)
			return cause
		}

		if sess.state != StateActive {
			return reject(rejTerminal, "session_"+string(sess.state), terminalError(sess))
		}
		if now >= sess.deadline {
			// Lazy expiry: the mutating call that first observes the
			// deadline wins the terminal transition.
			expireLocked(sess, now)
			return reject(rejExpired, "session_expired", ErrExpired)
		}

		// 3) Challenge matching: must be the current, unexpired, unconsumed
		//    challenge. Any challenge this session held before (consumed by
		//    an accepted receipt, or rotated away) is reported as stale.
		chHash := challengeHash(s.secret, r.Challenge)
		if sess.challengeHash == "" {
			if _, wasIssued := sess.pastChallengeHashes[chHash]; wasIssued {
				return reject(rejStaleChallenge, "challenge_consumed", ErrStaleChallenge)
			}
			return reject(rejNoChallenge, "no_outstanding_challenge", ErrNoChallenge)
		}
		if !equalHashes(chHash, sess.challengeHash) {
			if _, wasIssued := sess.pastChallengeHashes[chHash]; wasIssued {
				return reject(rejStaleChallenge, "rotated_challenge", ErrStaleChallenge)
			}
			return reject(rejChallengeMiss, "unknown_challenge", ErrChallengeMismatch)
		}
		if now >= sess.challengeExpiresAt {
			return reject(rejExpired, "challenge_expired", ErrExpired)
		}

		// 4) Proof matching: required, and not already decided.
		p, known := sess.proofs[r.Proof]
		if !known {
			return reject(rejUnknownProof, "proof_not_required", ErrUnknownProof)
		}
		if p.status != ProofPending {
			// A failed proof is pinned failed forever; a successful proof
			// is pinned succeeded. Neither can be silently overwritten.
			return reject(rejProofDecided, "proof_"+string(p.status), ErrProofDecided)
		}

		// 5) Decide the proof. The single-use challenge is consumed by this
		//    acceptance: the previous-challenge slot now holds it, so the
		//    next proof must use a rotated challenge.
		status := ProofSuccess
		auditKind := AuditReceiptAccepted
		if !r.Success {
			status = ProofFailed
			auditKind = AuditReceiptFailed
		}
		sess.proofs[r.Proof] = &proofRecord{
			typ:       r.Proof,
			status:    status,
			receiptNo: r.ReceiptNo,
			reason:    r.Reason,
		}
		detail := "proof_" + string(status)
		if status == ProofFailed && r.Reason != "" {
			detail += ":" + r.Reason
		}
		appendAudit(sess, now, auditKind, detail, r.ReceiptNo)

		// Consume the single-use challenge: the hash moves to the past set
		// and there is no outstanding challenge until RotateChallenge.
		if sess.challengeHash != "" {
			sess.pastChallengeHashes[sess.challengeHash] = struct{}{}
			sess.challengeHash = ""
		}

		rec := &receiptRecord{
			key:         key,
			receiptNo:   r.ReceiptNo,
			issuer:      r.Issuer,
			sessionID:   r.SessionID,
			proof:       r.Proof,
			fingerprint: fp,
			accepted:    true,
			status:      status,
			processedAt: now,
		}
		out := &ReceiptResult{
			Accepted:      true,
			Replay:        false,
			ProofStatus:   status,
			SessionStatus: StateActive,
		}

		// 6) One-shot completion: only an all-success active session reaches
		//    this, and it transitions inside the same transaction that
		//    records the final proof — no second completion is possible.
		if status == ProofSuccess && allProofsSucceeded(sess) {
			cred := issueCredentialLocked(d, sess, now)
			appendAudit(sess, now, AuditCompleted, "credential_issued", r.ReceiptNo)
			rec.credentialID = cred.id
			out.CredentialID = cred.id
			s.logf("session completed session=%s credential=%s", sess.id, cred.id)
		}

		d.receipts[key] = rec
		out.SessionStatus = sess.state
		res = out
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func stateOf(sess *sessionRecord) State {
	if sess == nil {
		return ""
	}
	return sess.state
}

// allProofsSucceeded reports every frozen required proof is present and
// successful.
func allProofsSucceeded(sess *sessionRecord) bool {
	for _, p := range sess.required {
		pr, ok := sess.proofs[p]
		if !ok || pr.status != ProofSuccess {
			return false
		}
	}
	return true
}

// issueCredentialLocked mints the single credential for an active,
// all-success session and moves it to completed. Caller must hold the write
// transaction; the caller appends the completion audit entry. The
// credBySession unique index is the in-memory backstop against double
// issuance (the SQL analogue is a UNIQUE(session_id) constraint).
func issueCredentialLocked(d *memData, sess *sessionRecord, now int64) *credentialRecord {
	if existing := sess.credentialID; existing != "" {
		if c, ok := d.credentials[existing]; ok {
			return c
		}
	}
	if id, ok := d.credBySession[sess.id]; ok {
		return d.credentials[id]
	}
	c := &credentialRecord{
		id:            newCredentialID(),
		sessionID:     sess.id,
		subjectDigest: sess.applicantHash,
		issuedAt:      now,
	}
	d.credentials[c.id] = c
	d.credBySession[sess.id] = c.id
	sess.credentialID = c.id
	sess.state = StateCompleted
	return c
}

// Complete explicitly attempts finalization. It succeeds only when every
// required proof has succeeded and the session is still active and unexpired.
// On an already-completed session it returns the existing credential.
func (s *Service) Complete(ctx context.Context, sessionID string) (*Credential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var cred *credentialRecord
	err := s.store.mutate(func(d *memData) error {
		now := s.unixNow()
		sess, ok := d.sessions[sessionID]
		if !ok {
			return ErrNotFound
		}
		if sess.state != StateActive {
			if sess.state == StateCompleted {
				cred = d.credentials[sess.credentialID]
				return nil
			}
			return terminalError(sess)
		}
		if now >= sess.deadline {
			expireLocked(sess, now)
			s.logf("session expired during complete session=%s", sessionID)
			return ErrExpired
		}
		if !allProofsSucceeded(sess) {
			return ErrIncomplete
		}
		c := issueCredentialLocked(d, sess, now)
		appendAudit(sess, now, AuditCompleted, "explicit_complete", "")
		cred = c
		s.logf("session completed session=%s credential=%s", sess.id, c.id)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return credentialView(cred), nil
}

// Cancel cancels an active session. Cancelling an already-cancelled session
// is idempotent (nil); cancelling a completed or expired session fails with
// ErrTerminal/ErrExpired. If the deadline has just passed, expiry wins and
// ErrExpired is returned.
func (s *Service) Cancel(ctx context.Context, sessionID, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.store.mutate(func(d *memData) error {
		now := s.unixNow()
		sess, ok := d.sessions[sessionID]
		if !ok {
			return ErrNotFound
		}
		if sess.state == StateCancelled {
			return nil
		}
		if sess.state != StateActive {
			return terminalError(sess)
		}
		if now >= sess.deadline {
			expireLocked(sess, now)
			s.logf("session expired during cancel session=%s", sessionID)
			return ErrExpired
		}
		sess.state = StateCancelled
		detail := "cancelled"
		if reason = strings.TrimSpace(reason); reason != "" {
			detail += ":" + sanitizeReason(reason)
		}
		appendAudit(sess, now, AuditCancelled, detail, "")
		s.logf("session cancelled session=%s", sessionID)
		return nil
	})
}

// RotateChallenge consumes the current challenge and issues a fresh
// single-use one. Used after an accepted receipt before submitting the next
// proof. The new challenge's expiry is clamped to the session deadline.
func (s *Service) RotateChallenge(ctx context.Context, sessionID string) (*SessionHandle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var h *SessionHandle
	err := s.store.mutate(func(d *memData) error {
		now := s.unixNow()
		sess, ok := d.sessions[sessionID]
		if !ok {
			return ErrNotFound
		}
		if sess.state != StateActive {
			return terminalError(sess)
		}
		if now >= sess.deadline {
			expireLocked(sess, now)
			return ErrExpired
		}
		challenge := newChallenge()
		chHash := challengeHash(s.secret, challenge)
		if sess.challengeHash != "" {
			sess.pastChallengeHashes[sess.challengeHash] = struct{}{}
		}
		sess.challengeHash = chHash
		sess.challengeRotations++
		exp := now + int64(s.ttl/time.Second)
		if exp > sess.deadline {
			exp = sess.deadline
		}
		sess.challengeExpiresAt = exp
		appendAudit(sess, now, AuditChallengeRotated,
			fmt.Sprintf("rotation=%d", sess.challengeRotations), "")
		h = &SessionHandle{
			ID:                 sess.id,
			State:              sess.state,
			RequiredProofs:     cloneRequired(sess.required),
			ApplicantDigest:    sess.applicantHash,
			Deadline:           sess.deadline,
			CreatedAt:          sess.createdAt,
			Challenge:          challenge,
			ChallengeHash:      chHash,
			ChallengeExpiresAt: exp,
			ChallengeRotations: sess.challengeRotations,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.logf("challenge rotated session=%s rotation=%d", sessionID, h.ChallengeRotations)
	return h, nil
}

// AdvanceExpirations moves every active session whose deadline has passed to
// the expired state and returns the IDs that transitioned. Call it from a
// periodic sweeper. Queries never expire sessions implicitly; only mutating
// calls and this sweeper observe time.
func (s *Service) AdvanceExpirations(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var expired []string
	err := s.store.mutate(func(d *memData) error {
		now := s.unixNow()
		for _, sess := range d.sessions {
			if sess.state == StateActive && now >= sess.deadline {
				expireLocked(sess, now)
				expired = append(expired, sess.id)
			}
		}
		sort.Strings(expired)
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, id := range expired {
		s.logf("session expired by sweeper session=%s", id)
	}
	return expired, nil
}

// GetSession returns a side-effect-free projection of a session.
func (s *Service) GetSession(ctx context.Context, sessionID string) (*SessionView, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var view *SessionView
	s.store.view(func(d *memData) {
		sess, ok := d.sessions[sessionID]
		if !ok {
			return
		}
		proofs := make([]ProofView, 0, len(sess.required))
		for _, t := range sess.required {
			pr := sess.proofs[t]
			pv := ProofView{Type: t, Status: ProofPending}
			if pr != nil {
				pv.Status = pr.status
				pv.ReceiptNo = pr.receiptNo
				pv.Reason = pr.reason
			}
			proofs = append(proofs, pv)
		}
		view = &SessionView{
			ID:                 sess.id,
			State:              sess.state,
			RequiredProofs:     cloneRequired(sess.required),
			ApplicantDigest:    sess.applicantHash,
			Deadline:           sess.deadline,
			CreatedAt:          sess.createdAt,
			ChallengeHash:      sess.challengeHash,
			ChallengeExpiresAt: sess.challengeExpiresAt,
			ChallengeRotations: sess.challengeRotations,
			Proofs:             proofs,
			CredentialID:       sess.credentialID,
			Audit:              cloneAudit(sess.audit),
		}
	})
	if view == nil {
		return nil, ErrNotFound
	}
	return view, nil
}

// GetCredential returns a credential by ID.
func (s *Service) GetCredential(ctx context.Context, credentialID string) (*Credential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out *Credential
	s.store.view(func(d *memData) {
		if c, ok := d.credentials[credentialID]; ok {
			out = credentialView(c)
		}
	})
	if out == nil {
		return nil, ErrNotFound
	}
	return out, nil
}

func credentialView(c *credentialRecord) *Credential {
	if c == nil {
		return nil
	}
	return &Credential{
		ID:            c.id,
		SessionID:     c.sessionID,
		SubjectDigest: c.subjectDigest,
		IssuedAt:      c.issuedAt,
	}
}

// sanitizeReason keeps free-form audit/reason text short and log-safe:
// no newlines or control characters.
func sanitizeReason(s string) string {
	mapped := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
	if len(mapped) > 64 {
		mapped = mapped[:64]
	}
	return mapped
}
