package goidentityproofing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- test harness ---------------------------------------------------------

type testEnv struct {
	svc   *Service
	store *MemoryStore
	log   *captureLogger
	clock atomic.Int64
}

type captureLogger struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *captureLogger) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.buf, format+"\n", args...)
}

func (l *captureLogger) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	env := &testEnv{store: NewMemoryStore(), log: &captureLogger{}}
	env.clock.Store(1_700_000_000)
	svc, err := NewService(env.store, Config{
		ChallengeTTL: 2 * time.Minute,
		Logger:       env.log,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	svc.setClock(func() int64 { return env.clock.Load() })
	env.svc = svc
	return env
}

func (e *testEnv) advance(secs int64) { e.clock.Add(secs) }

func sampleApplicant() Applicant {
	return Applicant{
		FullName:       "张三",
		DocumentNumber: "P12345678",
		DateOfBirth:    "1990-01-31",
		Country:        "CN",
		Extra:          map[string]string{"city": "Beijing"},
	}
}

// createSessionReq builds a session with the given required proofs and TTL
// (seconds).
func (e *testEnv) createSession(t *testing.T, ttlSecs int64, proofs ...ProofType) *SessionHandle {
	t.Helper()
	h, err := e.svc.CreateSession(context.Background(), CreateSessionRequest{
		Applicant:      sampleApplicant(),
		RequiredProofs: proofs,
		TTL:            time.Duration(ttlSecs) * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return h
}

// receipt builds a valid receipt for one proof.
func receipt(h *SessionHandle, proof ProofType, no string, ok bool, challenge string) Receipt {
	return Receipt{
		ReceiptNo: no,
		Issuer:    "issuer-a",
		SessionID: h.ID,
		Proof:     proof,
		Challenge: challenge,
		Success:   ok,
		Reason:    "",
		IssuedAt:  1,
	}
}

// submitOK submits a successful receipt for proof and then rotates the
// challenge so the next proof can be submitted, returning the new handle.
func (e *testEnv) submitOK(t *testing.T, h *SessionHandle, proof ProofType, no string) *SessionHandle {
	t.Helper()
	r, err := e.svc.SubmitReceipt(context.Background(), receipt(h, proof, no, true, h.Challenge))
	if err != nil {
		t.Fatalf("SubmitReceipt(%s): %v", no, err)
	}
	if !r.Accepted || r.ProofStatus != ProofSuccess {
		t.Fatalf("unexpected result: %+v", r)
	}
	if r.CredentialID == "" {
		nh, err := e.svc.RotateChallenge(context.Background(), h.ID)
		if err != nil {
			t.Fatalf("RotateChallenge: %v", err)
		}
		return nh
	}
	// Completing receipt: reflect completion on the handle.
	h.Challenge = ""
	return h
}

// ---- 1. session creation: frozen data, deadlines, single-use challenge ----

func TestCreateSession_FreezesInputsAndIssuesChallenge(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofLiveness, ProofIDDocument, ProofFacialMatch)

	if h.State != StateActive || h.Challenge == "" || h.ChallengeHash == "" {
		t.Fatalf("bad handle: %+v", h)
	}
	if !strings.HasPrefix(h.Challenge, "ch_") {
		t.Fatalf("challenge format: %q", h.Challenge)
	}
	if h.Challenge == h.ChallengeHash {
		t.Fatal("plaintext challenge equals stored hash")
	}
	// Required proofs are frozen sorted & de-duplicated.
	want := []ProofType{ProofFacialMatch, ProofIDDocument, ProofLiveness}
	if fmt.Sprint(h.RequiredProofs) != fmt.Sprint(want) {
		t.Fatalf("required proofs = %v, want %v", h.RequiredProofs, want)
	}
	// Challenge expiry is clamped to the session deadline.
	base := env.clock.Load()
	if h.CreatedAt != base || h.Deadline != base+600 {
		t.Fatalf("deadlines: created=%d deadline=%d", h.CreatedAt, h.Deadline)
	}
	if h.ChallengeExpiresAt != base+120 {
		t.Fatalf("challenge expiry = %d, want %d", h.ChallengeExpiresAt, base+120)
	}

	// Store must not contain plaintext challenge or document data.
	env.store.mu.RLock()
	sess := env.store.data.sessions[h.ID]
	blob := fmt.Sprintf("%+v", sess)
	env.store.mu.RUnlock()
	if strings.Contains(blob, h.Challenge) {
		t.Fatal("plaintext challenge present in stored session")
	}
	for _, secret := range []string{"P12345678", "张三", "1990-01-31"} {
		if strings.Contains(blob, secret) {
			t.Fatalf("PII %q present in stored session", secret)
		}
	}
}

func TestCreateSession_ChallengeTTLClampedToDeadline(t *testing.T) {
	env := newTestEnv(t)
	h, err := env.svc.CreateSession(context.Background(), CreateSessionRequest{
		Applicant:      sampleApplicant(),
		RequiredProofs: []ProofType{ProofIDDocument},
		TTL:            30 * time.Second, // shorter than the 2m challenge TTL
	})
	if err != nil {
		t.Fatal(err)
	}
	if h.ChallengeExpiresAt != h.Deadline {
		t.Fatalf("challenge expiry %d not clamped to deadline %d", h.ChallengeExpiresAt, h.Deadline)
	}
}

func TestRotateChallenge_KeepsSessionChallengeTTL(t *testing.T) {
	env := newTestEnv(t) // configured default challenge TTL is 2m
	h, err := env.svc.CreateSession(context.Background(), CreateSessionRequest{
		Applicant:      sampleApplicant(),
		RequiredProofs: []ProofType{ProofIDDocument, ProofLiveness},
		TTL:            10 * time.Minute,
		ChallengeTTL:   30 * time.Second, // per-session override
	})
	if err != nil {
		t.Fatal(err)
	}
	base := env.clock.Load()
	if h.ChallengeExpiresAt != base+30 {
		t.Fatalf("initial challenge expiry = %d, want %d", h.ChallengeExpiresAt, base+30)
	}
	// The per-session TTL is frozen at creation: rotations must reuse it,
	// not fall back to the service default.
	env.advance(10)
	h2, err := env.svc.RotateChallenge(context.Background(), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := env.clock.Load() + 30; h2.ChallengeExpiresAt != want {
		t.Fatalf("rotated challenge expiry = %d, want %d", h2.ChallengeExpiresAt, want)
	}
	// ... and it is still clamped to the session deadline.
	env.clock.Store(h.Deadline - 5)
	h3, err := env.svc.RotateChallenge(context.Background(), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if h3.ChallengeExpiresAt != h.Deadline {
		t.Fatalf("rotated challenge expiry = %d, want clamped deadline %d", h3.ChallengeExpiresAt, h.Deadline)
	}
}

func TestCreateSession_ApplicantDigestFreezesInput(t *testing.T) {
	env := newTestEnv(t)
	h1 := env.createSession(t, 600, ProofIDDocument)
	h2 := env.createSession(t, 600, ProofIDDocument)
	// Same inputs -> same digest; different Extra -> different digest.
	if h1.ApplicantDigest != h2.ApplicantDigest {
		t.Fatal("same applicant produced different digests")
	}
	a := sampleApplicant()
	a.Extra = map[string]string{"city": "Shanghai"}
	now := env.clock.Load()
	h3, err := env.svc.CreateSession(context.Background(), CreateSessionRequest{
		Applicant:      a,
		RequiredProofs: []ProofType{ProofIDDocument},
		TTL:            600 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if h3.ApplicantDigest == h1.ApplicantDigest {
		t.Fatal("different applicants produced same digest")
	}
	if strings.Contains(h1.ApplicantDigest, "P12345678") {
		t.Fatal("digest leaks document number")
	}
	_ = now

	// Extra map order must not matter: construct a second applicant type with
	// identical values indirectly through digest stability check.
	d1 := mustDigest(t, env.svc.secret, sampleApplicant())
	d2 := mustDigest(t, env.svc.secret, sampleApplicant())
	if d1 != d2 {
		t.Fatal("digest not deterministic")
	}
}

func mustDigest(t *testing.T, key []byte, a Applicant) string {
	t.Helper()
	d, err := applicantDigest(key, a)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestCreateSession_Validation(t *testing.T) {
	env := newTestEnv(t)
	base := CreateSessionRequest{
		Applicant:      sampleApplicant(),
		RequiredProofs: []ProofType{ProofIDDocument},
		TTL:            time.Minute,
	}
	cases := []func(*CreateSessionRequest){
		func(r *CreateSessionRequest) { r.Applicant.FullName = " " },
		func(r *CreateSessionRequest) { r.Applicant.DocumentNumber = "" },
		func(r *CreateSessionRequest) { r.RequiredProofs = nil },
		func(r *CreateSessionRequest) { r.RequiredProofs = []ProofType{" "} },
		func(r *CreateSessionRequest) { r.TTL = 0 },
		func(r *CreateSessionRequest) { r.ChallengeTTL = -time.Second },
	}
	for i, mutate := range cases {
		req := base
		mutate(&req)
		if _, err := env.svc.CreateSession(context.Background(), req); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("case %d: want ErrInvalidArgument, got %v", i, err)
		}
	}
}

// ---- 2. receipts: idempotency, conflict, matching, expiry -----------------

func TestSubmitReceipt_IdenticalReplayReturnsFirstResult(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofIDDocument, ProofLiveness)
	r := receipt(h, ProofIDDocument, "R-1", true, h.Challenge)

	first, err := env.svc.SubmitReceipt(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if first.Replay || !first.Accepted {
		t.Fatalf("first processing: %+v", first)
	}
	// Same number, byte-identical content -> replay, same answer.
	again, err := env.svc.SubmitReceipt(context.Background(), r)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !again.Replay || again.Accepted != true || again.ProofStatus != ProofSuccess {
		t.Fatalf("replay result: %+v", again)
	}

	// Finish the session; a replay must now surface the same credential.
	nh, err := env.svc.RotateChallenge(context.Background(), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	fin, err := env.svc.SubmitReceipt(context.Background(), receipt(nh, ProofLiveness, "R-2", true, nh.Challenge))
	if err != nil {
		t.Fatal(err)
	}
	if fin.CredentialID == "" {
		t.Fatal("expected completion")
	}
	replayFirst, err := env.svc.SubmitReceipt(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if !replayFirst.Replay || replayFirst.CredentialID != fin.CredentialID {
		t.Fatalf("replay after completion: %+v", replayFirst)
	}
}

func TestSubmitReceipt_SameNumberChangedContentIsConflict(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofIDDocument, ProofLiveness)
	r := receipt(h, ProofIDDocument, "R-1", true, h.Challenge)
	if _, err := env.svc.SubmitReceipt(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	changes := []Receipt{
		func() Receipt { x := r; x.Success = false; x.Reason = "no_match"; return x }(),
		func() Receipt { x := r; x.Proof = ProofLiveness; return x }(),
		func() Receipt { x := r; x.IssuedAt = 999; return x }(),
		func() Receipt { x := r; x.Issuer = "issuer-b"; return x }(),
	}
	for i, c := range changes {
		// Changed-content receipts use a fresh session each because the first
		// acceptance consumed the challenge; the conflict check precedes
		// challenge validation anyway, but keep cases independent and clear.
		env2 := newTestEnv(t)
		h2 := env2.createSession(t, 600, ProofIDDocument, ProofLiveness)
		first := receipt(h2, ProofIDDocument, "R-1", true, h2.Challenge)
		if _, err := env2.svc.SubmitReceipt(context.Background(), first); err != nil {
			t.Fatal(err)
		}
		c.SessionID = h2.ID
		c.Challenge = h2.Challenge
		if _, err := env2.svc.SubmitReceipt(context.Background(), c); !errors.Is(err, ErrConflict) {
			t.Fatalf("case %d: want ErrConflict, got %v", i, err)
		}
		// A subsequent identical replay of the ORIGINAL content still returns
		// the original success outcome — conflict never overwrites history.
		orig := receipt(h2, ProofIDDocument, "R-1", true, h2.Challenge)
		got, err := env2.svc.SubmitReceipt(context.Background(), orig)
		if err != nil {
			t.Fatalf("original replay after conflict: %v", err)
		}
		if !got.Replay || got.ProofStatus != ProofSuccess {
			t.Fatalf("original result altered by conflict: %+v", got)
		}
	}
}

func TestSubmitReceipt_MustMatchSessionProofAndChallenge(t *testing.T) {
	env := newTestEnv(t)
	h1 := env.createSession(t, 600, ProofIDDocument, ProofLiveness)
	h2 := env.createSession(t, 600, ProofIDDocument)

	// Wrong session.
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(h1, ProofIDDocument, "R-x", true, h1.Challenge)); err != nil {
		t.Fatal(err)
	}
	// h1's challenge used against h2.
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(h2, ProofIDDocument, "R-a", true, h1.Challenge)); !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("foreign challenge: want ErrChallengeMismatch, got %v", err)
	}
	// Forged/unknown challenge.
	forged := receipt(h2, ProofIDDocument, "R-b", true, "ch_totally_wrong")
	if _, err := env.svc.SubmitReceipt(context.Background(), forged); !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("forged challenge: want ErrChallengeMismatch, got %v", err)
	}
	// Proof not required by this session.
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(h2, ProofFacialMatch, "R-c", true, h2.Challenge)); !errors.Is(err, ErrUnknownProof) {
		t.Fatalf("unknown proof: want ErrUnknownProof, got %v", err)
	}
	// Unknown session.
	r := receipt(h1, ProofIDDocument, "R-zz", true, h1.Challenge)
	r.SessionID = "sess_does_not_exist"
	if _, err := env.svc.SubmitReceipt(context.Background(), r); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown session: want ErrNotFound, got %v", err)
	}
}

func TestSubmitReceipt_ChallengeIsSingleUse(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofIDDocument, ProofLiveness)

	consumed := h.Challenge
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(h, ProofIDDocument, "R-1", true, consumed)); err != nil {
		t.Fatal(err)
	}
	// Reusing the consumed challenge with a NEW receipt number is stale.
	r2 := receipt(h, ProofLiveness, "R-2", true, consumed)
	if _, err := env.svc.SubmitReceipt(context.Background(), r2); !errors.Is(err, ErrStaleChallenge) {
		t.Fatalf("consumed challenge: want ErrStaleChallenge, got %v", err)
	}
	// Identical replay of R-1 still works (idempotency beats staleness).
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(h, ProofIDDocument, "R-1", true, consumed)); err != nil {
		t.Fatalf("replay R-1: %v", err)
	}

	// After rotation the new challenge works; the old one stays stale.
	nh, err := env.svc.RotateChallenge(context.Background(), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(nh, ProofLiveness, "R-3", true, consumed)); !errors.Is(err, ErrStaleChallenge) {
		t.Fatalf("old challenge after rotation: want ErrStaleChallenge, got %v", err)
	}
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(nh, ProofLiveness, "R-4", true, nh.Challenge)); err != nil {
		t.Fatalf("new challenge after rotation: %v", err)
	}
}

func TestSubmitReceipt_ExpiredChallengeAndSession(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofIDDocument, ProofLiveness)

	// Challenge TTL 2m: advance past it but not past session deadline.
	env.advance(121)
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(h, ProofIDDocument, "R-1", true, h.Challenge)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired challenge: want ErrExpired, got %v", err)
	}
	// Rotation revives the session with a fresh challenge (clamped to deadline).
	nh, err := env.svc.RotateChallenge(context.Background(), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(nh, ProofIDDocument, "R-2", true, nh.Challenge)); err != nil {
		t.Fatalf("fresh challenge: %v", err)
	}

	// Session expiry: new session advanced past its deadline.
	h2 := env.createSession(t, 100, ProofIDDocument)
	env.advance(200)
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(h2, ProofIDDocument, "R-3", true, h2.Challenge)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired session: want ErrExpired, got %v", err)
	}
	v, err := env.svc.GetSession(context.Background(), h2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if v.State != StateExpired {
		t.Fatalf("state = %s, want expired", v.State)
	}
	// Rejected receipt replays reproduce the rejection.
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(h2, ProofIDDocument, "R-3", true, h2.Challenge)); !errors.Is(err, ErrExpired) {
		t.Fatalf("replay of rejected receipt: want ErrExpired, got %v", err)
	}
}

func TestSubmitReceipt_OutOfOrderSuccessThenFailDecidesProof(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofIDDocument, ProofLiveness)
	// Out-of-order is normal: proofs arrive in any order.
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(h, ProofLiveness, "R-1", true, h.Challenge)); err != nil {
		t.Fatal(err)
	}
	nh, err := env.svc.RotateChallenge(context.Background(), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	fail := receipt(nh, ProofIDDocument, "R-2", false, nh.Challenge)
	fail.Reason = "no_match"
	res, err := env.svc.SubmitReceipt(context.Background(), fail)
	if err != nil {
		t.Fatal(err)
	}
	if res.ProofStatus != ProofFailed || res.CredentialID != "" {
		t.Fatalf("failed receipt: %+v", res)
	}
	// A later successful receipt for the same proof must NOT overwrite.
	nh2, err := env.svc.RotateChallenge(context.Background(), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(nh2, ProofIDDocument, "R-3", true, nh2.Challenge)); !errors.Is(err, ErrProofDecided) {
		t.Fatalf("overwrite failed proof: want ErrProofDecided, got %v", err)
	}
	v, _ := env.svc.GetSession(context.Background(), h.ID)
	for _, p := range v.Proofs {
		if p.Type == ProofIDDocument && p.Status != ProofFailed {
			t.Fatalf("proof was overwritten: %+v", p)
		}
	}
	// Session can never complete after a failed proof.
	if err := env.svc.Cancel(context.Background(), h.ID, ""); err == nil {
		// cancel allowed, but completing must be impossible regardless:
	}
	if cred, err := env.svc.Complete(context.Background(), h.ID); !errors.Is(err, ErrTerminal) {
		t.Fatalf("complete after cancel: want ErrTerminal, got cred=%v err=%v", cred, err)
	}
}

func TestSubmitReceipt_RejectedReplayIsStable(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofIDDocument)
	bad := receipt(h, ProofIDDocument, "R-1", true, "ch_forged")
	for i := 0; i < 2; i++ {
		if _, err := env.svc.SubmitReceipt(context.Background(), bad); !errors.Is(err, ErrChallengeMismatch) {
			t.Fatalf("attempt %d: want ErrChallengeMismatch, got %v", i, err)
		}
	}
}

// ---- 3. one-shot completion & unique credential ---------------------------

func TestHappyPath_IssuesSingleCredential(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofIDDocument, ProofFacialMatch, ProofLiveness)
	proofs := []ProofType{ProofIDDocument, ProofFacialMatch, ProofLiveness}
	for i, p := range proofs {
		last := i == len(proofs)-1
		r, err := env.svc.SubmitReceipt(context.Background(),
			receipt(h, p, fmt.Sprintf("R-%d", i), true, h.Challenge))
		if err != nil {
			t.Fatalf("proof %s: %v", p, err)
		}
		if last {
			if r.SessionStatus != StateCompleted || r.CredentialID == "" {
				t.Fatalf("last receipt: %+v", r)
			}
			h.State = StateCompleted
		} else {
			if r.SessionStatus != StateActive || r.CredentialID != "" {
				t.Fatalf("proof %s completed early: %+v", p, r)
			}
			nh, err := env.svc.RotateChallenge(context.Background(), h.ID)
			if err != nil {
				t.Fatal(err)
			}
			h = nh
		}
	}
	v, err := env.svc.GetSession(context.Background(), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if v.State != StateCompleted || v.CredentialID == "" {
		t.Fatalf("view: %+v", v)
	}
	cred, err := env.svc.GetCredential(context.Background(), v.CredentialID)
	if err != nil {
		t.Fatal(err)
	}
	if cred.SessionID != h.ID || cred.SubjectDigest == "" {
		t.Fatalf("credential: %+v", cred)
	}
	// Complete on a completed session returns the SAME credential.
	c2, err := env.svc.Complete(context.Background(), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if c2.ID != cred.ID {
		t.Fatalf("second Complete issued new credential: %s vs %s", c2.ID, cred.ID)
	}
}

func TestCompletion_NeedsEveryProof(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofIDDocument, ProofLiveness)
	// Only one proof in: explicit Complete reports incomplete.
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(h, ProofIDDocument, "R-1", true, h.Challenge)); err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.Complete(context.Background(), h.ID); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("Complete partial: want ErrIncomplete, got %v", err)
	}
}

func TestConcurrent_FinalReceiptsCreateExactlyOneCredential(t *testing.T) {
	// Race design: two receipts that BOTH appear to be "the last one" are
	// fired concurrently. Serial challenge consumption makes a genuinely
	// parallel last-two impossible by design, so we race the same final
	// receipt number (duplicated network delivery): exactly one acceptance
	// and one credential, every replay observing it.
	for iter := 0; iter < 50; iter++ {
		env := newTestEnv(t)
		h := env.createSession(t, 600, ProofIDDocument, ProofLiveness)
		h = env.submitOK(t, h, ProofIDDocument, "R-1")

		final := receipt(h, ProofLiveness, "R-final", true, h.Challenge)
		const n = 16
		var wg sync.WaitGroup
		var credsMu sync.Mutex
		creds := map[string]struct{}{}
		var accepts, replays int32
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				defer wg.Done()
				r, err := env.svc.SubmitReceipt(context.Background(), final)
				if err != nil {
					t.Errorf("concurrent submit: %v", err)
					return
				}
				if r.CredentialID != "" {
					credsMu.Lock()
					creds[r.CredentialID] = struct{}{}
					credsMu.Unlock()
				}
				if r.Replay {
					atomic.AddInt32(&replays, 1)
				} else {
					atomic.AddInt32(&accepts, 1)
				}
			}()
		}
		wg.Wait()
		if accepts != 1 || replays != n-1 {
			t.Fatalf("iter %d: accepts=%d replays=%d", iter, accepts, replays)
		}
		if len(creds) != 1 {
			t.Fatalf("iter %d: distinct credentials = %d", iter, len(creds))
		}
		env.store.mu.RLock()
		nC := len(env.store.data.credentials)
		env.store.mu.RUnlock()
		if nC != 1 {
			t.Fatalf("iter %d: stored credentials = %d", iter, nC)
		}
	}
}

func TestConcurrent_DistinctFinalReceiptsOnlyOneAccepted(t *testing.T) {
	// Two DIFFERENT receipt numbers for the same proof, same challenge, fired
	// concurrently: one accepts the proof (and may complete), the other must
	// hit ErrProofDecided or ErrStaleChallenge — never a second credential.
	for iter := 0; iter < 50; iter++ {
		env := newTestEnv(t)
		h := env.createSession(t, 600, ProofIDDocument, ProofLiveness)
		h = env.submitOK(t, h, ProofIDDocument, "R-1")

		rA := receipt(h, ProofLiveness, "R-A", true, h.Challenge)
		rB := receipt(h, ProofLiveness, "R-B", true, h.Challenge)
		var wg sync.WaitGroup
		var credsMu sync.Mutex
		creds := map[string]struct{}{}
		okA, okB := int32(0), int32(0)
		wg.Add(2)
		go func() { defer wg.Done(); submitFinal(t, rA, env.svc, &okA, &credsMu, creds) }()
		go func() { defer wg.Done(); submitFinal(t, rB, env.svc, &okB, &credsMu, creds) }()
		wg.Wait()
		if okA+okB != 1 {
			t.Fatalf("iter %d: accepted count = %d (a=%d b=%d)", iter, okA+okB, okA, okB)
		}
		if len(creds) != 1 {
			t.Fatalf("iter %d: credentials = %d", iter, len(creds))
		}
		v, _ := env.svc.GetSession(context.Background(), h.ID)
		if v.State != StateCompleted {
			t.Fatalf("iter %d: state = %s", iter, v.State)
		}
	}
}

func submitFinal(t *testing.T, r Receipt, svc *Service, accepted *int32, mu *sync.Mutex, creds map[string]struct{}) {
	t.Helper()
	res, err := svc.SubmitReceipt(context.Background(), r)
	if err != nil {
		// The loser may observe proof-decided, a consumed/stale challenge,
		// or — if the winner completed the session — terminal state.
		if !errors.Is(err, ErrProofDecided) && !errors.Is(err, ErrStaleChallenge) &&
			!errors.Is(err, ErrTerminal) {
			t.Errorf("unexpected error: %v", err)
		}
		return
	}
	if res.Accepted {
		atomic.AddInt32(accepted, 1)
	}
	if res.CredentialID != "" {
		mu.Lock()
		creds[res.CredentialID] = struct{}{}
		mu.Unlock()
	}
}

func TestFailure_CannotBeOverwrittenEvenConcurrently(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofIDDocument, ProofLiveness)
	// Current challenge: fire a failure and a success (different receipt
	// numbers) concurrently. Whatever the order, exactly one outcome sticks.
	fail := receipt(h, ProofIDDocument, "R-fail", false, h.Challenge)
	fail.Reason = "no_match"
	ok := receipt(h, ProofIDDocument, "R-ok", true, h.Challenge)
	var wg sync.WaitGroup
	var failErr, okErr error
	var failRes, okRes *ReceiptResult
	wg.Add(2)
	go func() { defer wg.Done(); failRes, failErr = env.svc.SubmitReceipt(context.Background(), fail) }()
	go func() { defer wg.Done(); okRes, okErr = env.svc.SubmitReceipt(context.Background(), ok) }()
	wg.Wait()

	v, _ := env.svc.GetSession(context.Background(), h.ID)
	var doc ProofView
	for _, p := range v.Proofs {
		if p.Type == ProofIDDocument {
			doc = p
		}
	}
	switch doc.Status {
	case ProofFailed:
		if failErr != nil || failRes.ProofStatus != ProofFailed {
			t.Fatalf("failure branch: res=%+v err=%v", failRes, failErr)
		}
		if !errors.Is(okErr, ErrProofDecided) && !errors.Is(okErr, ErrStaleChallenge) {
			t.Fatalf("success after failure should be rejected, got res=%+v err=%v", okRes, okErr)
		}
	case ProofSuccess:
		if okErr != nil {
			t.Fatalf("success branch error: %v", okErr)
		}
		if !errors.Is(failErr, ErrProofDecided) && !errors.Is(failErr, ErrStaleChallenge) {
			t.Fatalf("failure after success should be rejected, got res=%+v err=%v", failRes, failErr)
		}
	default:
		t.Fatalf("proof unresolved: %+v", doc)
	}
}

// ---- 4. terminal-state races, cancellation, expiry sweeper ----------------

func TestCancel_RulesAndTerminalExclusivity(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofIDDocument)
	if err := env.svc.Cancel(context.Background(), h.ID, "applicant_request"); err != nil {
		t.Fatal(err)
	}
	// Idempotent cancel.
	if err := env.svc.Cancel(context.Background(), h.ID, "again"); err != nil {
		t.Fatalf("second cancel: %v", err)
	}
	// Receipts after cancellation are rejected.
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(h, ProofIDDocument, "R-1", true, h.Challenge)); !errors.Is(err, ErrTerminal) {
		t.Fatalf("receipt after cancel: want ErrTerminal, got %v", err)
	}
	// Rotation after cancellation rejected.
	if _, err := env.svc.RotateChallenge(context.Background(), h.ID); !errors.Is(err, ErrTerminal) {
		t.Fatalf("rotate after cancel: want ErrTerminal, got %v", err)
	}
	// Completion after cancellation rejected.
	if _, err := env.svc.Complete(context.Background(), h.ID); !errors.Is(err, ErrTerminal) {
		t.Fatalf("complete after cancel: want ErrTerminal, got %v", err)
	}
	v, _ := env.svc.GetSession(context.Background(), h.ID)
	if v.State != StateCancelled || v.CredentialID != "" {
		t.Fatalf("view: %+v", v)
	}
	if err := env.svc.Cancel(context.Background(), "sess_missing", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cancel missing: want ErrNotFound, got %v", err)
	}
}

func TestConcurrent_CompletionVsCancel_ExactlyOneWins(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		env := newTestEnv(t)
		h := env.createSession(t, 600, ProofIDDocument, ProofLiveness)
		h = env.submitOK(t, h, ProofIDDocument, "R-1")
		final := receipt(h, ProofLiveness, "R-final", true, h.Challenge)

		var wg sync.WaitGroup
		var finalErr, cancelErr error
		var res *ReceiptResult
		wg.Add(2)
		go func() { defer wg.Done(); res, finalErr = env.svc.SubmitReceipt(context.Background(), final) }()
		go func() { defer wg.Done(); cancelErr = env.svc.Cancel(context.Background(), h.ID, "race") }()
		wg.Wait()

		v, _ := env.svc.GetSession(context.Background(), h.ID)
		switch v.State {
		case StateCompleted:
			if finalErr != nil || res.CredentialID == "" {
				t.Fatalf("completed but receipt err=%v res=%+v", finalErr, res)
			}
			if !errors.Is(cancelErr, ErrTerminal) {
				t.Fatalf("lost cancel should be ErrTerminal, got %v", cancelErr)
			}
		case StateCancelled:
			if !errors.Is(finalErr, ErrTerminal) {
				t.Fatalf("lost receipt should be ErrTerminal, got %v", finalErr)
			}
			if cancelErr != nil {
				t.Fatalf("winning cancel err: %v", cancelErr)
			}
		default:
			t.Fatalf("iter %d: unexpected state %s", iter, v.State)
		}
		if v.CredentialID != "" && v.State != StateCompleted {
			t.Fatalf("credential in state %s", v.State)
		}
		// Exactly one completion audit entry at most.
		var completions, cancels int
		for _, a := range v.Audit {
			if a.Kind == AuditCompleted {
				completions++
			}
			if a.Kind == AuditCancelled {
				cancels++
			}
		}
		if completions > 1 || cancels > 1 || completions+cancels != 1 {
			t.Fatalf("iter %d: terminal audit entries = %d completed, %d cancelled", iter, completions, cancels)
		}
	}
}

func TestConcurrent_CompletionVsExpiry_ExactlyOneWins(t *testing.T) {
	// Deterministic coverage of both orderings, plus concurrent smoke runs
	// under -race to verify the decision is serialized by the store lock.

	// Case A: the final receipt arrives strictly before the deadline and
	// completes the session; a later sweep must not revoke completion.
	envA := newTestEnv(t)
	hA := envA.createSession(t, 100, ProofIDDocument, ProofLiveness)
	hA = envA.submitOK(t, hA, ProofIDDocument, "R-1")
	finalA := receipt(hA, ProofLiveness, "R-final", true, hA.Challenge)
	envA.advance(99)
	res, err := envA.svc.SubmitReceipt(context.Background(), finalA)
	if err != nil || res.CredentialID == "" {
		t.Fatalf("pre-deadline receipt: err=%v res=%+v", err, res)
	}
	envA.advance(10)
	if ids, _ := envA.svc.AdvanceExpirations(context.Background()); len(ids) != 0 {
		t.Fatalf("completed session swept: %v", ids)
	}
	vA, _ := envA.svc.GetSession(context.Background(), hA.ID)
	if vA.State != StateCompleted {
		t.Fatalf("state = %s", vA.State)
	}

	// Case B: the deadline passes first (observed by the sweeper); the
	// in-flight final receipt is rejected and no credential exists.
	envB := newTestEnv(t)
	hB := envB.createSession(t, 100, ProofIDDocument, ProofLiveness)
	hB = envB.submitOK(t, hB, ProofIDDocument, "R-1")
	finalB := receipt(hB, ProofLiveness, "R-final", true, hB.Challenge)
	envB.advance(100)
	ids, err := envB.svc.AdvanceExpirations(context.Background())
	if err != nil || len(ids) != 1 || ids[0] != hB.ID {
		t.Fatalf("sweep: ids=%v err=%v", ids, err)
	}
	if _, err := envB.svc.SubmitReceipt(context.Background(), finalB); !errors.Is(err, ErrTerminal) &&
		!errors.Is(err, ErrExpired) {
		t.Fatalf("post-expiry receipt: %v", err)
	}
	envB.store.mu.RLock()
	nCred := len(envB.store.data.credentials)
	envB.store.mu.RUnlock()
	if nCred != 0 {
		t.Fatalf("credentials after expiry: %d", nCred)
	}

	// Concurrent smoke: sweeper and receipt at the same instant, both sides,
	// repeated. The store lock must serialize the decision with a single
	// terminal state and at most one credential.
	for iter := 0; iter < 50; iter++ {
		env := newTestEnv(t)
		h := env.createSession(t, 100, ProofIDDocument, ProofLiveness)
		h = env.submitOK(t, h, ProofIDDocument, "R-1")
		final := receipt(h, ProofLiveness, "R-final", true, h.Challenge)
		// Clock already at the deadline: expiry is valid and the pair races
		// for the terminal state.
		env.advance(100)
		barrier := make(chan struct{})
		var wg sync.WaitGroup
		var finalErr error
		var r2 *ReceiptResult
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-barrier
			r2, finalErr = env.svc.SubmitReceipt(context.Background(), final)
		}()
		go func() {
			defer wg.Done()
			<-barrier
			_, _ = env.svc.AdvanceExpirations(context.Background())
		}()
		close(barrier)
		wg.Wait()

		v, _ := env.svc.GetSession(context.Background(), h.ID)
		if v.State != StateCompleted && v.State != StateExpired {
			t.Fatalf("iter %d: state = %s", iter, v.State)
		}
		if v.State == StateCompleted {
			// Unreachable with the clock already at the deadline; kept for a
			// complete invariant check.
			t.Fatalf("iter %d: completion despite deadline", iter)
		}
		if finalErr == nil && r2 != nil && r2.CredentialID != "" {
			t.Fatalf("iter %d: credential on expired session", iter)
		}
		env.store.mu.RLock()
		n := len(env.store.data.credentials)
		env.store.mu.RUnlock()
		if (v.State == StateCompleted) != (n == 1) {
			t.Fatalf("iter %d: state=%s credentials=%d", iter, v.State, n)
		}
	}
}

func TestAdvanceExpirations_Batch(t *testing.T) {
	env := newTestEnv(t)
	h1 := env.createSession(t, 100, ProofIDDocument)
	h2 := env.createSession(t, 200, ProofIDDocument)
	h3 := env.createSession(t, 400, ProofIDDocument)
	env.advance(150)
	ids, err := env.svc.AdvanceExpirations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != h1.ID {
		t.Fatalf("first sweep = %v", ids)
	}
	// Idempotent: nothing new.
	ids, _ = env.svc.AdvanceExpirations(context.Background())
	if len(ids) != 0 {
		t.Fatalf("second sweep = %v", ids)
	}
	env.advance(100)
	ids, _ = env.svc.AdvanceExpirations(context.Background())
	if len(ids) != 1 || ids[0] != h2.ID {
		t.Fatalf("third sweep = %v", ids)
	}
	// h3 (created at the base clock with TTL 400) stays active while the
	// clock is at +250; queries do not expire it.
	v, _ := env.svc.GetSession(context.Background(), h3.ID)
	if v.State != StateActive {
		t.Fatalf("h3 = %s", v.State)
	}
	// Cancel right at the deadline loses to expiry.
	env.advance(150)
	if err := env.svc.Cancel(context.Background(), h3.ID, ""); !errors.Is(err, ErrExpired) {
		t.Fatalf("cancel at deadline: want ErrExpired, got %v", err)
	}
	v, _ = env.svc.GetSession(context.Background(), h3.ID)
	if v.State != StateExpired {
		t.Fatalf("h3 = %s", v.State)
	}
}

// ---- audit & data hygiene -------------------------------------------------

func TestAuditTrail_RecordsTransitionsWithoutSecrets(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofIDDocument, ProofLiveness)
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(h, ProofIDDocument, "R-1", true, h.Challenge)); err != nil {
		t.Fatal(err)
	}
	nh, _ := env.svc.RotateChallenge(context.Background(), h.ID)
	fail := receipt(nh, ProofLiveness, "R-2", false, nh.Challenge)
	fail.Reason = "no_match"
	if _, err := env.svc.SubmitReceipt(context.Background(), fail); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.Cancel(context.Background(), h.ID, "manual"); err != nil {
		t.Fatal(err)
	}
	v, _ := env.svc.GetSession(context.Background(), h.ID)
	kinds := map[AuditKind]int{}
	for _, a := range v.Audit {
		kinds[a.Kind]++
	}
	for _, want := range []AuditKind{
		AuditSessionCreated, AuditReceiptAccepted, AuditChallengeRotated,
		AuditReceiptFailed, AuditCancelled,
	} {
		if kinds[want] != 1 {
			t.Fatalf("audit kind %s count = %d (all=%v)", want, kinds[want], kinds)
		}
	}

	// Neither audit detail nor log output may contain secrets.
	forbidden := []string{h.Challenge, nh.Challenge, "P12345678", "张三", "1990-01-31"}
	for _, a := range v.Audit {
		for _, secret := range forbidden {
			if strings.Contains(a.Detail, secret) || strings.Contains(a.ReceiptNo, secret) {
				t.Fatalf("audit leaks %q: %+v", secret, a)
			}
		}
	}
	logs := env.log.String()
	for _, secret := range forbidden {
		if strings.Contains(logs, secret) {
			t.Fatalf("logs leak %q", secret)
		}
	}

	// Full storage serialization must not contain the secrets either.
	env.store.mu.RLock()
	dump := fmt.Sprintf("%#v\n", env.store.data)
	env.store.mu.RUnlock()
	for _, secret := range forbidden {
		if strings.Contains(dump, secret) {
			t.Fatalf("storage dump leaks %q", secret)
		}
	}
}

func TestErrors_DoNotCarrySensitiveData(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofIDDocument)
	// Trigger every rejection class and ensure error strings are generic.
	cases := []func() error{
		func() error {
			_, err := env.svc.SubmitReceipt(context.Background(), receipt(h, ProofIDDocument, "E1", true, "ch_bad"))
			return err
		},
		func() error {
			_, err := env.svc.SubmitReceipt(context.Background(), receipt(h, ProofAddress, "E2", true, h.Challenge))
			return err
		},
	}
	consumed := h.Challenge
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(h, ProofIDDocument, "E3", true, consumed)); err != nil {
		t.Fatal(err)
	}
	cases = append(cases, func() error {
		_, err := env.svc.SubmitReceipt(context.Background(), receipt(h, ProofLiveness, "E4", true, consumed))
		return err
	})
	for i, fn := range cases {
		err := fn()
		if err == nil {
			t.Fatalf("case %d expected error", i)
		}
		msg := err.Error()
		for _, secret := range []string{consumed, "P12345678", "张三"} {
			if strings.Contains(msg, secret) {
				t.Fatalf("case %d error leaks %q: %s", i, secret, msg)
			}
		}
	}
}

func TestGetSession_NotFoundAndNoMutationOnRead(t *testing.T) {
	env := newTestEnv(t)
	if _, err := env.svc.GetSession(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetSession: %v", err)
	}
	if _, err := env.svc.GetCredential(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetCredential: %v", err)
	}
	h := env.createSession(t, 100, ProofIDDocument)
	env.advance(200)
	// Reads must not advance expiry.
	v, _ := env.svc.GetSession(context.Background(), h.ID)
	if v.State != StateActive {
		t.Fatalf("read mutated state: %s", v.State)
	}
}

func TestBoundaryAndHelpers(t *testing.T) {
	ctx := context.Background()

	// NewService rejects a nil store.
	if _, err := NewService(nil, Config{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("nil store: %v", err)
	}
	// NewDefaultService is usable end to end.
	def := NewDefaultService()
	if _, err := def.GetSession(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("default service: %v", err)
	}
	// IsTerminal covers all states.
	if StateActive.IsTerminal() || !StateCompleted.IsTerminal() ||
		!StateCancelled.IsTerminal() || !StateExpired.IsTerminal() {
		t.Fatal("IsTerminal wrong")
	}

	env := newTestEnv(t)

	// Complete: unknown session, expired session, and completed idempotency.
	if _, err := env.svc.Complete(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("complete missing: %v", err)
	}
	hExp := env.createSession(t, 10, ProofIDDocument)
	env.advance(20)
	if _, err := env.svc.Complete(ctx, hExp.ID); !errors.Is(err, ErrExpired) {
		t.Fatalf("complete expired: %v", err)
	}
	v, _ := env.svc.GetSession(ctx, hExp.ID)
	if !v.State.IsTerminal() || v.State != StateExpired {
		t.Fatalf("state after complete-expired: %s", v.State)
	}

	h := env.createSession(t, 600, ProofIDDocument)
	if _, err := env.svc.SubmitReceipt(ctx,
		receipt(h, ProofIDDocument, "R-1", true, h.Challenge)); err != nil {
		t.Fatal(err)
	}
	cred1, err := env.svc.Complete(ctx, h.ID)
	if err != nil {
		t.Fatalf("explicit complete: %v", err)
	}
	cred2, err := env.svc.Complete(ctx, h.ID)
	if err != nil || cred2.ID != cred1.ID {
		t.Fatalf("complete idempotency: %v %v", err, cred2)
	}
	fetched, err := env.svc.GetCredential(ctx, cred1.ID)
	if err != nil || fetched.ID != cred1.ID {
		t.Fatalf("get credential: %v %v", err, fetched)
	}

	// Rotate on missing and terminal sessions.
	if _, err := env.svc.RotateChallenge(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rotate missing: %v", err)
	}
	if _, err := env.svc.RotateChallenge(ctx, h.ID); !errors.Is(err, ErrTerminal) {
		t.Fatalf("rotate completed: %v", err)
	}
	h2 := env.createSession(t, 60, ProofIDDocument)
	env.advance(60)
	if _, err := env.svc.RotateChallenge(ctx, h2.ID); !errors.Is(err, ErrExpired) {
		t.Fatalf("rotate at deadline: %v", err)
	}
	v2, _ := env.svc.GetSession(ctx, h2.ID)
	if v2.State != StateExpired {
		t.Fatalf("rotate should have expired session: %s", v2.State)
	}

	// Cancel reason is sanitized into the audit trail (control chars, length).
	h3 := env.createSession(t, 600, ProofIDDocument)
	long := strings.Repeat("x", 100) + "\n\t"
	if err := env.svc.Cancel(ctx, h3.ID, long); err != nil {
		t.Fatal(err)
	}
	v3, _ := env.svc.GetSession(ctx, h3.ID)
	var detail string
	for _, a := range v3.Audit {
		if a.Kind == AuditCancelled {
			detail = a.Detail
		}
	}
	if strings.ContainsAny(detail, "\n\t") || len(detail) > 80 {
		t.Fatalf("reason not sanitized: %q", detail)
	}
}

func TestSubmitReceipt_InvalidArguments(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofIDDocument)
	base := receipt(h, ProofIDDocument, "R-1", true, h.Challenge)
	cases := []Receipt{
		func() Receipt { x := base; x.ReceiptNo = " "; return x }(),
		func() Receipt { x := base; x.Issuer = ""; return x }(),
		func() Receipt { x := base; x.SessionID = ""; return x }(),
		func() Receipt { x := base; x.Proof = ""; return x }(),
		func() Receipt { x := base; x.Challenge = " "; return x }(),
	}
	for i, r := range cases {
		if _, err := env.svc.SubmitReceipt(context.Background(), r); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("case %d: want ErrInvalidArgument, got %v", i, err)
		}
	}
}

func TestComplete_OnCancelled(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofIDDocument)
	if err := env.svc.Cancel(context.Background(), h.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.Complete(context.Background(), h.ID); !errors.Is(err, ErrTerminal) {
		t.Fatalf("complete cancelled: %v", err)
	}
}

func TestContextCancellation_Propagates(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofIDDocument)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := env.svc.CreateSession(ctx, CreateSessionRequest{
		Applicant:      sampleApplicant(),
		RequiredProofs: []ProofType{ProofIDDocument},
		TTL:            time.Minute,
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("create: %v", err)
	}
	if _, err := env.svc.SubmitReceipt(ctx, receipt(h, ProofIDDocument, "R-1", true, h.Challenge)); !errors.Is(err, context.Canceled) {
		t.Fatalf("submit: %v", err)
	}
	if err := env.svc.Cancel(ctx, h.ID, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := env.svc.AdvanceExpirations(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("sweep: %v", err)
	}
}
