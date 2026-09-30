package goidentityproofing

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// This file adds hardening tests for edge cases around single-use challenge
// consumption, failed-proof idempotency, terminal exclusivity and audit
// hygiene. It complements service_test.go.

// After an accepted receipt consumes the challenge, receipts for other proofs
// cannot ride on the consumed challenge: they must observe "no outstanding
// challenge" (or stale for the consumed hash), and RotateChallenge is the only
// way to make progress.
func TestSubmitReceipt_NoOutstandingChallengeUntilRotation(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofIDDocument, ProofLiveness, ProofFacialMatch)

	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(h, ProofIDDocument, "R-1", true, h.Challenge)); err != nil {
		t.Fatal(err)
	}
	// A brand new receipt number against the (consumed) current hash is stale.
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(h, ProofLiveness, "R-2", true, h.Challenge)); !errors.Is(err, ErrStaleChallenge) {
		t.Fatalf("consumed challenge reuse: want ErrStaleChallenge, got %v", err)
	}
	// An unknown challenge while no challenge is outstanding reports
	// ErrNoChallenge (never silently accepted).
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(h, ProofLiveness, "R-3", true, "ch_some_unknown_value")); !errors.Is(err, ErrNoChallenge) {
		t.Fatalf("unknown challenge while consumed: want ErrNoChallenge, got %v", err)
	}
	// The rejected receipt is persistent: an identical replay reproduces the
	// same rejection rather than being re-evaluated.
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(h, ProofLiveness, "R-3", true, "ch_some_unknown_value")); !errors.Is(err, ErrNoChallenge) {
		t.Fatalf("replay rejected receipt: want ErrNoChallenge, got %v", err)
	}

	// Rotation issues exactly one new, usable challenge and increments the
	// rotation counter monotonically; the old hash stays stale.
	h2, err := env.svc.RotateChallenge(context.Background(), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if h2.Challenge == h.Challenge || h2.ChallengeHash == h.ChallengeHash {
		t.Fatal("rotation did not issue a fresh challenge")
	}
	if h2.ChallengeRotations != 1 {
		t.Fatalf("rotations = %d, want 1", h2.ChallengeRotations)
	}
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(h2, ProofLiveness, "R-4", true, h.Challenge)); !errors.Is(err, ErrStaleChallenge) {
		t.Fatalf("old hash after rotation: want ErrStaleChallenge, got %v", err)
	}
	if _, err := env.svc.SubmitReceipt(context.Background(),
		receipt(h2, ProofLiveness, "R-5", true, h2.Challenge)); err != nil {
		t.Fatalf("fresh challenge must work: %v", err)
	}
}

// A failure permanently decides a proof: not only can it not be overwritten,
// but the identical failing receipt replays the first failed result forever,
// including after the session has been cancelled.
func TestSubmitReceipt_FailureReplayReturnsFailedResult(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofIDDocument, ProofLiveness)
	fail := receipt(h, ProofIDDocument, "R-fail", false, h.Challenge)
	fail.Reason = "no_match"

	first, err := env.svc.SubmitReceipt(context.Background(), fail)
	if err != nil {
		t.Fatal(err)
	}
	if first.ProofStatus != ProofFailed || !first.Accepted || first.Replay {
		t.Fatalf("first failure: %+v", first)
	}
	again, err := env.svc.SubmitReceipt(context.Background(), fail)
	if err != nil {
		t.Fatalf("replay failure: %v", err)
	}
	if !again.Replay || again.ProofStatus != ProofFailed || again.CredentialID != "" {
		t.Fatalf("replayed failure must reproduce failed result: %+v", again)
	}

	// After cancellation the identical replay still reproduces the recorded
	// failure; the failed proof never flips.
	if err := env.svc.Cancel(context.Background(), h.ID, "give_up"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.SubmitReceipt(context.Background(), fail); err != nil {
		t.Fatalf("identical replay after cancel should still replay: %v", err)
	}
	v, _ := env.svc.GetSession(context.Background(), h.ID)
	for _, p := range v.Proofs {
		if p.Type == ProofIDDocument && (p.Status != ProofFailed || p.ReceiptNo != "R-fail") {
			t.Fatalf("failed proof mutated: %+v", p)
		}
	}
}

// Explicit Complete and the completing receipt race: only one credential may
// ever exist and the session reaches a single completed state.
func TestConcurrent_ReceiptCompletionVsExplicitComplete(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		env := newTestEnv(t)
		h := env.createSession(t, 600, ProofIDDocument, ProofLiveness)
		h = env.submitOK(t, h, ProofIDDocument, "R-1")
		final := receipt(h, ProofLiveness, "R-final", true, h.Challenge)

		var wg sync.WaitGroup
		var receiptCred, completeCred string
		var receiptErr, completeErr error
		barrier := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-barrier
			res, err := env.svc.SubmitReceipt(context.Background(), final)
			receiptErr = err
			if err == nil {
				receiptCred = res.CredentialID
			}
		}()
		go func() {
			defer wg.Done()
			<-barrier
			c, err := env.svc.Complete(context.Background(), h.ID)
			completeErr = err
			if err == nil {
				completeCred = c.ID
			}
		}()
		close(barrier)
		wg.Wait()

		// The completing receipt must always win its credential; explicit
		// Complete either joins the same credential or loses with a generic
		// error. Either way exactly one credential exists.
		if receiptErr != nil || receiptCred == "" {
			t.Fatalf("iter %d: completing receipt failed: %v", iter, receiptErr)
		}
		if completeErr == nil && completeCred != receiptCred {
			t.Fatalf("iter %d: two distinct credentials: %s vs %s", iter, receiptCred, completeCred)
		}
		if completeErr != nil && !errors.Is(completeErr, ErrIncomplete) &&
			!errors.Is(completeErr, ErrTerminal) {
			t.Fatalf("iter %d: unexpected complete error: %v", iter, completeErr)
		}
		env.store.mu.RLock()
		n := len(env.store.data.credentials)
		env.store.mu.RUnlock()
		if n != 1 {
			t.Fatalf("iter %d: credentials = %d", iter, n)
		}
		v, _ := env.svc.GetSession(context.Background(), h.ID)
		if v.State != StateCompleted {
			t.Fatalf("iter %d: state = %s", iter, v.State)
		}
	}
}

// Three-way race among the final receipt, cancellation and expiry. Exactly
// one terminal state wins, no credential is issued at/past the deadline, and
// the audit log records exactly one terminal transition.
func TestConcurrent_ReceiptCancelExpiry_OneTerminal(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		env := newTestEnv(t)
		// Deadline at +100; the clock jumps to exactly the deadline so the
		// cancellation/expiry contenders are simultaneously plausible and the
		// completing receipt must lose.
		h := env.createSession(t, 100, ProofIDDocument, ProofLiveness)
		h = env.submitOK(t, h, ProofIDDocument, "R-1")
		final := receipt(h, ProofLiveness, "R-final", true, h.Challenge)
		env.advance(100)

		var wg sync.WaitGroup
		var rErr, cErr error
		barrier := make(chan struct{})
		wg.Add(3)
		go func() {
			defer wg.Done()
			<-barrier
			_, rErr = env.svc.SubmitReceipt(context.Background(), final)
		}()
		go func() {
			defer wg.Done()
			<-barrier
			cErr = env.svc.Cancel(context.Background(), h.ID, "race")
		}()
		go func() {
			defer wg.Done()
			<-barrier
			_, _ = env.svc.AdvanceExpirations(context.Background())
		}()
		close(barrier)
		wg.Wait()

		v, _ := env.svc.GetSession(context.Background(), h.ID)
		if !v.State.IsTerminal() {
			t.Fatalf("iter %d: non-terminal state %s", iter, v.State)
		}
		// At the deadline completion can never win: expiry/cancel dominate.
		if v.State == StateCompleted {
			t.Fatalf("iter %d: completion won at the deadline", iter)
		}
		if rErr == nil {
			t.Fatalf("iter %d: receipt accepted in state %s", iter, v.State)
		}
		switch v.State {
		case StateCancelled:
			if cErr != nil {
				t.Fatalf("cancel won but errored: %v", cErr)
			}
		case StateExpired:
			if !errors.Is(cErr, ErrExpired) && !errors.Is(cErr, ErrTerminal) {
				t.Fatalf("cancel lost but err=%v", cErr)
			}
		}
		env.store.mu.RLock()
		nCred := len(env.store.data.credentials)
		env.store.mu.RUnlock()
		if nCred != 0 {
			t.Fatalf("iter %d: credentials = %d", iter, nCred)
		}
		terminals := 0
		for _, a := range v.Audit {
			switch a.Kind {
			case AuditCompleted, AuditCancelled, AuditExpired:
				terminals++
			}
		}
		if terminals != 1 {
			t.Fatalf("iter %d: terminal audit entries = %d", iter, terminals)
		}
	}
}

// Caller-supplied failure reasons reach storage and audit detail; they must be
// sanitized (control characters stripped, length bounded) and must never carry
// the plaintext challenge into stored data, logs or the audit trail.
func TestReceiptReason_SanitizedInStorageAuditAndLogs(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofIDDocument)
	fail := receipt(h, ProofIDDocument, "R-1", false, h.Challenge)
	fail.Reason = "bad\n\t\r" + strings.Repeat("x", 200) + h.Challenge
	if _, err := env.svc.SubmitReceipt(context.Background(), fail); err != nil {
		t.Fatal(err)
	}
	v, _ := env.svc.GetSession(context.Background(), h.ID)
	var storedReason string
	for _, p := range v.Proofs {
		if p.Type == ProofIDDocument {
			storedReason = p.Reason
		}
	}
	if strings.ContainsAny(storedReason, "\n\t\r") || len(storedReason) > 64 {
		t.Fatalf("stored reason not sanitized: %q", storedReason)
	}
	for _, a := range v.Audit {
		if strings.Contains(a.Detail, h.Challenge) {
			t.Fatalf("audit detail leaks challenge: %+v", a)
		}
		if strings.ContainsAny(a.Detail, "\n\t\r") || len(a.Detail) > 80 {
			t.Fatalf("audit detail not sanitized: %q", a.Detail)
		}
	}
	if strings.Contains(env.log.String(), h.Challenge) {
		t.Fatal("logs leak challenge via reason")
	}
	env.store.mu.RLock()
	dump := fmt.Sprintf("%#v\n", env.store.data)
	env.store.mu.RUnlock()
	if strings.Contains(dump, h.Challenge) {
		t.Fatal("storage dump leaks challenge via reason")
	}
}

// Rejected receipts (e.g. terminal state) leave an audit trail, and their
// identical replays return the same rejection while never mutating the
// session or producing credentials.
func TestSubmitReceipt_RejectionAuditAndReplayAfterCancel(t *testing.T) {
	env := newTestEnv(t)
	h := env.createSession(t, 600, ProofIDDocument)
	if err := env.svc.Cancel(context.Background(), h.ID, ""); err != nil {
		t.Fatal(err)
	}
	r := receipt(h, ProofIDDocument, "R-late", true, h.Challenge)
	for i := 0; i < 2; i++ {
		if _, err := env.svc.SubmitReceipt(context.Background(), r); !errors.Is(err, ErrTerminal) {
			t.Fatalf("attempt %d: want ErrTerminal, got %v", i, err)
		}
	}
	v, _ := env.svc.GetSession(context.Background(), h.ID)
	if v.State != StateCancelled || v.CredentialID != "" {
		t.Fatalf("state mutated by rejected receipt: %+v", v)
	}
	var rejected, replays int
	for _, a := range v.Audit {
		switch a.Kind {
		case AuditReceiptRejected:
			rejected++
		case AuditReceiptReplay:
			replays++
		}
	}
	if rejected != 1 || replays != 1 {
		t.Fatalf("audit rejected=%d replay=%d", rejected, replays)
	}
}

// Out-of-order proofs (reverse order) still complete exactly once when the
// last pending proof succeeds.
func TestSubmitReceipt_ReverseOrderCompletesOnce(t *testing.T) {
	env := newTestEnv(t)
	order := []ProofType{ProofIDDocument, ProofFacialMatch, ProofLiveness}
	h := env.createSession(t, 600, order...)
	current := h
	for i := len(order) - 1; i >= 0; i-- {
		no := fmt.Sprintf("R-%s", order[i])
		res, err := env.svc.SubmitReceipt(context.Background(),
			receipt(current, order[i], no, true, current.Challenge))
		if err != nil {
			t.Fatalf("proof %s: %v", order[i], err)
		}
		if i == 0 {
			if res.CredentialID == "" || res.SessionStatus != StateCompleted {
				t.Fatalf("final reversed receipt: %+v", res)
			}
		} else if res.CredentialID != "" {
			t.Fatalf("premature completion at %s", order[i])
		} else {
			current, err = env.svc.RotateChallenge(context.Background(), h.ID)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	v, _ := env.svc.GetSession(context.Background(), h.ID)
	if v.State != StateCompleted || v.CredentialID == "" {
		t.Fatalf("view: %+v", v)
	}
	for _, p := range v.Proofs {
		if p.Status != ProofSuccess {
			t.Fatalf("proof %s = %s", p.Type, p.Status)
		}
	}
}
