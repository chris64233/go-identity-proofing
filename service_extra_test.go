package goidentityproofing

import (
	"errors"
	"testing"
	"time"
)

func TestMasking(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"name 3 runes", maskName("张三丰"), "张**"},
		{"name ascii", maskName("John"), "J***"},
		{"name single", maskName("J"), "J*"},
		{"name empty", maskName("  "), ""},
		{"doc long", maskDocumentNumber("E123456789"), "******6789"},
		{"doc short", maskDocumentNumber("1234"), "****"},
		{"doc empty", maskDocumentNumber(""), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("got %q, want %q", tc.got, tc.want)
			}
		})
	}
	label := applicantLabel(validApplicant())
	if label != "张**|******6789" {
		t.Fatalf("label = %q", label)
	}
}

func TestReceiptContentHash_DeterministicAndSensitive(t *testing.T) {
	r := successReceipt("R-1", "a", "challenge-plaintext")
	h1 := receiptContentHash(testPepper, r)
	h2 := receiptContentHash(testPepper, successReceipt("R-1", "a", "challenge-plaintext"))
	if h1 != h2 {
		t.Fatal("identical receipts produced different hashes")
	}
	// 回执号不参与内容哈希：同内容不同号应得到相同内容哈希，
	// 这样“同号异内容”冲突与“同内容不同号”互不干扰。
	h3 := receiptContentHash(testPepper, successReceipt("R-OTHER", "a", "challenge-plaintext"))
	if h1 != h3 {
		t.Fatal("receipt number must not participate in content hash")
	}
	// 结果、原因、证明类型变化都应改变哈希。
	mutated := []Receipt{
		{ReceiptNumber: "R-1", ProofType: "a", Challenge: "challenge-plaintext", Success: false},
		{ReceiptNumber: "R-1", ProofType: "b", Challenge: "challenge-plaintext", Success: true},
		{ReceiptNumber: "R-1", ProofType: "a", Challenge: "other-challenge", Success: true},
		{ReceiptNumber: "R-1", ProofType: "a", Challenge: "challenge-plaintext", Success: true, Reason: "x"},
	}
	for i, m := range mutated {
		if receiptContentHash(testPepper, m) == h1 {
			t.Fatalf("mutated receipt %d has same hash", i)
		}
	}
}

func TestIssueChallenge_Flows(t *testing.T) {
	svc, fc := newTestService(t)
	cs := mustCreateSession(t, svc, []ProofType{"a", "b"}, fc.Now().Add(30*time.Minute))

	if _, err := svc.IssueChallenge(cs.Session.ID, "zzz"); !errors.Is(err, ErrUnknownProof) {
		t.Fatalf("unknown proof: err = %v", err)
	}
	if _, err := svc.IssueChallenge("", "a"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("empty session: err = %v", err)
	}
	if _, err := svc.IssueChallenge("ses_nope", "a"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("missing session: err = %v", err)
	}

	// 完成证明后不再签发挑战。
	submitSucceed(t, svc, cs.Session.ID, "R-a", "a", cs.Challenges["a"])
	if _, err := svc.IssueChallenge(cs.Session.ID, "a"); !errors.Is(err, ErrProofAlreadyHandled) {
		t.Fatalf("handled proof: err = %v, want ErrProofAlreadyHandled", err)
	}

	// 取消后拒绝签发。
	if _, err := svc.CancelSession(cs.Session.ID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := svc.IssueChallenge(cs.Session.ID, "b"); !errors.Is(err, ErrSessionCanceled) {
		t.Fatalf("after cancel: err = %v, want ErrSessionCanceled", err)
	}
}

func TestCancel_IdempotentErrorsAndQuery(t *testing.T) {
	svc, fc := newTestService(t)
	cs := mustCreateSession(t, svc, []ProofType{"a"}, fc.Now().Add(30*time.Minute))

	if _, err := svc.CancelSession(""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("empty id: err = %v", err)
	}
	if _, err := svc.CancelSession("ses_nope"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("missing: err = %v", err)
	}
	view, err := svc.CancelSession(cs.Session.ID)
	if err != nil {
		t.Fatalf("first cancel: %v", err)
	}
	if view.Status != StatusCanceled {
		t.Fatalf("status = %s", view.Status)
	}
	if _, err := svc.CancelSession(cs.Session.ID); !errors.Is(err, ErrSessionCanceled) {
		t.Fatalf("second cancel: err = %v, want ErrSessionCanceled", err)
	}
	got, err := svc.GetSession(cs.Session.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.Status != StatusCanceled {
		t.Fatalf("query status = %s", got.Status)
	}
}

func TestSubmitResult_InvalidArgs(t *testing.T) {
	svc, fc := newTestService(t)
	cs := mustCreateSession(t, svc, []ProofType{"a"}, fc.Now().Add(30*time.Minute))
	base := successReceipt("R-1", "a", cs.Challenges["a"])
	cases := map[string]func() (string, Receipt){
		"empty session":   func() (string, Receipt) { return "", base },
		"empty receipt":   func() (string, Receipt) { r := base; r.ReceiptNumber = ""; return cs.Session.ID, r },
		"empty proof":     func() (string, Receipt) { r := base; r.ProofType = ""; return cs.Session.ID, r },
		"empty challenge": func() (string, Receipt) { r := base; r.Challenge = ""; return cs.Session.ID, r },
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			sid, r := fn()
			if _, err := svc.SubmitResult(sid, r); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
		})
	}
}

func TestSessionWithSingleProof_FailureDoesNotCreateCredential(t *testing.T) {
	svc, fc := newTestService(t)
	cs := mustCreateSession(t, svc, []ProofType{"a"}, fc.Now().Add(30*time.Minute))
	res, err := svc.SubmitResult(cs.Session.ID, failReceipt("R-1", "a", cs.Challenges["a"], "nope"))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if res.Credential != nil || res.Session.Credential != nil {
		t.Fatalf("failure produced credential: %+v", res)
	}
	if res.Session.Status != StatusFailed {
		t.Fatalf("status = %s", res.Session.Status)
	}
}

func TestGetAuditTrail_Errors(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := svc.GetAuditTrail(""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("empty: err = %v", err)
	}
	if _, err := svc.GetAuditTrail("ses_nope"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("missing: err = %v", err)
	}
}

func TestChallengeTTL_OptionClamped(t *testing.T) {
	fc := newFakeClock(time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC))
	// 过短/过长的配置被忽略，使用默认 TTL。
	svc, err := NewService(NewMemoryRepository(),
		WithClock(fc.Now), WithPepper(testPepper),
		WithChallengeTTL(time.Second),
		WithChallengeTTL(48*time.Hour),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	cs := mustCreateSession(t, svc, []ProofType{"a"}, fc.Now().Add(time.Hour))
	if !cs.Session.Proofs["a"].ChallengeExpiresAt.Equal(fc.Now().Add(defaultChallengeTTL)) {
		t.Fatalf("expires = %v, want default ttl", cs.Session.Proofs["a"].ChallengeExpiresAt)
	}
}
