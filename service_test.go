package goidentityproofing

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- 测试夹具 ---------------------------------------------------------------

const (
	testPepper = "unit-test-pepper"
	testName   = "张三丰"
	testDoc    = "E123456789"
)

var testProofs = []ProofType{"id_document", "face_match", "address"}

func newTestService(t *testing.T, opts ...Option) (*Service, *fakeClock) {
	t.Helper()
	fc := newFakeClock(time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC))
	allOpts := append([]Option{WithClock(fc.Now), WithPepper(testPepper)}, opts...)
	svc, err := NewService(NewMemoryRepository(), allOpts...)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, fc
}

func validApplicant() ApplicantInfo {
	return ApplicantInfo{
		FullName:       testName,
		DocumentType:   "passport",
		DocumentNumber: testDoc,
		Extra:          map[string]string{"country": "CN"},
	}
}

func mustCreateSession(t *testing.T, svc *Service, proofs []ProofType, deadline time.Time) *CreatedSession {
	t.Helper()
	cs, err := svc.CreateSession(CreateSessionRequest{
		RequiredProofs: proofs,
		Applicant:      validApplicant(),
		Deadline:       deadline,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return cs
}

func successReceipt(num string, pt ProofType, challenge string) Receipt {
	return Receipt{ReceiptNumber: num, ProofType: pt, Challenge: challenge, Success: true}
}

func failReceipt(num string, pt ProofType, challenge, reason string) Receipt {
	return Receipt{ReceiptNumber: num, ProofType: pt, Challenge: challenge, Success: false, Reason: reason}
}

// submitSucceed 提交成功回执并断言无错误。
func submitSucceed(t *testing.T, svc *Service, sid string, num string, pt ProofType, ch string) *ResultView {
	t.Helper()
	res, err := svc.SubmitResult(sid, successReceipt(num, pt, ch))
	if err != nil {
		t.Fatalf("SubmitResult(%s,%s): %v", num, pt, err)
	}
	return res
}

// fakeClock 是可手动推进的时钟。
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{t: start} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
	return c.t
}

// ---- 创建会话 ---------------------------------------------------------------

func TestCreateSession_FreezesInputs(t *testing.T) {
	svc, fc := newTestService(t)
	deadline := fc.Now().Add(10 * time.Minute)
	cs := mustCreateSession(t, svc, testProofs, deadline)

	if cs.Session.Status != StatusActive {
		t.Fatalf("status = %s, want active", cs.Session.Status)
	}
	if len(cs.Challenges) != len(testProofs) {
		t.Fatalf("challenges = %d, want %d", len(cs.Challenges), len(testProofs))
	}
	seen := map[string]bool{}
	for pt, ch := range cs.Challenges {
		if ch == "" {
			t.Fatalf("empty challenge for %s", pt)
		}
		if seen[ch] {
			t.Fatalf("duplicate challenge issued: %s", ch)
		}
		seen[ch] = true
	}
	if cs.Session.ApplicantDigest == "" {
		t.Fatal("applicant digest empty")
	}
	if !cs.Session.Deadline.Equal(deadline) {
		t.Fatalf("deadline = %v, want %v", cs.Session.Deadline, deadline)
	}
	// 脱敏标签不含完整姓名/证件号。
	if cs.Session.ApplicantLabel == testName || strings.Contains(cs.Session.ApplicantLabel, testDoc) {
		t.Fatalf("applicant label leaks sensitive data: %q", cs.Session.ApplicantLabel)
	}
	if !strings.Contains(cs.Session.ApplicantLabel, "****") {
		t.Fatalf("label not masked: %q", cs.Session.ApplicantLabel)
	}
}

func TestCreateSession_DedupProofsAndDefaults(t *testing.T) {
	svc, fc := newTestService(t)
	cs, err := svc.CreateSession(CreateSessionRequest{
		RequiredProofs: []ProofType{"a", "a", "b"},
		Applicant:      validApplicant(),
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if len(cs.Session.RequiredProofs) != 2 {
		t.Fatalf("proofs = %v, want deduped 2", cs.Session.RequiredProofs)
	}
	if cs.Session.Deadline.Equal(fc.Now()) || !cs.Session.Deadline.After(fc.Now()) {
		t.Fatalf("default deadline not in future: %v", cs.Session.Deadline)
	}
}

func TestCreateSession_InvalidArgs(t *testing.T) {
	svc, fc := newTestService(t)
	cases := []struct {
		name string
		req  CreateSessionRequest
	}{
		{"no proofs", CreateSessionRequest{Applicant: validApplicant()}},
		{"empty proof type", CreateSessionRequest{RequiredProofs: []ProofType{""}, Applicant: validApplicant()}},
		{"no name", CreateSessionRequest{RequiredProofs: testProofs, Applicant: ApplicantInfo{DocumentNumber: "x"}}},
		{"no doc", CreateSessionRequest{RequiredProofs: testProofs, Applicant: ApplicantInfo{FullName: "x"}}},
		{"deadline past", CreateSessionRequest{RequiredProofs: testProofs, Applicant: validApplicant(), Deadline: fc.Now().Add(-time.Minute)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.CreateSession(tc.req); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
		})
	}
}

// ---- 敏感数据不落持久层 -----------------------------------------------------

func TestPersistence_ContainsNoPlaintextSecrets(t *testing.T) {
	svc, fc := newTestService(t)
	cs := mustCreateSession(t, svc, testProofs, fc.Now().Add(10*time.Minute))
	sid := cs.Session.ID

	// 完成全部证明后持久层中应同时存在挑战哈希、回执记录与凭证哈希。
	var token string
	for _, pt := range testProofs {
		res := submitSucceed(t, svc, sid, "R-"+string(pt), pt, cs.Challenges[pt])
		if res.Credential != nil {
			token = res.Credential.Token
		}
	}
	if token == "" {
		t.Fatal("completion did not return a credential token")
	}

	repo := svc.repo.(*MemoryRepository)
	for _, raw := range repo.Snapshot() {
		data, err := json.Marshal(raw)
		if err != nil {
			t.Fatalf("marshal snapshot: %v", err)
		}
		text := string(data)
		for _, secret := range []string{
			cs.Challenges["id_document"], // 挑战明文
			testName,                     // 姓名
			testDoc,                      // 证件号
			token,                        // 凭证令牌明文
		} {
			if secret == "" {
				continue
			}
			if bytes.Contains(data, []byte(secret)) {
				t.Fatalf("persisted record leaks secret %q: %s", secret, text)
			}
		}
	}
}

func TestPersistence_ChallengeStoredOnlyAsHash(t *testing.T) {
	svc, fc := newTestService(t)
	cs := mustCreateSession(t, svc, []ProofType{"id_document"}, fc.Now().Add(10*time.Minute))
	raw, ok := svc.repo.(*MemoryRepository).Snapshot()[cs.Session.ID]
	if !ok {
		t.Fatal("session missing")
	}
	ch := raw.Proofs["id_document"].Challenge
	if ch.Hash != sha256Hex(cs.Challenges["id_document"]) {
		t.Fatal("stored challenge is not sha256 of plaintext")
	}
	if !ch.ExpiresAt.Equal(fc.Now().Add(defaultChallengeTTL)) {
		t.Fatalf("challenge expires %v, want %v", ch.ExpiresAt, fc.Now().Add(defaultChallengeTTL))
	}
}

func TestErrorsAndAudit_ContainNoSecrets(t *testing.T) {
	svc, fc := newTestService(t)
	cs := mustCreateSession(t, svc, testProofs, fc.Now().Add(10*time.Minute))
	sid := cs.Session.ID
	ch := cs.Challenges["id_document"]

	// 制造若干错误路径并检查错误文本。
	_, err := svc.SubmitResult(sid, Receipt{ReceiptNumber: "X", ProofType: "id_document", Challenge: "wrong-challenge", Success: true})
	if !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("err = %v, want ErrChallengeMismatch", err)
	}
	if strings.Contains(err.Error(), "wrong-challenge") {
		t.Fatalf("error message leaks challenge: %v", err)
	}

	// 审计轨迹不得包含挑战明文或证件信息。
	audit, err := svc.GetAuditTrail(sid)
	if err != nil {
		t.Fatalf("GetAuditTrail: %v", err)
	}
	for _, a := range audit {
		joined := a.Detail + string(a.Action) + string(a.ProofType)
		if strings.Contains(joined, ch) || strings.Contains(joined, testDoc) || strings.Contains(joined, testName) {
			t.Fatalf("audit entry leaks secret: %+v", a)
		}
	}
}

// ---- 回执幂等与冲突 ---------------------------------------------------------

func TestSubmitResult_IdempotentSameContent(t *testing.T) {
	svc, fc := newTestService(t)
	cs := mustCreateSession(t, svc, testProofs, fc.Now().Add(10*time.Minute))
	sid := cs.Session.ID
	r := successReceipt("R-100", "id_document", cs.Challenges["id_document"])

	first, err := svc.SubmitResult(sid, r)
	if err != nil {
		t.Fatalf("first submit: %v", err)
	}
	if first.Replayed {
		t.Fatal("first submit marked replayed")
	}

	// 完全相同的回执重复到达（甚至会话过期后），返回首次结果。
	fc.Advance(11 * time.Minute)
	second, err := svc.SubmitResult(sid, r)
	if err != nil {
		t.Fatalf("replay submit: %v", err)
	}
	if !second.Replayed {
		t.Fatal("duplicate receipt not marked replayed")
	}
	if second.ProofType != "id_document" || !second.Success {
		t.Fatalf("replay result = %+v, want first result", second)
	}
	// 幂等重放不再下发任何凭证明文（本会话也未完成）。
	if second.Credential != nil && second.Credential.Token != "" {
		t.Fatal("replay must not return credential token")
	}
}

func TestSubmitResult_ConflictOnContentChange(t *testing.T) {
	svc, fc := newTestService(t)
	cs := mustCreateSession(t, svc, testProofs, fc.Now().Add(30*time.Minute))
	sid := cs.Session.ID

	first := successReceipt("R-200", "id_document", cs.Challenges["id_document"])
	if _, err := svc.SubmitResult(sid, first); err != nil {
		t.Fatalf("first submit: %v", err)
	}

	variants := []Receipt{
		{ReceiptNumber: "R-200", ProofType: "id_document", Challenge: cs.Challenges["id_document"], Success: false, Reason: "mismatch"},
		{ReceiptNumber: "R-200", ProofType: "face_match", Challenge: cs.Challenges["face_match"], Success: true},
		{ReceiptNumber: "R-200", ProofType: "id_document", Challenge: cs.Challenges["id_document"], Success: true, Reason: "different"},
	}
	for i, v := range variants {
		if _, err := svc.SubmitResult(sid, v); !errors.Is(err, ErrReceiptConflict) {
			t.Fatalf("variant %d: err = %v, want ErrReceiptConflict", i, err)
		}
	}

	// 首次结果不受冲突影响：原证明仍为 succeeded。
	view, err := svc.GetSession(sid)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if view.Proofs["id_document"].Status != ProofSucceeded {
		t.Fatalf("proof status = %s, want succeeded", view.Proofs["id_document"].Status)
	}
}

func TestSubmitResult_ReplayCompletedSessionReturnsFirstOutcome(t *testing.T) {
	svc, fc := newTestService(t)
	cs := mustCreateSession(t, svc, []ProofType{"id_document"}, fc.Now().Add(10*time.Minute))
	sid := cs.Session.ID
	r := successReceipt("R-1", "id_document", cs.Challenges["id_document"])
	first, err := svc.SubmitResult(sid, r)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if first.Session.Status != StatusCompleted || first.Credential == nil || first.Credential.Token == "" {
		t.Fatalf("completion result wrong: %+v", first)
	}
	tokenFirst := first.Credential.Token

	// 重复完成回执：返回首次成功结果（Replayed），但不再下发明文令牌。
	second, err := svc.SubmitResult(sid, r)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !second.Replayed || !second.Success {
		t.Fatalf("replay = %+v", second)
	}
	if second.Session.Status != StatusCompleted {
		t.Fatalf("status = %s", second.Session.Status)
	}
	if second.Session.Credential == nil || second.Session.Credential.Token != "" {
		t.Fatalf("replay must expose token hash only: %+v", second.Session.Credential)
	}
	if second.Session.Credential.TokenHash != sha256Hex(tokenFirst) {
		t.Fatal("credential identity changed across replay")
	}
}

// ---- 挑战校验 ---------------------------------------------------------------

func TestSubmitResult_ChallengeMismatch(t *testing.T) {
	svc, fc := newTestService(t)
	cs := mustCreateSession(t, svc, testProofs, fc.Now().Add(30*time.Minute))
	sid := cs.Session.ID

	_, err := svc.SubmitResult(sid, successReceipt("R-1", "id_document", "not-the-issued-challenge"))
	if !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("err = %v, want ErrChallengeMismatch", err)
	}
	// 用了其它证明的挑战也不匹配。
	_, err = svc.SubmitResult(sid, successReceipt("R-2", "id_document", cs.Challenges["face_match"]))
	if !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("err = %v, want ErrChallengeMismatch (cross-proof)", err)
	}
	view, _ := svc.GetSession(sid)
	if view.Proofs["id_document"].Status != ProofPending {
		t.Fatal("rejected receipt must not change proof state")
	}
}

func TestSubmitResult_ChallengeExpiry(t *testing.T) {
	svc, fc := newTestService(t, WithChallengeTTL(time.Minute))
	cs := mustCreateSession(t, svc, testProofs, fc.Now().Add(30*time.Minute))
	sid := cs.Session.ID

	fc.Advance(2 * time.Minute)
	_, err := svc.SubmitResult(sid, successReceipt("R-1", "id_document", cs.Challenges["id_document"]))
	if !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("err = %v, want ErrChallengeExpired", err)
	}

	// 轮换挑战后旧挑战被拒、新挑战可用。
	issued, err := svc.IssueChallenge(sid, "id_document")
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	_, err = svc.SubmitResult(sid, successReceipt("R-2", "id_document", cs.Challenges["id_document"]))
	if !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("old challenge after rotation: err = %v, want ErrChallengeMismatch", err)
	}
	if _, err := svc.SubmitResult(sid, successReceipt("R-3", "id_document", issued.Challenge)); err != nil {
		t.Fatalf("new challenge submit: %v", err)
	}
}

func TestChallenge_SingleUse(t *testing.T) {
	svc, fc := newTestService(t)
	cs := mustCreateSession(t, svc, []ProofType{"a", "b"}, fc.Now().Add(30*time.Minute))
	sid := cs.Session.ID
	// 同一挑战明文搭配两个不同回执号：第二次必须拒绝（一次性）。
	r1 := successReceipt("R-1", "a", cs.Challenges["a"])
	if _, err := svc.SubmitResult(sid, r1); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := svc.SubmitResult(sid, successReceipt("R-2", "a", cs.Challenges["a"]))
	if !errors.Is(err, ErrProofAlreadyHandled) {
		t.Fatalf("reuse challenge: err = %v, want ErrProofAlreadyHandled", err)
	}
}

// ---- 证明归属 / 会话匹配 ----------------------------------------------------

func TestSubmitResult_WrongSessionAndProof(t *testing.T) {
	svc, fc := newTestService(t)
	cs1 := mustCreateSession(t, svc, []ProofType{"a"}, fc.Now().Add(30*time.Minute))
	cs2 := mustCreateSession(t, svc, []ProofType{"a"}, fc.Now().Add(30*time.Minute))

	if _, err := svc.SubmitResult("ses_does_not_exist", successReceipt("R-1", "a", cs1.Challenges["a"])); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("missing session: err = %v", err)
	}
	// 会话2 的挑战不能用于会话1。
	if _, err := svc.SubmitResult(cs1.Session.ID, successReceipt("R-1", "a", cs2.Challenges["a"])); !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("cross-session challenge: err = %v, want ErrChallengeMismatch", err)
	}
	// 清单之外的证明类型。
	if _, err := svc.SubmitResult(cs1.Session.ID, successReceipt("R-2", "zzz", "whatever")); !errors.Is(err, ErrUnknownProof) {
		t.Fatalf("unknown proof: err = %v, want ErrUnknownProof", err)
	}
}

// ---- 失败不可覆盖、终态互斥 -------------------------------------------------

func TestSubmitResult_FailureIsTerminal(t *testing.T) {
	svc, fc := newTestService(t)
	cs := mustCreateSession(t, svc, testProofs, fc.Now().Add(30*time.Minute))
	sid := cs.Session.ID

	if _, err := svc.SubmitResult(sid, failReceipt("R-F", "id_document", cs.Challenges["id_document"], "doc forged")); err != nil {
		t.Fatalf("fail submit: %v", err)
	}
	view, _ := svc.GetSession(sid)
	if view.Status != StatusFailed || view.Proofs["id_document"].Status != ProofFailed {
		t.Fatalf("status = %s proof = %s, want failed/failed", view.Status, view.Proofs["id_document"].Status)
	}

	// 后来的成功回执（新回执号、新挑战）不能静默覆盖失败。
	issued, err := svc.IssueChallenge(sid, "id_document")
	if err == nil {
		t.Fatalf("IssueChallenge on failed session should fail, got %+v", issued)
	}
	if !errors.Is(err, ErrSessionTerminal) {
		t.Fatalf("IssueChallenge err = %v, want ErrSessionTerminal", err)
	}
	_, err = svc.SubmitResult(sid, successReceipt("R-OK", "id_document", cs.Challenges["id_document"]))
	if !errors.Is(err, ErrSessionTerminal) {
		t.Fatalf("override failure: err = %v, want ErrSessionTerminal", err)
	}
	view, _ = svc.GetSession(sid)
	if view.Status != StatusFailed {
		t.Fatalf("status mutated to %s", view.Status)
	}
}

func TestSubmitResult_OutOfOrderOnlyCompletesOnce(t *testing.T) {
	svc, fc := newTestService(t)
	cs := mustCreateSession(t, svc, testProofs, fc.Now().Add(30*time.Minute))
	sid := cs.Session.ID

	submitSucceed(t, svc, sid, "R-3", "address", cs.Challenges["address"])
	submitSucceed(t, svc, sid, "R-1", "id_document", cs.Challenges["id_document"])
	view, _ := svc.GetSession(sid)
	if view.Status != StatusActive {
		t.Fatalf("status = %s, want still active", view.Status)
	}
	last := submitSucceed(t, svc, sid, "R-2", "face_match", cs.Challenges["face_match"])
	if last.Session.Status != StatusCompleted || last.Credential == nil || last.Credential.Token == "" {
		t.Fatalf("final receipt did not complete session: %+v", last)
	}
}

// ---- 凭证唯一性（并发） -----------------------------------------------------

func TestConcurrentFinalProofs_SingleCredential(t *testing.T) {
	svc, fc := newTestService(t)
	const n = 8
	proofs := make([]ProofType, n)
	for i := range proofs {
		proofs[i] = ProofType(fmt.Sprintf("p%d", i))
	}
	cs := mustCreateSession(t, svc, proofs, fc.Now().Add(30*time.Minute))
	sid := cs.Session.ID

	// 先串行完成前 n-1 项。
	for i := 0; i < n-1; i++ {
		pt := proofs[i]
		submitSucceed(t, svc, sid, "R-"+string(pt), pt, cs.Challenges[pt])
	}

	// 最后一项并发提交多份（不同回执号 + 轮换挑战的极端竞争由“证明终态”拦截；
	// 这里用同挑战不同回执号验证一次性 + 终态保护）。
	pt := proofs[n-1]
	var wg sync.WaitGroup
	var mu sync.Mutex
	var completions, terminals int
	credIDs := map[string]struct{}{}
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			num := fmt.Sprintf("R-%s-%d", pt, i)
			res, err := svc.SubmitResult(sid, successReceipt(num, pt, cs.Challenges[pt]))
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				if res.Credential != nil && res.Credential.Token != "" {
					completions++
					credIDs[res.Credential.ID] = struct{}{}
				}
			} else if errors.Is(err, ErrProofAlreadyHandled) || errors.Is(err, ErrSessionTerminal) {
				terminals++
			}
		}(i)
	}
	wg.Wait()

	if completions != 1 {
		t.Fatalf("completions = %d, want exactly 1", completions)
	}
	if len(credIDs) != 1 {
		t.Fatalf("credential ids = %d, want 1", len(credIDs))
	}
	if terminals != 15 {
		t.Fatalf("rejected = %d, want 15", terminals)
	}
	view, _ := svc.GetSession(sid)
	if view.Status != StatusCompleted || view.Credential == nil {
		t.Fatalf("final status = %s cred = %+v", view.Status, view.Credential)
	}
}

func TestConcurrentMixedProofs_ExactlyOneCredentialOrFailure(t *testing.T) {
	// 多项证明全部并发提交：其中一项注定失败。任何交错下都不能出现凭证，
	// 且失败项不会被成功重放覆盖。
	svc, fc := newTestService(t)
	proofs := []ProofType{"a", "b", "c", "d"}
	cs := mustCreateSession(t, svc, proofs, fc.Now().Add(30*time.Minute))
	sid := cs.Session.ID

	var wg sync.WaitGroup
	for i, pt := range proofs {
		wg.Add(1)
		go func(i int, pt ProofType) {
			defer wg.Done()
			var r Receipt
			if pt == "c" {
				r = failReceipt("R-"+string(pt), pt, cs.Challenges[pt], "no match")
			} else {
				r = successReceipt("R-"+string(pt), pt, cs.Challenges[pt])
			}
			_, _ = svc.SubmitResult(sid, r)
		}(i, pt)
	}
	wg.Wait()

	view, _ := svc.GetSession(sid)
	if view.Status != StatusFailed {
		t.Fatalf("status = %s, want failed", view.Status)
	}
	if view.Credential != nil {
		t.Fatalf("credential issued despite failure: %+v", view.Credential)
	}
}

// ---- 取消 / 过期 / 完成的终态竞争 ------------------------------------------

func TestCancel_RacesWithCompletion(t *testing.T) {
	svc, fc := newTestService(t)
	cs := mustCreateSession(t, svc, []ProofType{"a", "b"}, fc.Now().Add(30*time.Minute))
	sid := cs.Session.ID
	submitSucceed(t, svc, sid, "R-a", "a", cs.Challenges["a"])

	// 大量并发：取消 vs 最后一项成功。终态必须唯一。
	const rounds = 200
	var wg sync.WaitGroup
	for i := 0; i < rounds; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = svc.CancelSession(sid)
		}()
		go func() {
			defer wg.Done()
			_, _ = svc.SubmitResult(sid, successReceipt("R-b", "b", cs.Challenges["b"]))
		}()
	}
	wg.Wait()

	view, _ := svc.GetSession(sid)
	switch view.Status {
	case StatusCanceled, StatusCompleted:
	default:
		t.Fatalf("status = %s, want a terminal state", view.Status)
	}
	if view.Status == StatusCompleted {
		// 完成后取消必须被拒绝。
		if _, err := svc.CancelSession(sid); !errors.Is(err, ErrSessionTerminal) {
			t.Fatalf("cancel completed: err = %v, want ErrSessionTerminal", err)
		}
	} else {
		// 取消后回执必须被拒绝。
		_, err := svc.SubmitResult(sid, successReceipt("R-b2", "b", cs.Challenges["b"]))
		if !errors.Is(err, ErrSessionCanceled) {
			t.Fatalf("receipt after cancel: err = %v, want ErrSessionCanceled", err)
		}
	}
}

func TestExpiry_LazyAndSweep(t *testing.T) {
	svc, fc := newTestService(t)
	cs1 := mustCreateSession(t, svc, []ProofType{"a"}, fc.Now().Add(5*time.Minute))
	cs2 := mustCreateSession(t, svc, []ProofType{"a"}, fc.Now().Add(20*time.Minute))

	fc.Advance(10 * time.Minute)

	// 逻辑过期在只读视图立即可见。
	v1, _ := svc.GetSession(cs1.Session.ID)
	if v1.Status != StatusExpired {
		t.Fatalf("view status = %s, want expired", v1.Status)
	}
	v2, _ := svc.GetSession(cs2.Session.ID)
	if v2.Status != StatusActive {
		t.Fatalf("cs2 status = %s, want active", v2.Status)
	}

	// 扫描推进。
	n, err := svc.ExpireSessions()
	if err != nil {
		t.Fatalf("ExpireSessions: %v", err)
	}
	if n != 1 {
		t.Fatalf("expired = %d, want 1", n)
	}
	// 幂等：再次扫描不重复推进。
	n, _ = svc.ExpireSessions()
	if n != 0 {
		t.Fatalf("second sweep expired = %d, want 0", n)
	}

	// 过期会话拒绝回执与取消。
	if _, err := svc.SubmitResult(cs1.Session.ID, successReceipt("R-1", "a", cs1.Challenges["a"])); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("receipt after expiry: err = %v, want ErrSessionExpired", err)
	}
	if _, err := svc.CancelSession(cs1.Session.ID); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("cancel after expiry: err = %v, want ErrSessionExpired", err)
	}
	// 未过期会话仍可用（挑战可能已到期，轮换后提交）。
	issued, err := svc.IssueChallenge(cs2.Session.ID, "a")
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	submitSucceed(t, svc, cs2.Session.ID, "R-1", "a", issued.Challenge)
}

func TestExpiryRacesWithCompletion_OnlyOneTerminal(t *testing.T) {
	// 使用真实时钟与极短截止时间，所有协作者在起跑门后同时出发，
	// 使取消、过期推进、完成回执在截止时刻附近真实竞争。
	svc, err := NewService(NewMemoryRepository(), WithPepper(testPepper), WithChallengeTTL(10*time.Second))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	cs, err := svc.CreateSession(CreateSessionRequest{
		RequiredProofs: []ProofType{"a"},
		Applicant:      validApplicant(),
		Deadline:       time.Now().Add(5 * time.Millisecond),
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sid := cs.Session.ID

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); <-start; _, _ = svc.ExpireSessions() }()
		go func() { defer wg.Done(); <-start; _, _ = svc.CancelSession(sid) }()
		go func() {
			defer wg.Done()
			<-start
			_, _ = svc.SubmitResult(sid, successReceipt("R-a", "a", cs.Challenges["a"]))
		}()
	}
	close(start)
	wg.Wait()

	view, _ := svc.GetSession(sid)
	if !view.Status.IsTerminal() {
		t.Fatalf("status = %s, want terminal", view.Status)
	}
	// 终态语义自洽：completed 必有凭证；expired/canceled 必无凭证。
	switch view.Status {
	case StatusCompleted:
		if view.Credential == nil {
			t.Fatal("completed without credential")
		}
	case StatusExpired, StatusCanceled, StatusFailed:
		if view.Credential != nil {
			t.Fatalf("%s session must not carry credential", view.Status)
		}
	}

	// 审计中终态动作至多一个。
	trail, _ := svc.GetAuditTrail(sid)
	finals := map[AuditAction]int{}
	for _, a := range trail {
		switch a.Action {
		case AuditSessionCompleted, AuditSessionFailed, AuditSessionCanceled, AuditSessionExpired:
			finals[a.Action]++
		}
	}
	total := 0
	for _, c := range finals {
		total += c
	}
	if total != 1 {
		t.Fatalf("terminal audit actions = %d (%v), want exactly 1", total, finals)
	}
}

// ---- 查询与审计 -------------------------------------------------------------

func TestGetSession_NotFound(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := svc.GetSession("ses_nope"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("err = %v, want ErrSessionNotFound", err)
	}
}

func TestAuditTrail_RecordsLifecycle(t *testing.T) {
	svc, fc := newTestService(t)
	cs := mustCreateSession(t, svc, []ProofType{"a"}, fc.Now().Add(10*time.Minute))
	sid := cs.Session.ID
	submitSucceed(t, svc, sid, "R-1", "a", cs.Challenges["a"])
	trail, err := svc.GetAuditTrail(sid)
	if err != nil {
		t.Fatalf("GetAuditTrail: %v", err)
	}
	var actions []AuditAction
	for _, a := range trail {
		actions = append(actions, a.Action)
	}
	want := []AuditAction{AuditChallengeIssued, AuditSessionCreated, AuditProofSubmitted, AuditSessionCompleted}
	if fmt.Sprint(actions) != fmt.Sprint(want) {
		t.Fatalf("audit actions = %v, want %v", actions, want)
	}
	for _, a := range trail {
		if a.At.IsZero() {
			t.Fatalf("zero audit timestamp: %+v", a)
		}
	}
}

// ---- 摘要稳定性 -------------------------------------------------------------

func TestApplicantDigest_StableAndSensitive(t *testing.T) {
	a1 := validApplicant()
	a2 := validApplicant()
	if applicantDigest(testPepper, a1) != applicantDigest(testPepper, a2) {
		t.Fatal("same applicant produced different digests")
	}
	a3 := validApplicant()
	a3.DocumentNumber = "E999999999"
	if applicantDigest(testPepper, a1) == applicantDigest(testPepper, a3) {
		t.Fatal("different document numbers produced same digest")
	}
	a4 := validApplicant()
	a4.Extra = map[string]string{"country": "CN", "x": "y"}
	a5 := validApplicant()
	a5.Extra = map[string]string{"x": "y", "country": "CN"}
	if applicantDigest(testPepper, a4) != applicantDigest(testPepper, a5) {
		t.Fatal("map key order changed digest")
	}
	d := applicantDigest(testPepper, a1)
	if strings.Contains(d, testName) || strings.Contains(d, testDoc) {
		t.Fatalf("digest leaks plaintext: %s", d)
	}
	// 不同 pepper 得到不同摘要。
	if applicantDigest("other-pepper", a1) == d {
		t.Fatal("digest must depend on pepper")
	}
}
