package goidentityproofing

import (
	"testing"
	"time"
)

func TestMemoryRepository_PutDuplicateAndTx(t *testing.T) {
	repo := NewMemoryRepository()
	sn := &persistedSession{
		ID:       "ses_x",
		Status:   StatusActive,
		Proofs:   map[ProofType]*persistedProof{},
		Receipts: map[string]*persistedReceipt{},
	}
	if !repo.PutSession(sn) {
		t.Fatal("first PutSession should succeed")
	}
	if repo.PutSession(sn) {
		t.Fatal("duplicate PutSession must return false")
	}

	// 事务回滚不改变持久状态。
	err := repo.UpdateSessionTx("ses_x", func(s *persistedSession) error {
		s.Status = StatusCanceled
		return ErrSessionTerminal
	})
	if err != ErrSessionTerminal {
		t.Fatalf("tx err = %v", err)
	}
	got, ok := repo.GetSession("ses_x")
	if !ok || got.Status != StatusActive {
		t.Fatalf("rolled-back tx changed state: %+v", got)
	}

	// 事务提交生效。
	if err := repo.UpdateSessionTx("ses_x", func(s *persistedSession) error {
		s.Status = StatusExpired
		return nil
	}); err != nil {
		t.Fatalf("commit tx: %v", err)
	}
	got, _ = repo.GetSession("ses_x")
	if got.Status != StatusExpired {
		t.Fatalf("status = %s, want expired", got.Status)
	}
	if ids := repo.ListActiveSessionIDs(); len(ids) != 0 {
		t.Fatalf("active ids = %v, want empty", ids)
	}
	if err := repo.UpdateSessionTx("ses_missing", func(s *persistedSession) error { return nil }); err != ErrSessionNotFound {
		t.Fatalf("missing tx: err = %v", err)
	}
}

func TestWithDefaultSessionTTL(t *testing.T) {
	fc := newFakeClock(time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC))
	svc, err := NewService(NewMemoryRepository(),
		WithClock(fc.Now), WithPepper(testPepper),
		WithDefaultSessionTTL(90*time.Second),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	cs, err := svc.CreateSession(CreateSessionRequest{
		RequiredProofs: []ProofType{"a"},
		Applicant:      validApplicant(),
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if !cs.Session.Deadline.Equal(fc.Now().Add(90 * time.Second)) {
		t.Fatalf("deadline = %v, want +90s", cs.Session.Deadline)
	}
}

func TestNewService_RandomPepper(t *testing.T) {
	s1, err := NewService(NewMemoryRepository())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	s2, err := NewService(NewMemoryRepository())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if s1.pepper == "" || s1.pepper == s2.pepper {
		t.Fatal("pepper must be auto-generated and unique per process")
	}
}
