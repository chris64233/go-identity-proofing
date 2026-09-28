package goidentityproofing

import (
	"strconv"
	"time"
)

// CreatedSession 是创建会话的结果。Challenges 以证明类型为键，值为一次性
// 挑战明文，只在本次响应中出现，服务端不再保存、无法再次取回。
type CreatedSession struct {
	Session    SessionView
	Challenges map[ProofType]string
}

// CreateSession 创建核验会话：冻结证明类型清单、申请人摘要与截止时间，
// 并为每项证明预签一个一次性短期挑战。
func (s *Service) CreateSession(req CreateSessionRequest) (*CreatedSession, error) {
	if len(req.RequiredProofs) == 0 {
		return nil, ErrInvalidArgument
	}
	seen := make(map[ProofType]struct{}, len(req.RequiredProofs))
	proofTypes := make([]ProofType, 0, len(req.RequiredProofs))
	for _, t := range req.RequiredProofs {
		if t == "" {
			return nil, ErrInvalidArgument
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		proofTypes = append(proofTypes, t)
	}
	if req.Applicant.FullName == "" || req.Applicant.DocumentNumber == "" {
		return nil, ErrInvalidArgument
	}

	at := s.now()
	deadline := req.Deadline
	if deadline.IsZero() {
		deadline = at.Add(s.defaultTTL)
	}
	if !deadline.After(at) {
		return nil, ErrInvalidArgument
	}

	id, err := s.randomID("ses_")
	if err != nil {
		return nil, err
	}

	sn := &persistedSession{
		ID:              id,
		Status:          StatusActive,
		RequiredProofs:  proofTypes,
		ApplicantDigest: applicantDigest(s.pepper, req.Applicant),
		ApplicantLabel:  applicantLabel(req.Applicant),
		Deadline:        deadline,
		CreatedAt:       at,
		Proofs:          make(map[ProofType]*persistedProof, len(proofTypes)),
		Receipts:        make(map[string]*persistedReceipt),
	}
	challenges := make(map[ProofType]string, len(proofTypes))
	for _, t := range proofTypes {
		p := &persistedProof{Type: t, Status: ProofPending}
		plaintext, err := s.mintChallenge(p, at)
		if err != nil {
			return nil, err
		}
		sn.Proofs[t] = p
		challenges[t] = plaintext
		addAudit(sn, persistedAudit{
			At:        at,
			Action:    AuditChallengeIssued,
			ProofType: t,
			Detail:    "challenge=" + hashPrefix(p.Challenge.Hash) + ";expires_at=" + p.Challenge.ExpiresAt.UTC().Format(time.RFC3339),
		})
	}
	addAudit(sn, persistedAudit{
		At:     at,
		Action: AuditSessionCreated,
		Detail: "proofs=" + strconv.Itoa(len(proofTypes)) + ";deadline=" + deadline.UTC().Format(time.RFC3339),
	})

	if !s.repo.PutSession(sn) {
		// 随机 ID 冲突在实践中不可达，仅作防御。
		return nil, ErrSessionTerminal
	}
	return &CreatedSession{Session: toView(sn, ""), Challenges: challenges}, nil
}

// IssuedChallenge 是挑战轮换的结果。明文只在本次响应中返回。
type IssuedChallenge struct {
	ProofType ProofType
	Challenge string
	ExpiresAt time.Time
}

// IssueChallenge 为指定证明轮换一个新的一次性短期挑战，旧挑战立即失效。
// 证明已有终态结果、会话处于终态或已过期时拒绝签发。
func (s *Service) IssueChallenge(sessionID string, pt ProofType) (*IssuedChallenge, error) {
	if sessionID == "" || pt == "" {
		return nil, ErrInvalidArgument
	}
	var out *IssuedChallenge
	err := s.repo.UpdateSessionTx(sessionID, func(sn *persistedSession) error {
		now := s.now()
		if s.advanceExpiredLocked(sn) {
			return ErrSessionExpired
		}
		if sn.Status != StatusActive {
			return terminalError(sn.Status)
		}
		p, ok := sn.Proofs[pt]
		if !ok {
			return ErrUnknownProof
		}
		if p.Status != ProofPending {
			return ErrProofAlreadyHandled
		}
		plaintext, err := s.mintChallenge(p, now)
		if err != nil {
			return err
		}
		addAudit(sn, persistedAudit{
			At:        now,
			Action:    AuditChallengeIssued,
			ProofType: pt,
			Detail:    "challenge=" + hashPrefix(p.Challenge.Hash) + ";expires_at=" + p.Challenge.ExpiresAt.UTC().Format(time.RFC3339),
		})
		out = &IssuedChallenge{
			ProofType: pt,
			Challenge: plaintext,
			ExpiresAt: p.Challenge.ExpiresAt,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
