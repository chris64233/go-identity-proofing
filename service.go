package goidentityproofing

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// 默认参数，可通过 ServiceOption 覆盖。
const (
	// defaultSessionTTL 未显式指定截止时间时的会话有效期。
	defaultSessionTTL = 30 * time.Minute
	// defaultChallengeTTL 一次性挑战的默认有效期（短期）。
	defaultChallengeTTL = 5 * time.Minute
	// minChallengeTTL / maxChallengeTTL 限制可配置的挑战有效期。
	minChallengeTTL = 10 * time.Second
	maxChallengeTTL = 1 * time.Hour
	// idBytes 会话 ID / 凭证 ID 的随机字节数。
	idBytes = 16
)

// Clock 抽象时间来源，生产环境使用 time.Now，测试可注入固定时钟。
type Clock func() time.Time

// Service 是核验会话服务，所有方法均并发安全。
type Service struct {
	repo         Repository
	pepper       string
	clock        Clock
	challengeTTL time.Duration
	defaultTTL   time.Duration
}

// Option 配置 Service。
type Option func(*Service)

// WithClock 注入自定义时钟（主要用于测试）。
func WithClock(c Clock) Option {
	return func(s *Service) {
		if c != nil {
			s.clock = c
		}
	}
}

// WithPepper 注入服务端 pepper（HMAC 密钥）。不配置时启动生成随机 pepper；
// 多实例部署/持久化跨进程复用场景必须显式配置相同的 pepper。
func WithPepper(pepper string) Option {
	return func(s *Service) {
		if pepper != "" {
			s.pepper = pepper
		}
	}
}

// WithChallengeTTL 配置一次性挑战的有效期。
func WithChallengeTTL(d time.Duration) Option {
	return func(s *Service) {
		if d >= minChallengeTTL && d <= maxChallengeTTL {
			s.challengeTTL = d
		}
	}
}

// WithDefaultSessionTTL 配置未指定截止时间时的默认会话有效期。
func WithDefaultSessionTTL(d time.Duration) Option {
	return func(s *Service) {
		if d > 0 {
			s.defaultTTL = d
		}
	}
}

// NewService 创建核验会话服务。
func NewService(repo Repository, opts ...Option) (*Service, error) {
	svc := &Service{
		repo:         repo,
		clock:        time.Now,
		challengeTTL: defaultChallengeTTL,
		defaultTTL:   defaultSessionTTL,
	}
	for _, opt := range opts {
		opt(svc)
	}
	if svc.pepper == "" {
		key := make([]byte, digestSize)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		svc.pepper = hex.EncodeToString(key)
	}
	return svc, nil
}

// now 返回当前时间（可能被测试时钟覆盖）。
func (s *Service) now() time.Time { return s.clock() }

// randomID 生成会话/凭证 ID。
func (s *Service) randomID(prefix string) (string, error) {
	b := make([]byte, idBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

// mintChallenge 生成一个一次性挑战并写入证明槽位；返回挑战明文（仅此一次）。
// 调用方必须已经在事务内（或尚未发布会话），plaintext 只经返回值离开服务。
func (s *Service) mintChallenge(p *persistedProof, at time.Time) (string, error) {
	plaintext, err := randomToken(challengeBytes)
	if err != nil {
		return "", err
	}
	p.Challenge = persistedChallenge{
		Hash:      sha256Hex(plaintext),
		IssuedAt:  at,
		ExpiresAt: at.Add(s.challengeTTL),
		Consumed:  false,
	}
	return plaintext, nil
}

// addAudit 在会话审计尾部追加一条记录。
func addAudit(sn *persistedSession, e persistedAudit) {
	sn.Audit = append(sn.Audit, e)
}

// isExpired 判断会话在时刻 now 是否应视为已过期。
func isExpired(sn *persistedSession, now time.Time) bool {
	return sn.Status == StatusActive && !now.Before(sn.Deadline)
}

// toView 把持久化会话转换为对外视图。tokenPlaintext 非空时填入
// Credential.Token（只用于完成核验的当次响应）。
func toView(sn *persistedSession, tokenPlaintext string) SessionView {
	proofs := make(map[ProofType]ProofView, len(sn.Proofs))
	for t, p := range sn.Proofs {
		pv := ProofView{
			Type:      p.Type,
			Status:    p.Status,
			Success:   p.Status == ProofSucceeded,
			Reason:    p.Reason,
			UpdatedAt: p.UpdatedAt,
		}
		if p.Status == ProofPending {
			pv.ChallengeExpiresAt = p.Challenge.ExpiresAt
		}
		proofs[t] = pv
	}
	v := SessionView{
		ID:              sn.ID,
		Status:          sn.Status,
		RequiredProofs:  append([]ProofType(nil), sn.RequiredProofs...),
		ApplicantDigest: sn.ApplicantDigest,
		ApplicantLabel:  sn.ApplicantLabel,
		Deadline:        sn.Deadline,
		CreatedAt:       sn.CreatedAt,
		Proofs:          proofs,
	}
	if sn.Credential != nil {
		cv := &CredentialView{
			ID:        sn.Credential.ID,
			SessionID: sn.ID,
			TokenHash: sn.Credential.TokenHash,
			IssuedAt:  sn.Credential.IssuedAt,
		}
		if tokenPlaintext != "" {
			cv.Token = tokenPlaintext
		}
		v.Credential = cv
	}
	return v
}

// terminalError 把已持久化的终态映射为对应的哨兵错误。
func terminalError(status SessionStatus) error {
	switch status {
	case StatusCompleted, StatusFailed:
		return ErrSessionTerminal
	case StatusCanceled:
		return ErrSessionCanceled
	case StatusExpired:
		return ErrSessionExpired
	default:
		return ErrSessionTerminal
	}
}

// advanceExpiredLocked 若会话已过期则推进到 expired 终态并追加审计。
// 返回 true 表示发生了状态推进。调用方必须在事务内。
func (s *Service) advanceExpiredLocked(sn *persistedSession) bool {
	if !isExpired(sn, s.now()) {
		return false
	}
	sn.Status = StatusExpired
	addAudit(sn, persistedAudit{
		At:     s.now(),
		Action: AuditSessionExpired,
		Detail: "deadline=" + sn.Deadline.UTC().Format(time.RFC3339),
	})
	return true
}
