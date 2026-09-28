package goidentityproofing

import (
	"sync"
	"time"
)

// persistedChallenge 是挑战的持久化形态：只保存 SHA-256 哈希、签发与过期时间。
// 挑战明文在任何情况下都不会落盘。
type persistedChallenge struct {
	Hash      string
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Consumed 为 true 表示该一次性挑战已被一份回执使用。
	Consumed bool
}

// persistedProof 是单项证明的持久化形态。
type persistedProof struct {
	Type      ProofType
	Status    ProofStatus
	Reason    string
	UpdatedAt time.Time
	Challenge persistedChallenge
}

// persistedCredential 是身份凭证的持久化形态：只保存令牌哈希，不保存明文。
type persistedCredential struct {
	ID        string
	TokenHash string
	IssuedAt  time.Time
}

// persistedReceipt 记录回执号 -> 首次处理结果，用于幂等与冲突检测。
// 不保存回执原文，只保存内容的 HMAC 摘要。
type persistedReceipt struct {
	Number      string
	ContentHash string
	Success     bool
	ProofType   ProofType
	HandledAt   time.Time
}

// persistedSession 是会话的持久化形态。申请人信息只保存 HMAC 摘要与脱敏标签。
type persistedSession struct {
	ID              string
	Status          SessionStatus
	RequiredProofs  []ProofType
	ApplicantDigest string
	ApplicantLabel  string
	Deadline        time.Time
	CreatedAt       time.Time
	Proofs          map[ProofType]*persistedProof
	Credential      *persistedCredential
	// Receipts 以回执号为键。属于会话的索引，保证与会话状态在同一事务内更新。
	Receipts map[string]*persistedReceipt
	Audit    []persistedAudit
}

// persistedAudit 是审计记录的持久化形态。
type persistedAudit struct {
	At            time.Time
	Action        AuditAction
	ProofType     ProofType
	ReceiptNumber string
	Detail        string
}

// Repository 是会话存储抽象。所有方法必须并发安全；生产实现（数据库）应把
// UpdateSessionTx 实现为针对单会话的乐观锁/行锁事务，使“读-改-写”原子化，
// 从而保证并发回执下凭证最多签发一次、终态唯一。
type Repository interface {
	// PutSession 写入一个新会话；ID 冲突时返回 false。
	PutSession(s *persistedSession) bool
	// GetSession 读取会话；不存在返回 (nil, false)。
	GetSession(id string) (*persistedSession, bool)
	// ListActiveSessionIDs 返回所有非终态会话 ID，供过期推进扫描使用。
	ListActiveSessionIDs() []string
	// UpdateSessionTx 在一个原子事务内加载会话、执行 fn 并保存结果。
	// fn 返回非 nil 错误时事务回滚（不保存）。会话不存在返回 ErrSessionNotFound。
	UpdateSessionTx(id string, fn func(s *persistedSession) error) error
}

// MemoryRepository 是基于内存的 Repository 实现，使用单一互斥锁串行化
// 全部事务，适用于单机场景与测试。读写均经过 JSON 深拷贝，避免调用方
// 在锁外修改内部状态。
type MemoryRepository struct {
	mu       sync.Mutex
	sessions map[string]*persistedSession
}

// NewMemoryRepository 创建空的内存存储。
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{sessions: make(map[string]*persistedSession)}
}

// PutSession 实现 Repository。
func (r *MemoryRepository) PutSession(s *persistedSession) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.sessions[s.ID]; ok {
		return false
	}
	r.sessions[s.ID] = cloneSession(s)
	return true
}

// GetSession 实现 Repository，返回深拷贝。
func (r *MemoryRepository) GetSession(id string) (*persistedSession, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	if !ok {
		return nil, false
	}
	return cloneSession(s), true
}

// ListActiveSessionIDs 实现 Repository。
func (r *MemoryRepository) ListActiveSessionIDs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.sessions))
	for id, s := range r.sessions {
		if !s.Status.IsTerminal() {
			ids = append(ids, id)
		}
	}
	return ids
}

// UpdateSessionTx 实现 Repository。事务期间持锁，fn 修改的是内部记录的
// 深拷贝，仅当 fn 返回 nil 时才提交。
func (r *MemoryRepository) UpdateSessionTx(id string, fn func(s *persistedSession) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	if !ok {
		return ErrSessionNotFound
	}
	working := cloneSession(s)
	if err := fn(working); err != nil {
		return err
	}
	r.sessions[id] = working
	return nil
}

// Snapshot 返回当前全部会话的深拷贝，主要用于测试与运维巡检。
func (r *MemoryRepository) Snapshot() map[string]*persistedSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]*persistedSession, len(r.sessions))
	for id, s := range r.sessions {
		out[id] = cloneSession(s)
	}
	return out
}
