package goidentityproofing

import (
	"errors"
	"time"
)

// CancelSession 取消会话。取消、过期推进、完成/失败在同一事务内竞争：
// 若会话已处于任何终态（包括被并发回执刚刚完成、或刚好被惰性过期），
// 取消返回该终态对应的错误，绝不覆盖已有终态。
// 取消成功返回最新会话视图。
func (s *Service) CancelSession(sessionID string) (SessionView, error) {
	if sessionID == "" {
		return SessionView{}, ErrInvalidArgument
	}
	var view SessionView
	err := s.repo.UpdateSessionTx(sessionID, func(sn *persistedSession) error {
		now := s.now()
		// 过期优先惰性推进：截止时间已过的会话由取消路径触碰时同样落为 expired。
		if s.advanceExpiredLocked(sn) {
			return ErrSessionExpired
		}
		if sn.Status != StatusActive {
			return terminalError(sn.Status)
		}
		sn.Status = StatusCanceled
		addAudit(sn, persistedAudit{At: now, Action: AuditSessionCanceled})
		view = toView(sn, "")
		return nil
	})
	if err != nil {
		return SessionView{}, err
	}
	return view, nil
}

// ExpireSessions 扫描全部进行中的会话，把截止时间已过的推进到 expired。
// 与取消/回执并发时由每个会话的事务保证终态唯一：只有仍处于 active 的
// 会话会被推进。返回本次实际过期的会话数量。
func (s *Service) ExpireSessions() (int, error) {
	ids := s.repo.ListActiveSessionIDs()
	expired := 0
	for _, id := range ids {
		var didExpire bool
		err := s.repo.UpdateSessionTx(id, func(sn *persistedSession) error {
			didExpire = s.advanceExpiredLocked(sn)
			return nil
		})
		if errors.Is(err, ErrSessionNotFound) {
			continue
		}
		if err != nil {
			return expired, err
		}
		if didExpire {
			expired++
		}
	}
	return expired, nil
}

// GetSession 查询会话当前状态。查询同样会观察截止时间，但不会把过期
// 持久化（只读路径不产生状态变更）；需要推进终态时调用 ExpireSessions。
// 返回的视图不含任何敏感明文（凭证令牌只暴露哈希）。
func (s *Service) GetSession(sessionID string) (SessionView, error) {
	if sessionID == "" {
		return SessionView{}, ErrInvalidArgument
	}
	sn, ok := s.repo.GetSession(sessionID)
	if !ok {
		return SessionView{}, ErrSessionNotFound
	}
	view := toView(sn, "")
	if sn.Status == StatusActive && !s.now().Before(sn.Deadline) {
		// 仅在视图层反映“逻辑上已过期”，不修改持久状态。
		view.Status = StatusExpired
	}
	return view, nil
}

// AuditView 是审计记录的对外形态。
type AuditView struct {
	At            time.Time
	Action        AuditAction
	ProofType     ProofType
	ReceiptNumber string
	Detail        string
}

// GetAuditTrail 返回会话的审计轨迹（按时间先后）。审计只含动作、证明类型、
// 回执号、哈希前缀与状态等非敏感信息，可安全持久化与输出。
func (s *Service) GetAuditTrail(sessionID string) ([]AuditView, error) {
	if sessionID == "" {
		return nil, ErrInvalidArgument
	}
	sn, ok := s.repo.GetSession(sessionID)
	if !ok {
		return nil, ErrSessionNotFound
	}
	out := make([]AuditView, 0, len(sn.Audit))
	for _, a := range sn.Audit {
		out = append(out, AuditView{
			At:            a.At,
			Action:        a.Action,
			ProofType:     a.ProofType,
			ReceiptNumber: a.ReceiptNumber,
			Detail:        a.Detail,
		})
	}
	return out, nil
}
