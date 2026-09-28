// Package goidentityproofing 实现由多项证明（proof）组成的身份核验会话。
//
// 核心模型：
//
//   - 会话在创建时冻结证明类型清单、申请人信息摘要与截止时间；
//   - 每项证明绑定一个一次性、短期有效的挑战（challenge），挑战值只在签发
//     时以明文返回一次，持久层仅保存其 SHA-256 哈希；
//   - 外部核验结果按“回执号”幂等处理：同号同内容返回首次结果，同号异内容冲突；
//   - 全部必需证明成功且会话仍有效时，核验只能一次性完成并生成唯一身份凭证；
//   - 取消（canceled）、过期（expired）、完成（completed）/失败（failed）
//     互斥且终态，任何竞争都只保留其中一个；
//   - 所有状态流转都追加一条审计记录（audit）。
package goidentityproofing

import (
	"errors"
	"time"
)

// ProofType 是证明类型标识（如 "id_document"、"face_match"、"address"）。
type ProofType string

// SessionStatus 表示会话状态。除 Active 外其余均为终态。
type SessionStatus string

const (
	// StatusActive 会话进行中。
	StatusActive SessionStatus = "active"
	// StatusCompleted 全部证明成功，凭证已签发（终态）。
	StatusCompleted SessionStatus = "completed"
	// StatusFailed 某项必需证明返回失败，失败不可被后续回执覆盖（终态）。
	StatusFailed SessionStatus = "failed"
	// StatusCanceled 会话被取消（终态）。
	StatusCanceled SessionStatus = "canceled"
	// StatusExpired 会话已过截止时间（终态）。
	StatusExpired SessionStatus = "expired"
)

// IsTerminal 报告状态是否为终态。
func (s SessionStatus) IsTerminal() bool { return s != StatusActive }

// ProofStatus 表示单项证明的处理状态。
type ProofStatus string

const (
	// ProofPending 等待外部核验结果。
	ProofPending ProofStatus = "pending"
	// ProofSucceeded 外部核验成功。
	ProofSucceeded ProofStatus = "succeeded"
	// ProofFailed 外部核验失败（终态，不可覆盖）。
	ProofFailed ProofStatus = "failed"
)

// 业务错误。错误消息均为静态文本，不包含挑战值、证件号等敏感数据。
var (
	// ErrInvalidArgument 入参非法（空值、缺少必需字段、时间无效等）。
	ErrInvalidArgument = errors.New("proofing: invalid argument")
	// ErrSessionNotFound 会话不存在。
	ErrSessionNotFound = errors.New("proofing: session not found")
	// ErrSessionTerminal 会话已处于终态，拒绝写入。
	ErrSessionTerminal = errors.New("proofing: session is in a terminal state")
	// ErrSessionExpired 会话已过截止时间（或已由过期推进进入终态）。
	ErrSessionExpired = errors.New("proofing: session expired")
	// ErrSessionCanceled 会话已被取消。
	ErrSessionCanceled = errors.New("proofing: session canceled")
	// ErrUnknownProof 回执引用的证明类型不在本次会话冻结的清单中。
	ErrUnknownProof = errors.New("proofing: unknown proof type for session")
	// ErrProofAlreadyHandled 该证明已有终态结果，新的成功回执不得覆盖失败结果。
	ErrProofAlreadyHandled = errors.New("proofing: proof already handled")
	// ErrChallengeMismatch 回执携带的挑战与该证明当前挑战不符。
	ErrChallengeMismatch = errors.New("proofing: challenge does not match")
	// ErrChallengeExpired 挑战已过期或已被使用，必须重新签发。
	ErrChallengeExpired = errors.New("proofing: challenge expired or consumed")
	// ErrReceiptConflict 同一回执号再次到达但内容与首次不同。
	ErrReceiptConflict = errors.New("proofing: receipt id reused with different content")
)

// ApplicantInfo 是申请人信息。原始证件字段属于敏感数据：服务只用它们计算
// 摘要与审计用脱敏标签，从不持久化、不写日志、不放进错误消息。
type ApplicantInfo struct {
	// FullName 申请人姓名。
	FullName string
	// DocumentNumber 证件号码。
	DocumentNumber string
	// DocumentType 证件类型，如 passport / national_id。
	DocumentType string
	// Extra 其他需要参与摘要冻结的字段（可选）。
	Extra map[string]string
}

// CreateSessionRequest 创建会话请求。证明类型清单与申请人信息在创建时冻结。
type CreateSessionRequest struct {
	// RequiredProofs 本次核验需要的全部证明类型，不得为空；重复项按一个处理。
	RequiredProofs []ProofType
	// Applicant 申请人信息（只保存 HMAC 摘要与脱敏标签）。
	Applicant ApplicantInfo
	// Deadline 会话截止时间；零值表示使用服务默认有效期。
	Deadline time.Time
}

// SessionView 是对外的会话视图，不含任何敏感明文。
type SessionView struct {
	ID              string
	Status          SessionStatus
	RequiredProofs  []ProofType
	ApplicantDigest string // 申请人信息的 HMAC-SHA-256 摘要（十六进制）
	ApplicantLabel  string // 仅供人工核对的脱敏标签，如 "ZH***|****1234"
	Deadline        time.Time
	CreatedAt       time.Time
	Proofs          map[ProofType]ProofView
	Credential      *CredentialView // 仅 completed 会话非空
}

// ProofView 单项证明视图。
type ProofView struct {
	Type      ProofType
	Status    ProofStatus
	Success   bool
	Reason    string // 外部回执给出的非敏感结果说明（可选）
	UpdatedAt time.Time
	// ChallengeExpiresAt 当前挑战的过期时间；证明已有终态结果时为零值。
	ChallengeExpiresAt time.Time
}

// CredentialView 身份凭证视图。Token 只在完成核验的当次调用中明文返回一次，
// 之后查询只能拿到 TokenHash。
type CredentialView struct {
	ID        string
	SessionID string
	// Token 凭证令牌明文，仅在完成核验的首次响应中出现。
	Token     string
	TokenHash string
	IssuedAt  time.Time
}

// Receipt 是外部核验结果回执。
type Receipt struct {
	// ReceiptNumber 外部回执号，幂等键。
	ReceiptNumber string
	// ProofType 回执对应的证明类型。
	ProofType ProofType
	// Challenge 回执方引用的挑战明文，服务据此校验其属于当前会话/证明/挑战。
	Challenge string
	// Success 外部核验是否成功。
	Success bool
	// Reason 结果说明；不得包含敏感证件信息（由调用方负责脱敏）。
	Reason string
}

// ResultView 回执处理结果视图。
type ResultView struct {
	ReceiptNumber string
	ProofType     ProofType
	Success       bool
	// Replayed 表示该回执号此前已处理过，本次返回的是首次处理结果。
	Replayed bool
	// Session 处理回执后的会话快照。
	Session SessionView
	// Credential 非空表示本次（或首次）处理触发了凭证签发；
	// Replayed=true 时令牌明文不再返回，只通过 Session.Credential 暴露哈希。
	Credential *CredentialView
}

// AuditAction 审计动作类型。
type AuditAction string

const (
	AuditSessionCreated   AuditAction = "session_created"
	AuditChallengeIssued  AuditAction = "challenge_issued"
	AuditProofSubmitted   AuditAction = "proof_submitted"
	AuditProofReplayed    AuditAction = "proof_replayed"
	AuditReceiptRejected  AuditAction = "receipt_rejected"
	AuditSessionCompleted AuditAction = "session_completed"
	AuditSessionFailed    AuditAction = "session_failed"
	AuditSessionCanceled  AuditAction = "session_canceled"
	AuditSessionExpired   AuditAction = "session_expired"
)

// AuditEntry 审计记录。Detail 只放非敏感的结构化信息（哈希前缀、状态等），
// 严禁放入挑战明文、证件号、原始回执内容。
type AuditEntry struct {
	At            time.Time
	Action        AuditAction
	ProofType     ProofType
	ReceiptNumber string
	Detail        string
}
