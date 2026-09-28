# go-identity-proofing

由多项证明（proof）组成的身份核验会话服务（Go 库）。一个会话冻结本次需要的证明
类型、申请人信息摘要和截止时间，并在会话有效期内逐项收集外部核验回执；只有全部
必需证明成功且会话仍然有效时，才**一次性**签发唯一身份凭证。

- 语言：Go 1.23，无第三方依赖
- 持久化：内存实现（`MemoryStore`），所有状态迁移在单把写锁保护的临界区内完成，
  等价于一条可序列化数据库事务；代码注释给出了 SQL 表与唯一约束的映射

## 核心安全与正确性保证

1. **创建即冻结 + 一次性短期挑战**
   - 必需证明类型（排序去重）、申请人信息**密钥化摘要**（HMAC-SHA256，进程随机
     密钥、不落盘）和会话截止时间在创建时冻结，之后不可更改。
   - 挑战为 24 字节 `crypto/rand` 随机串，只在 `SessionHandle` 中以明文返回一次；
     存储层只保留其 HMAC 哈希。挑战有效期默认 5 分钟，且不超过会话截止时间。
   - 挑战**只能使用一次**：回执被接受（成功或失败）即消费当前挑战，之后必须调用
     `RotateChallenge` 取得新挑战才能提交下一项证明。
   - 申请人证件号等敏感信息、挑战明文不会出现在持久化数据、日志、错误消息或审计
     明细中（有测试对整个存储结构序列化后做子串检查）。

2. **回执幂等、乱序、冲突检测**
   - 回执号（`ReceiptNo`）是全局幂等键：同号 + 内容完全一致 → 返回**首次处理结果**
     （含首次时观察到的凭证 ID），标记 `Replay=true`；同号 + 任何字段变化 →
     `ErrConflict`，冲突不改变首次记录。
   - 新回执必须同时匹配：会话存在且有效、证明类型属于冻结的必需集合、携带的是
     **当前未过期且未消费**的挑战。
     - 用了本会话曾签发但已轮换/消费的挑战 → `ErrStaleChallenge`
     - 用了从未签发的挑战 → `ErrChallengeMismatch`
     - 挑战或会话已过期 → `ErrExpired`；过期会话（包括"旧会话"）的回执一律拒绝
   - 证明可乱序到达；每项证明的结论只写一次：失败项**永远不能被后来的成功回执
     覆盖**（`ErrProofDecided`）。被拒绝的回执也会留痕，其相同重放返回相同拒绝。

3. **一次性完成、唯一凭证**
   - 记录最后一项证明与"全部成功 → 签发凭证 → 会话完成"在同一个临界区内，不存在
     中间窗口。
   - `credentials.session_id` 有唯一索引兜底（内存中为 map 索引），并发下最多一份
     凭证；重复完成返回同一份凭证。
   - 任一项失败即永久不可完成；并发的失败/成功回执只有一个结论落定。

4. **取消 / 过期 / 完成只保留一个终态**
   - 状态机：`active → completed | cancelled | expired`，终态不可逆。
   - 取消幂等（重复取消成功）；取消与完成、取消与过期、完成与过期并发竞争时，
     临界区裁决且只有一方胜出，败者得到 `ErrTerminal`/`ErrExpired`。
   - 过期推进有两种方式：变更类调用在发现越过截止时间时惰性过期；定时任务可调用
     `AdvanceExpirations` 批量扫描。只读查询**不**改变状态。
   - 每个会话保留只增审计链：创建、回执接受/失败/拒绝/重放/冲突、挑战轮换、完成、
     取消、过期；明细仅含哈希、回执号和短原因码。

## API 概览

| 方法 | 说明 |
| --- | --- |
| `NewService(store, Config)` / `NewDefaultService()` | 构造服务（默认挑战 TTL 5 分钟，可选 `Logger`） |
| `CreateSession(ctx, req)` | 冻结证明类型/申请人摘要/截止时间，签发首个挑战 |
| `SubmitReceipt(ctx, Receipt)` | 提交外部核验回执（幂等/冲突/匹配校验，可能直接完成会话） |
| `RotateChallenge(ctx, sessionID)` | 消费当前挑战并签发新的短期一次性挑战 |
| `Complete(ctx, sessionID)` | 显式完成（全部成功且有效时），已完成则返回同一凭证 |
| `Cancel(ctx, sessionID, reason)` | 取消会话（幂等） |
| `AdvanceExpirations(ctx)` | 批量过期推进，返回本次转入 expired 的会话 ID |
| `GetSession(ctx, id)` | 只读查询会话投影（状态、各证明、凭证 ID、审计链） |
| `GetCredential(ctx, id)` | 按凭证 ID 查询 |

典型流程（每项证明一个新挑战）：

```go
svc := NewDefaultService()

h, _ := svc.CreateSession(ctx, CreateSessionRequest{
    Applicant:      Applicant{FullName: "张三", DocumentNumber: "P12345678", DateOfBirth: "1990-01-31", Country: "CN"},
    RequiredProofs: []ProofType{ProofIDDocument, ProofFacialMatch, ProofLiveness},
    TTL:            10 * time.Minute,
})
// h.Challenge 是一次性短期挑战明文，只在此处可得；通过机密通道交给核验方

res, err := svc.SubmitReceipt(ctx, Receipt{
    ReceiptNo: "provider-001", Issuer: "issuer-a",
    SessionID: h.ID, Proof: ProofIDDocument, Challenge: h.Challenge, Success: true,
})
// res.CredentialID == "" 说明尚未集齐：轮换挑战后提交下一项
h2, _ := svc.RotateChallenge(ctx, h.ID)
// ... 其余证明同理；最后一项成功时 res.CredentialID 非空，会话进入 completed
```

回执重放与冲突：

```go
// 网络重发：同号同内容 → 首次结果（Replay=true），不重复记账
svc.SubmitReceipt(ctx, sameReceipt)

// 同号但 success/证明/挑战/issuer 等任一字段变化 → ErrConflict，首次结果不变
```

## 错误模型

所有错误均为包级哨兵错误，消息通用、不含敏感数据，可用 `errors.Is` 判定：

| 错误 | 触发场景 |
| --- | --- |
| `ErrInvalidArgument` | 入参缺失/非法（无申请人、无证明类型、TTL 非正等） |
| `ErrNotFound` | 会话或凭证不存在 |
| `ErrTerminal` | 对已完成/已取消会话做变更操作 |
| `ErrExpired` | 会话或当前挑战已过截止时间 |
| `ErrChallengeMismatch` | 回执挑战从未对该会话签发 |
| `ErrStaleChallenge` | 回执挑战是本会话旧挑战（已消费/已轮换） |
| `ErrNoChallenge` | 上一挑战已消费、尚未轮换 |
| `ErrUnknownProof` | 回执证明类型不在冻结的必需集合内 |
| `ErrProofDecided` | 证明结论已写定（失败不可覆盖、成功不可重复） |
| `ErrConflict` | 回执号被不同内容复用 |
| `ErrIncomplete` | 显式 `Complete` 时仍有必需证明未成功 |

## 持久化映射（从内存实现迁移到 SQL）

`MemoryStore.mutate` 的临界区对应一条数据库事务，记录类型对应表：

- `sessions(id PK, state, required_proofs, applicant_digest, deadline, created_at,
  challenge_hash, challenge_expires_at, challenge_rotations, credential_id)`
- `session_challenges(session_id, hash, status)` —— 已签发挑战集合，用于区分
  stale / mismatch（内存实现中为 `pastChallengeHashes`）
- `session_proofs(session_id, proof_type, status, receipt_no, reason,
  PRIMARY KEY(session_id, proof_type))` —— 行一旦插入结论即固定，失败无法覆盖
- `receipts(receipt_no PK, issuer, session_id, proof_type, fingerprint, accepted,
  reject_code)` —— 幂等与冲突的依据；指纹是包含挑战明文在内的回执内容的
  密钥化 HMAC
- `credentials(id PK, session_id UNIQUE)` —— `session_id UNIQUE` 保证一份会话
  最多一份凭证
- `session_audit(session_id, seq, at, kind, detail, receipt_no)` —— 只增审计

状态迁移建议配合 `SELECT ... FOR UPDATE` 或乐观版本号实现；终态迁移可用
`UPDATE sessions SET state=? WHERE id=? AND state='active'` 的受影响行数裁决
竞争。

## 测试

```bash
go test -race -count=1 ./...
```

测试覆盖（`-race`）：

- 创建冻结、TTL 钳制、申请人摘要确定性与敏感性、入参校验
- 幂等重放（含完成后重放返回同一凭证）、同号内容冲突（各字段变化）
- 会话/证明/挑战三重匹配、挑战一次性消费与轮换、过期挑战与过期会话
- 乱序到达、失败不可被成功覆盖（含失败/成功并发竞争，结论唯一）
- 最后回执并发重放（50×16 goroutine）：恰有一次接受、恰有一份凭证
- 完成 vs 取消、完成 vs 过期的并发终态竞争：只有一个终态，审计终态条目恰有一条
- 取消规则与幂等、批量过期推进、只读不触发过期
- 审计链、日志、错误消息、整库序列化均不含挑战明文与申请人敏感信息
- `context.Context` 取消传播
