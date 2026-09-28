# go-identity-proofing

由多项证明（proof）组成的身份核验会话服务（Go 库，无第三方依赖）。
支持会话创建、外部核验结果回执（支持重复/乱序）、取消、过期推进、结果查询与审计，
并在并发下保证凭证最多签发一次、终态唯一。

## 领域模型

```
Session 1──* Proof（创建时冻结的证明类型清单）
        1──1 Credential?（全部证明成功后唯一签发）
        1──* ReceiptIndex（回执号 -> 首次处理结果，幂等键）
        1──* AuditEntry
```

会话状态机：

```
                 全部证明成功
        ┌──────────────────────────▶ completed（终态，唯一凭证）
        │
active ─┼──── 任一证明失败 ─────────▶ failed（终态，失败不可覆盖）
        │
        ├──── 取消 ────────────────▶ canceled（终态）
        │
        └──── 超过 Deadline ───────▶ expired（终态，惰性推进或扫描推进）
```

四个终态互斥：取消、过期、完成、失败的任何并发交错下，只有一个终态会落库。

## API

| 方法 | 说明 |
| --- | --- |
| `NewService(repo, opts...)` | 创建服务；可注入 pepper、时钟、挑战 TTL、默认会话 TTL |
| `CreateSession(req)` | 冻结证明清单/申请人摘要/截止时间，为每项证明签发一次性挑战 |
| `IssueChallenge(sid, proof)` | 轮换某证明的挑战（旧挑战立即失效），证明已有结果或会话终态时拒绝 |
| `SubmitResult(sid, receipt)` | 提交外部核验回执（幂等、冲突检测、挑战三重匹配） |
| `CancelSession(sid)` | 取消会话；与终态竞争失败时返回对应哨兵错误 |
| `ExpireSessions()` | 扫描并推进所有到期会话，返回本次过期数量 |
| `GetSession(sid)` | 查询会话快照（过期在只读视图即时反映，不产生写操作） |
| `GetAuditTrail(sid)` | 查询按时间排序的审计轨迹 |

错误均为可 `errors.Is` 的哨兵错误：`ErrInvalidArgument`、`ErrSessionNotFound`、
`ErrSessionTerminal`、`ErrSessionExpired`、`ErrSessionCanceled`、`ErrUnknownProof`、
`ErrProofAlreadyHandled`、`ErrChallengeMismatch`、`ErrChallengeExpired`、
`ErrReceiptConflict`。错误消息是静态文本，不含任何业务数据。

## 关键语义

### 1. 创建即冻结

- 证明类型清单去重后冻结；回执引用清单之外的证明类型返回 `ErrUnknownProof`。
- 申请人姓名/证件号等敏感信息**不入库**：只持久化
  HMAC-SHA-256（服务端 pepper 参与，防库泄漏后枚举反查）摘要与脱敏标签
  （如 `张**|******6789`）。
- 截止时间冻结；默认 30 分钟，可在请求中显式指定。

### 2. 一次性短期挑战

- 每项证明在创建会话时获得一个 256 位随机挑战，默认 5 分钟有效。
- 挑战明文**只在签发响应中出现一次**；持久层只保存其 SHA-256 哈希、签发/过期时间。
- 回执必须同时满足三重匹配才被接受：
  1. 挑战哈希等于该证明槽位的**当前**挑战（跨会话、跨证明、轮换前的旧挑战均被拒）；
  2. 挑战未过期；
  3. 挑战未被消费（一次性，已被一份回执使用即失效）。
- 挑战过期后可调用 `IssueChallenge` 轮换；已有终态结果的证明不能再签发。

### 3. 回执幂等与冲突

回执以 `ReceiptNumber` 为幂等键，内容（证明类型、挑战、成功与否、原因）做
HMAC 摘要：

- **同号同内容**（重复、乱序、甚至会话已过期后到达）：返回首次处理结果，
  `Replayed=true`，不重复产生副作用；
- **同号异内容**：返回 `ErrReceiptConflict`，首次结果不受影响；
- 幂等检查先于会话/挑战校验，保证同一回执号在任何时序下语义稳定。

### 4. 失败不可静默覆盖

任一必需证明返回失败 → 证明为 `failed` 且会话进入 `failed` 终态。
之后携带新回执号、新挑战的成功回执返回 `ErrSessionTerminal`，
失败结果不会被覆盖，也不会签发凭证。

### 5. 凭证的一次性与终态竞争

- 仅当**全部**必需证明成功且会话仍为 active 时，才在同一事务内创建凭证
  （随机令牌，仅持久化其 SHA-256 哈希）并转入 `completed`。
- 凭证令牌明文只在完成核验的当次响应返回；之后查询/重放只能拿到哈希。
- 并发到达的最后几项证明中，单会话事务（读-改-写原子化）保证只有一个事务
  能观察到“全部成功”，因此**凭证最多一份**；其余回执收到
  `ErrProofAlreadyHandled` / `ErrSessionTerminal`。
- 取消 / 过期推进（惰性 + 定时扫描）/ 完成回执在同一事务上竞争，
  终态审计动作（completed/failed/canceled/expired）全库恰好一条。

### 6. 审计

每次状态流转追加审计记录：会话创建、挑战签发、回执提交、回执重放、
回执拒绝（含拒绝原因代码）、完成、失败、取消、过期。
审计只包含动作、证明类型、回执号、哈希前缀与时间，可安全持久化和外发。

## 持久化与部署

`Repository` 是存储接口，内存实现 `MemoryRepository` 以单会话事务
（`UpdateSessionTx`）串行化所有读-改-写。生产环境接入数据库时，应把
`UpdateSessionTx` 实现为针对单会话行的行锁/乐观锁事务（如
`SELECT ... FOR UPDATE` 或版本号 CAS），即可保留全部并发保证：

- 终态唯一来自“检查状态 + 写终态”在同一事务内；
- 凭证唯一来自“检查全部成功 + 写凭证”在同一事务内；
- 回执幂等来自回执索引与会话状态在同一事务内更新。

多实例部署时必须通过 `WithPepper` 配置共享 pepper，否则重启/换实例后
HMAC 摘要无法复算；挑战与凭证令牌本身是高熵随机值，使用无密钥 SHA-256。
建议由外部定时器周期性调用 `ExpireSessions()` 推进过期；
写路径（回执/取消/挑战签发）也会惰性推进过期，不依赖定时器的及时性。

## 快速开始

```go
svc, _ := proofing.NewService(
    proofing.NewMemoryRepository(),
    proofing.WithPepper("shared-hmac-pepper"),
)

created, _ := svc.CreateSession(proofing.CreateSessionRequest{
    RequiredProofs: []proofing.ProofType{"id_document", "face_match"},
    Applicant: proofing.ApplicantInfo{
        FullName: "张三丰", DocumentType: "passport", DocumentNumber: "E123456789",
    },
})
sid := created.Session.ID

// 挑战明文只在此处可得
res, err := svc.SubmitResult(sid, proofing.Receipt{
    ReceiptNumber: "EXT-1",
    ProofType:     "id_document",
    Challenge:     created.Challenges["id_document"],
    Success:       true,
})
// ... 提交其余证明；最后一个成功的回执返回 res.Credential.Token（仅一次）
```

可运行示例见 `example_test.go`。

## 测试

```bash
go test -race -count=1 ./...        # 全部测试（含竞态检测）
go test -race -count=20 -run 'Concurrent|Races' ./...   # 并发用例压力复跑
go test -cover ./...                # 语句覆盖率（当前 92.9%）
```

测试覆盖：

- 创建冻结、参数校验、默认值与去重；
- 敏感信息不出现在持久化快照、错误消息、审计记录中（白盒断言）；
- 挑战只以哈希存储、过期、轮换、一次性、跨会话/跨证明不匹配；
- 回执幂等（含会话过期后的重放）、内容冲突、凭证令牌不二次下发；
- 失败终态不可被成功回执覆盖；乱序回执只完成一次；
- 16 路并发提交最后一项证明 → 恰好 1 份凭证；混合成败并发 → 绝不出凭证；
- 取消 vs 完成各 200 轮、取消/过期扫描/完成 100×3 路竞争 →
  终态唯一且审计终态动作恰好一条。
