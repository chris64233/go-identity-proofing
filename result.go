package goidentityproofing

// SubmitResult 提交一份外部核验回执。
//
// 处理顺序（全部在单会话事务内）：
//  1. 基础参数校验；
//  2. 回执号幂等：同号同内容返回首次处理结果（Replayed=true）；
//     同号异内容返回 ErrReceiptConflict；
//  3. 会话必须存在、未处于终态、未过截止时间（惰性推进过期）；
//  4. 证明类型必须属于创建时冻结的清单，且尚未有终态结果
//     （失败项不得被后来的成功回执静默覆盖）；
//  5. 挑战必须与该证明当前挑战哈希一致、未过期、未被消费
//     （过期挑战/旧挑战的结果一律拒绝）；
//  6. 记录结果、消费挑战；若全部必需证明成功则唯一一次性签发凭证；
//     若本项失败则会话进入 failed 终态。
func (s *Service) SubmitResult(sessionID string, r Receipt) (*ResultView, error) {
	if sessionID == "" || r.ReceiptNumber == "" || r.ProofType == "" || r.Challenge == "" {
		return nil, ErrInvalidArgument
	}
	contentHash := receiptContentHash(s.pepper, r)

	var res ResultView
	err := s.repo.UpdateSessionTx(sessionID, func(sn *persistedSession) error {
		now := s.now()

		// (2) 幂等/冲突检查先于其他一切校验：同一回执号无论重复、乱序、
		// 延迟多久到达，语义都必须稳定。
		if prev, ok := sn.Receipts[r.ReceiptNumber]; ok {
			if !equalHash(prev.ContentHash, contentHash) {
				addAudit(sn, persistedAudit{
					At:            now,
					Action:        AuditReceiptRejected,
					ProofType:     r.ProofType,
					ReceiptNumber: r.ReceiptNumber,
					Detail:        "reason=receipt_conflict;first_proof=" + string(prev.ProofType),
				})
				return ErrReceiptConflict
			}
			addAudit(sn, persistedAudit{
				At:            now,
				Action:        AuditProofReplayed,
				ProofType:     prev.ProofType,
				ReceiptNumber: r.ReceiptNumber,
			})
			// 返回首次处理时刻的会话结果；凭证令牌明文不二次下发。
			res = ResultView{
				ReceiptNumber: prev.Number,
				ProofType:     prev.ProofType,
				Success:       prev.Success,
				Replayed:      true,
				Session:       toView(sn, ""),
			}
			return nil
		}

		// (3) 会话状态校验。
		if s.advanceExpiredLocked(sn) {
			addAudit(sn, persistedAudit{
				At:            now,
				Action:        AuditReceiptRejected,
				ProofType:     r.ProofType,
				ReceiptNumber: r.ReceiptNumber,
				Detail:        "reason=session_expired",
			})
			return ErrSessionExpired
		}
		if sn.Status != StatusActive {
			addAudit(sn, persistedAudit{
				At:            now,
				Action:        AuditReceiptRejected,
				ProofType:     r.ProofType,
				ReceiptNumber: r.ReceiptNumber,
				Detail:        "reason=session_terminal;status=" + string(sn.Status),
			})
			return terminalError(sn.Status)
		}

		// (4) 证明归属与终态保护。
		p, ok := sn.Proofs[r.ProofType]
		if !ok {
			addAudit(sn, persistedAudit{
				At:            now,
				Action:        AuditReceiptRejected,
				ProofType:     r.ProofType,
				ReceiptNumber: r.ReceiptNumber,
				Detail:        "reason=unknown_proof",
			})
			return ErrUnknownProof
		}
		if p.Status != ProofPending {
			addAudit(sn, persistedAudit{
				At:            now,
				Action:        AuditReceiptRejected,
				ProofType:     r.ProofType,
				ReceiptNumber: r.ReceiptNumber,
				Detail:        "reason=proof_handled;status=" + string(p.Status),
			})
			return ErrProofAlreadyHandled
		}

		// (5) 挑战三重匹配：证明槽位当前哈希一致 + 未过期 + 未消费。
		// 轮换过的旧挑战哈希与当前不一致，因此旧挑战的结果天然被拒。
		if !equalHash(p.Challenge.Hash, sha256Hex(r.Challenge)) {
			addAudit(sn, persistedAudit{
				At:            now,
				Action:        AuditReceiptRejected,
				ProofType:     r.ProofType,
				ReceiptNumber: r.ReceiptNumber,
				Detail:        "reason=challenge_mismatch",
			})
			return ErrChallengeMismatch
		}
		if p.Challenge.Consumed {
			addAudit(sn, persistedAudit{
				At:            now,
				Action:        AuditReceiptRejected,
				ProofType:     r.ProofType,
				ReceiptNumber: r.ReceiptNumber,
				Detail:        "reason=challenge_consumed",
			})
			return ErrChallengeExpired
		}
		if !now.Before(p.Challenge.ExpiresAt) {
			addAudit(sn, persistedAudit{
				At:            now,
				Action:        AuditReceiptRejected,
				ReceiptNumber: r.ReceiptNumber,
				ProofType:     r.ProofType,
				Detail:        "reason=challenge_expired",
			})
			return ErrChallengeExpired
		}

		// (6) 落结果：消费挑战、写证明、登记回执幂等记录。
		p.Challenge.Consumed = true
		if r.Success {
			p.Status = ProofSucceeded
		} else {
			p.Status = ProofFailed
		}
		p.Reason = r.Reason
		p.UpdatedAt = now
		sn.Receipts[r.ReceiptNumber] = &persistedReceipt{
			Number:      r.ReceiptNumber,
			ContentHash: contentHash,
			Success:     r.Success,
			ProofType:   r.ProofType,
			HandledAt:   now,
		}
		addAudit(sn, persistedAudit{
			At:            now,
			Action:        AuditProofSubmitted,
			ProofType:     r.ProofType,
			ReceiptNumber: r.ReceiptNumber,
			Detail:        "success=" + boolStr(r.Success),
		})

		res = ResultView{
			ReceiptNumber: r.ReceiptNumber,
			ProofType:     r.ProofType,
			Success:       r.Success,
		}

		// credentialToken 非空表示本次事务完成核验并签发凭证。
		var credentialToken string

		// 终态推进。事务持锁保证并发到达的最后几项证明中只有一个事务
		// 能观察到“全部成功且会话仍 active”，凭证最多签发一次。
		if !r.Success {
			sn.Status = StatusFailed
			addAudit(sn, persistedAudit{
				At:        now,
				Action:    AuditSessionFailed,
				ProofType: r.ProofType,
				Detail:    "proof=" + string(r.ProofType),
			})
		} else if allProofsSucceeded(sn) {
			token, err := randomToken(credentialTokenBytes)
			if err != nil {
				return err
			}
			credID, err := s.randomID("cre_")
			if err != nil {
				return err
			}
			sn.Credential = &persistedCredential{
				ID:        credID,
				TokenHash: sha256Hex(token),
				IssuedAt:  now,
			}
			sn.Status = StatusCompleted
			addAudit(sn, persistedAudit{
				At:     now,
				Action: AuditSessionCompleted,
				Detail: "credential=" + credID + ";token=" + hashPrefix(sn.Credential.TokenHash),
			})
			credentialToken = token
			res.Credential = &CredentialView{
				ID:        credID,
				SessionID: sn.ID,
				Token:     token,
				TokenHash: sn.Credential.TokenHash,
				IssuedAt:  now,
			}
		}
		// 凭证令牌明文只进入完成核验的当次响应；持久层与后续查询只有哈希。
		res.Session = toView(sn, credentialToken)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// allProofsSucceeded 判断会话全部必需证明是否均已成功。
func allProofsSucceeded(sn *persistedSession) bool {
	for _, t := range sn.RequiredProofs {
		if sn.Proofs[t].Status != ProofSucceeded {
			return false
		}
	}
	return true
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
