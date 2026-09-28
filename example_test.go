package goidentityproofing_test

import (
	"fmt"
	"time"

	proofing "github.com/chris64233/go-identity-proofing"
)

// 固定时钟仅为保证示例输出确定；生产代码不传 WithClock。
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func Example() {
	start := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	svc, err := proofing.NewService(
		proofing.NewMemoryRepository(),
		proofing.WithPepper("shared-hmac-pepper"),
		proofing.WithClock(fixedClock{t: start}.Now),
	)
	if err != nil {
		panic(err)
	}

	// 1) 创建会话：冻结证明清单、申请人摘要、截止时间；挑战只返回这一次。
	created, err := svc.CreateSession(proofing.CreateSessionRequest{
		RequiredProofs: []proofing.ProofType{"id_document", "face_match"},
		Applicant: proofing.ApplicantInfo{
			FullName:       "张三丰",
			DocumentType:   "passport",
			DocumentNumber: "E123456789",
		},
		Deadline: start.Add(30 * time.Minute),
	})
	if err != nil {
		panic(err)
	}
	sid := created.Session.ID
	fmt.Println("status:", created.Session.Status)
	fmt.Println("label:", created.Session.ApplicantLabel)

	// 2) 外部结果乱序到达，凭挑战明文提交回执。
	if _, err := svc.SubmitResult(sid, proofing.Receipt{
		ReceiptNumber: "EXT-2",
		ProofType:     "face_match",
		Challenge:     created.Challenges["face_match"],
		Success:       true,
	}); err != nil {
		panic(err)
	}
	final, err := svc.SubmitResult(sid, proofing.Receipt{
		ReceiptNumber: "EXT-1",
		ProofType:     "id_document",
		Challenge:     created.Challenges["id_document"],
		Success:       true,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("final:", final.Session.Status)
	fmt.Println("credential issued:", final.Credential != nil && final.Credential.Token != "")

	// 3) 重复回执（相同回执号、相同内容）返回首次结果，不再下发凭证明文。
	replay, err := svc.SubmitResult(sid, proofing.Receipt{
		ReceiptNumber: "EXT-1",
		ProofType:     "id_document",
		Challenge:     created.Challenges["id_document"],
		Success:       true,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("replayed:", replay.Replayed)
	fmt.Println("token on replay hidden:", replay.Session.Credential != nil && replay.Session.Credential.Token == "")

	// 4) 查询会话与审计轨迹。
	view, _ := svc.GetSession(sid)
	fmt.Println("query:", view.Status)
	trail, _ := svc.GetAuditTrail(sid)
	fmt.Println("audit entries:", len(trail))

	// Output:
	// status: active
	// label: 张**|******6789
	// final: completed
	// credential issued: true
	// replayed: true
	// token on replay hidden: true
	// query: completed
	// audit entries: 7
}
