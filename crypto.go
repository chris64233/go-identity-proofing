package goidentityproofing

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"sort"
	"strings"
)

// digestSize 是 SHA-256 / HMAC-SHA-256 摘要的字节数。
const digestSize = 32

// challengeBytes 是随机挑战令牌的字节数（256 位熵）。
const challengeBytes = 32

// credentialTokenBytes 是凭证令牌的字节数。
const credentialTokenBytes = 32

// randomToken 返回 n 字节密码学随机数的十六进制编码。
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// sha256Hex 计算数据的 SHA-256 摘要。用于高熵、无需加盐的对象
// （挑战令牌、凭证令牌本身由 crypto/rand 生成）。
func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

// hmacHex 用服务端 pepper 计算数据的 HMAC-SHA-256。用于低熵、可被枚举的
// 敏感对象（申请人姓名、证件号、外部回执原文），防止持久层泄露后被反查。
func hmacHex(pepper string, data []byte) string {
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// hashPrefix 返回十六进制摘要的短前缀，仅供审计与日志定位，不可用于校验。
func hashPrefix(hexDigest string) string {
	const prefixLen = 12
	if len(hexDigest) < prefixLen {
		return hexDigest
	}
	return hexDigest[:prefixLen]
}

// equalHash 以恒定时间比较两个十六进制摘要，避免计时侧信道。
func equalHash(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// canonicalApplicant 以字段顺序确定的方式编码申请人信息，
// Extra 按 key 排序，保证同一申请人始终得到同一摘要。
func canonicalApplicant(a ApplicantInfo) []byte {
	var b strings.Builder
	b.WriteString("v1\n")
	b.WriteString("name=")
	b.WriteString(strings.TrimSpace(a.FullName))
	b.WriteString("\ndoc_type=")
	b.WriteString(strings.TrimSpace(a.DocumentType))
	b.WriteString("\ndoc_number=")
	b.WriteString(strings.TrimSpace(a.DocumentNumber))

	keys := make([]string, 0, len(a.Extra))
	for k := range a.Extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString("\n")
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(a.Extra[k])
	}
	return []byte(b.String())
}

// receiptCanonicalBytes 以字段顺序确定的方式编码回执内容。
// ReceiptNumber 不参与：它是幂等键，内容哈希用于检测“同号异内容”冲突。
func receiptCanonicalBytes(r Receipt) []byte {
	var b strings.Builder
	b.WriteString("v1\nproof=")
	b.WriteString(string(r.ProofType))
	b.WriteString("\nchallenge_hash=")
	// 只纳入挑战哈希，避免把挑战明文扩散到回执摘要的计算输入之外；
	// 挑战本身不持久化，这里仅做内存内计算。
	b.WriteString(sha256Hex(r.Challenge))
	b.WriteString("\nsuccess=")
	if r.Success {
		b.WriteString("true")
	} else {
		b.WriteString("false")
	}
	b.WriteString("\nreason=")
	b.WriteString(r.Reason)
	return []byte(b.String())
}

// receiptContentHash 计算回执内容的 HMAC 摘要（pepper 防止枚举外部回执）。
func receiptContentHash(pepper string, r Receipt) string {
	return hmacHex(pepper, receiptCanonicalBytes(r))
}

// applicantDigest 计算申请人信息摘要。
func applicantDigest(pepper string, a ApplicantInfo) string {
	return hmacHex(pepper, canonicalApplicant(a))
}

// maskName 姓名脱敏：保留首字符，其余以 * 替代；单字符保留并加 *。
// 非 ASCII 字符按 rune 处理。
func maskName(name string) string {
	name = strings.TrimSpace(name)
	runes := []rune(name)
	switch len(runes) {
	case 0:
		return ""
	case 1:
		return string(runes[0]) + "*"
	default:
		return string(runes[0]) + strings.Repeat("*", len(runes)-1)
	}
}

// maskDocumentNumber 证件号脱敏：保留后四位，其余以 * 替代。
func maskDocumentNumber(number string) string {
	number = strings.TrimSpace(number)
	runes := []rune(number)
	if len(runes) <= 4 {
		return strings.Repeat("*", len(runes))
	}
	return strings.Repeat("*", len(runes)-4) + string(runes[len(runes)-4:])
}

// applicantLabel 生成审计/展示用脱敏标签，不含任何完整敏感字段。
func applicantLabel(a ApplicantInfo) string {
	return maskName(a.FullName) + "|" + maskDocumentNumber(a.DocumentNumber)
}
