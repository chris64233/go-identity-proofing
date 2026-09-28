package goidentityproofing

import "encoding/json"

// cloneSession 通过 JSON 序列化往返做深拷贝。持久化记录全部由可序列化的
// 基础类型构成；这同时充当“持久化形态自检”——任何不可序列化的字段
// （例如放错位置的明文敏感数据）都会立即暴露。
func cloneSession(s *persistedSession) *persistedSession {
	if s == nil {
		return nil
	}
	data, err := json.Marshal(s)
	if err != nil {
		// 记录类型由本包完全控制且仅含基础类型，序列化失败属于程序缺陷。
		panic("proofing: cannot marshal persisted session: " + err.Error())
	}
	var out persistedSession
	if err := json.Unmarshal(data, &out); err != nil {
		panic("proofing: cannot unmarshal persisted session: " + err.Error())
	}
	return &out
}
