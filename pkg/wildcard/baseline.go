package wildcard

import (
	"encoding/json"
	"fmt"
	"sort"

	xxhash "github.com/cespare/xxhash/v2"
)

// AnswerSet represents a DNS answer in canonical form.
type AnswerSet struct {
	RecordType string   `json:"type"`
	TTL        uint32   `json:"ttl"`
	Rdata      []string `json:"rdata"`
}

// canonicalize sorts rdata for stable hashing.
func canonicalize(set []AnswerSet) []AnswerSet {
	out := make([]AnswerSet, len(set))
	for i, ans := range set {
		r := append([]string(nil), ans.Rdata...)
		sort.Strings(r)
		out[i] = AnswerSet{RecordType: ans.RecordType, TTL: ans.TTL, Rdata: r}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RecordType == out[j].RecordType {
			if out[i].TTL == out[j].TTL {
				return fmt.Sprint(out[i].Rdata) < fmt.Sprint(out[j].Rdata)
			}
			return out[i].TTL < out[j].TTL
		}
		return out[i].RecordType < out[j].RecordType
	})
	return out
}

// HashSet hashes the provided answer set using xxhash.
func HashSet(set []AnswerSet) string {
	c := canonicalize(set)
	b, _ := json.Marshal(c)
	h := xxhash.Sum64(b)
	return fmt.Sprintf("%x", h)
}
