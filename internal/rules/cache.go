package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"

	"yars/internal/lru"
)

// ResultStore keeps the results of script and AI rules across restarts (the
// database's rule_cache).
type ResultStore interface {
	// RuleResult returns the result (JSON) stored under key; ok is false
	// when there is none.
	RuleResult(key string) (result string, ok bool, err error)
	// PutRuleResult stores result (JSON) under key; kind is ai or script.
	PutRuleResult(key, kind, result string) error
}

// AICacheSize and ScriptCacheSize bound the results a runner keeps in
// memory.
const (
	AICacheSize     = 2000
	ScriptCacheSize = 2000
)

func (rn *Runner) initCache() {
	rn.cacheOnce.Do(func() {
		rn.cache = lru.New[string, aiResult](AICacheSize)
		rn.scripts = lru.New[string, []Violation](ScriptCacheSize)
	})
}

func (rn *Runner) aiCache() *lru.Cache[string, aiResult] {
	rn.initCache()
	return rn.cache
}

func (rn *Runner) scriptCache() *lru.Cache[string, []Violation] {
	rn.initCache()
	return rn.scripts
}

// resultKey is the hex SHA-256 of parts, each after a NUL but the first.
func resultKey(parts ...string) string {
	h := sha256.New()
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte{0})
		}
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// stored reads the result kept under key into v; false when there is none
// or it cannot be read (the rule runs then).
func (rn *Runner) stored(key string, v any) bool {
	if rn.Results == nil {
		return false
	}
	s, ok, err := rn.Results.RuleResult(key)
	if err == nil && ok {
		err = json.Unmarshal([]byte(s), v)
	}
	if err != nil {
		log.Printf("rules: stored result: %v", err)
		return false
	}
	return ok
}

// keep stores v under key (kind ai or script).
func (rn *Runner) keep(key, kind string, v any) {
	if rn.Results == nil {
		return
	}
	b, err := json.Marshal(v)
	if err == nil {
		err = rn.Results.PutRuleResult(key, kind, string(b))
	}
	if err != nil {
		log.Printf("rules: store result: %v", err)
	}
}
