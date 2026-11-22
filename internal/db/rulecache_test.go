package db

import (
	"fmt"
	"testing"
)

// Q1, Q16: a rule result is stored by its key with its kind and read back;
// storing a key again replaces it.
func TestRuleResult(t *testing.T) {
	d, _ := open(t)
	if _, ok, err := d.RuleResult("k1"); ok || err != nil {
		t.Fatalf("empty table: %v %v", ok, err)
	}
	if err := d.PutRuleResult("k1", "ai", `{"violations":[]}`); err != nil {
		t.Fatal(err)
	}
	if err := d.PutRuleResult("k2", "script", `[]`); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := d.RuleResult("k1"); !ok || err != nil || v != `{"violations":[]}` {
		t.Fatalf("k1 %q %v %v", v, ok, err)
	}
	if err := d.PutRuleResult("k1", "ai", `{"violations":null}`); err != nil {
		t.Fatal(err)
	}
	if v, _, _ := d.RuleResult("k1"); v != `{"violations":null}` {
		t.Fatalf("k1 replaced %q", v)
	}
	var kind string
	var created int64
	if err := d.QueryRow("SELECT kind, created FROM rule_cache WHERE key = 'k2'").Scan(&kind, &created); err != nil || kind != "script" || created < d.now().Unix()-60 {
		t.Fatalf("k2 %q %d %v", kind, created, err)
	}
	if n := count(t, d, "rule_cache"); n != 2 {
		t.Fatalf("rows %d", n)
	}
}

// Q1: the table keeps the newest rows only: storing past the limit drops
// the oldest.
func TestRuleResultBounded(t *testing.T) {
	d, _ := open(t)
	for i := range 8 {
		if err := d.putRuleResult(fmt.Sprint("k", i), "ai", "{}", 5); err != nil {
			t.Fatal(err)
		}
	}
	if n := count(t, d, "rule_cache"); n != 5 {
		t.Fatalf("rows %d", n)
	}
	for i := range 8 {
		_, ok, err := d.RuleResult(fmt.Sprint("k", i))
		if err != nil || ok != (i >= 3) {
			t.Fatalf("k%d kept %v (%v)", i, ok, err)
		}
	}
	// a key stored again is new: it outlives the ones stored after it first
	if err := d.putRuleResult("k3", "ai", "{}", 5); err != nil {
		t.Fatal(err)
	}
	if err := d.putRuleResult("k8", "ai", "{}", 5); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := d.RuleResult("k3"); !ok {
		t.Fatal("k3 stored again was dropped")
	}
	if _, ok, _ := d.RuleResult("k4"); ok {
		t.Fatal("k4 outlived the limit")
	}
	if n := count(t, d, "rule_cache"); n > 5 {
		t.Fatalf("rows %d", n)
	}
	if RuleCacheMax != 50000 {
		t.Fatalf("RuleCacheMax %d", RuleCacheMax)
	}
}

// Q1: an older database gets the table on opening.
func TestMigrateAddsRuleCache(t *testing.T) {
	p := openAtVersion(t, schemaVersion-1)
	d, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.PutRuleResult("k", "script", "[]"); err != nil {
		t.Fatal(err)
	}
	var name string
	if err := d.QueryRow("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'rule_cache'").Scan(&name); err != nil {
		t.Fatalf("no rule_cache: %v", err)
	}
}
