package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The workflow key: "simple" is the simple workflow; no key (or
// "standard") is the standard one; anything else does not load. Default
// writes no key, so a standard config.yaml looks as it always did.
func TestWorkflowKey(t *testing.T) {
	c, err := Parse([]byte("workflow: simple\n"))
	if err != nil || c.Workflow != WorkflowSimple || !c.Simple() {
		t.Fatalf("simple: %+v %v", c.Workflow, err)
	}
	for _, in := range []string{"", "sections: [A]\n", "workflow: standard\n"} {
		c, err := Parse([]byte(in))
		if err != nil || c.Simple() {
			t.Errorf("%q: simple=%v %v", in, c.Simple(), err)
		}
	}
	if _, err := Parse([]byte("workflow: lean\n")); err == nil || err.Error() != `config: workflow "lean" must be standard or simple` {
		t.Fatalf("lean: %v", err)
	}
	if Default().Simple() || Default().Workflow != "" {
		t.Fatal("the default is not the standard workflow")
	}
	b, err := yaml.Marshal(Default())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "workflow") {
		t.Fatalf("the default config writes a workflow key:\n%s", b)
	}
	s := Default()
	s.Workflow = WorkflowSimple
	if b, _ := yaml.Marshal(s); !strings.HasPrefix(string(b), "workflow: simple\n") {
		t.Fatalf("the workflow key is not at the top:\n%s", b)
	}
	if WorkflowStandard != "standard" || WorkflowSimple != "simple" {
		t.Fatal("names")
	}
}
