package rules

import (
	"context"
	"time"
)

// Usage is one call to the AI provider (D24: Admin › System, AI usage).
type Usage struct {
	Purpose         string // "rule", "test", later "fix"
	Provider, Model string
	Rule            string
	User, Eng, Fid  string // from the context (WithCaller); "" when unknown
	In, Out         int    // tokens as the provider reported them
	Took            time.Duration
	OK              bool
}

// Caller names who a run is for and on which finding.
type Caller struct{ User, Eng, Fid string }

type callerKey struct{}

// WithCaller carries c to the AI calls made under ctx.
func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// CallerOf is the caller ctx carries (zero when none).
func CallerOf(ctx context.Context) Caller {
	c, _ := ctx.Value(callerKey{}).(Caller)
	return c
}
