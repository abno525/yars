package main

import (
	"strings"
	"testing"
)

// A certificate needs its key and the key its certificate.
func TestServeTLSFlagsNeedBoth(t *testing.T) {
	for _, args := range [][]string{{"--tls-cert", "x"}, {"--tls-key", "y"}} {
		err := cmdServe(args)
		if err == nil || err.Error() != "--tls-cert and --tls-key go together" {
			t.Fatalf("%v: err %v", args, err)
		}
	}
	if err := cmdServe([]string{"--https", "--tls-cert", "x"}); err == nil || !strings.Contains(err.Error(), "go together") {
		t.Fatalf("--https with only a certificate: %v", err)
	}
}
