package protocol

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Live check: a direct probe must succeed on a machine that can reach WeChat.
// Skips when the environment has no WeChat access.
func TestProbeLongLinkLiveDirect(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result := ProbeLongLink(ctx, "", 10*time.Second)
	t.Logf("direct probe: ok=%v stage=%s target=%s elapsed=%dms err=%s",
		result.OK, result.Stage, result.Target, result.ElapsedMS, result.Err)
	if !result.OK {
		t.Skipf("environment cannot reach WeChat LongLink: %s", result.Err)
	}
	if result.Stage != ProbeStageOK {
		t.Fatalf("stage = %q, want ok", result.Stage)
	}
}

var _ = fmt.Sprint
