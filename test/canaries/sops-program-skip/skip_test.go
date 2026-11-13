package canary

import "testing"

// Two pass, so the count is met; the third skips, which the gate must
// not take for a pass.
func TestSOPSProgramOne(t *testing.T) {}
func TestSOPSProgramTwo(t *testing.T) {}
func TestSOPSProgramThree(t *testing.T) {
	t.Run("deep", func(t *testing.T) { t.Skip("planted skip") })
}
