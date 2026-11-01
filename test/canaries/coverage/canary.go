package canary

// Tested is covered by canary_test.go.
func Tested() int { return 1 }

// Untested has no test, so the total stays below the canary's floor of 90.
func Untested(n int) int {
	if n > 0 {
		return n * 2
	}
	return -n
}
