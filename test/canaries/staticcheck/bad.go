package canary

import "strings"

func Bad(s string) bool {
	strings.ToUpper(s) // SA4017: result discarded
	return true
}
