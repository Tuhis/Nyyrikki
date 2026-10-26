package canary

import "fmt"

func Bad() string { return fmt.Sprintf("%d", "not a number") }
