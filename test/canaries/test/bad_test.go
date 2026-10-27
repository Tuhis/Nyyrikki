package canary

import "testing"

func TestFails(t *testing.T) { t.Fatal("planted failure") }
