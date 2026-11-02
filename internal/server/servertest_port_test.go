package server_test

import (
	"net"
	"testing"

	"github.com/Tuhis/Nyyrikki/internal/server/servertest"
)

// TestStartRetriesATakenPort: servertest picks a free port, closes it and
// lets nyyrikkid bind it; another test can take it in between ("bind:
// address already in use", CI on #56). Start must pick another port
// rather than fail.
func TestStartRetriesATakenPort(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	calls := 0
	orig := servertest.PickAddr
	servertest.PickAddr = func(t testing.TB) string {
		calls++
		if calls == 1 {
			return taken.Addr().String()
		}
		return orig(t)
	}
	defer func() { servertest.PickAddr = orig }()
	e := servertest.Start(t)
	if e.MainAddr == taken.Addr().String() || calls < 2 {
		t.Fatalf("started on %s after %d picks; want another port than the taken %s", e.MainAddr, calls, taken.Addr())
	}
}
