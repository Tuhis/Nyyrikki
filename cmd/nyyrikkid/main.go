// Command nyyrikkid is the Nyyrikki server (docs/01 D2). This is the
// skeleton of docs/01 FD1: it starts and exits.
package main

import "fmt"

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

func main() { fmt.Println("nyyrikkid", version) }
