// Package sshhost embeds the SSH host setup script, so that nyyrikkid
// serves exactly the file in the repo (docs/07 D16, OD3).
package sshhost

import _ "embed"

// Script is deploy/ssh-host/nyyrikki-host-setup.sh, byte for byte.
//
//go:embed nyyrikki-host-setup.sh
var Script []byte
