package sshca

import (
	"fmt"
	"log/slog"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/config"
)

// FromConfig builds the loader of the ssh block (docs/08 D1): the three
// key files, the extra trusted keys and the revoked ones. The server and
// `nyyrikkid enroll-token` build it the same way, so they read the same
// keys. a may be nil.
func FromConfig(s config.SSH, a audit.Appender, log *slog.Logger) (*Keys, error) {
	o := Options{
		Files:  Files{UserCA: s.UserCAKeyFile, NextUserCA: s.NextUserCAKeyFile, HostCA: s.HostCAKeyFile},
		Audit:  a,
		Logger: log,
	}
	for i, k := range s.UserCAPublicKeys {
		pk, err := config.ParseUserCAKey(k)
		if err != nil {
			return nil, fmt.Errorf("ssh.user_ca_public_keys[%d]: %w", i, err)
		}
		o.Extra = append(o.Extra, pk)
	}
	for i, k := range s.RevokedUserCAKeys {
		pk, err := config.ParseUserCAKey(k)
		if err != nil {
			return nil, fmt.Errorf("ssh.revoked_user_ca_keys[%d]: %w", i, err)
		}
		o.Revoked = append(o.Revoked, pk)
	}
	return New(o), nil
}
