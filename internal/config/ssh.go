package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// validateSSH checks the shared ssh block (docs/07 §5.5, docs/08 §5.3). Each value
// that the setup endpoint serves is checked for the format the setup
// script accepts too (docs/07 D16), so nothing the script would refuse,
// or read as anything but data, is ever served.
func validateSSH(s *SSH) []error {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if s.UserCAKeyFile == "" {
		bad("user_ca_key_file is required")
	}
	// docs/08 D1: three different files; one path for two keys would
	// make a staged key the current one, or the host CA a user CA.
	if s.NextUserCAKeyFile != "" && s.NextUserCAKeyFile == s.UserCAKeyFile {
		bad("next_user_ca_key_file must differ from user_ca_key_file")
	}
	if s.HostCAKeyFile != "" && (s.HostCAKeyFile == s.UserCAKeyFile || s.HostCAKeyFile == s.NextUserCAKeyFile) {
		bad("host_ca_key_file must differ from user_ca_key_file and next_user_ca_key_file")
	}
	// user_ca_public_keys holds only extra keys now; the CA keys' own
	// public halves are derived from the key files (docs/08 D1).
	for i, k := range s.UserCAPublicKeys {
		if _, err := ParseUserCAKey(k); err != nil {
			bad("user_ca_public_keys[%d]: %v", i, err)
		}
	}
	for i, k := range s.RevokedUserCAKeys {
		if _, err := ParseUserCAKey(k); err != nil {
			bad("revoked_user_ca_keys[%d]: %v", i, err)
		}
	}
	if len(s.SourceAddresses) == 0 {
		bad("source_addresses is required")
	}
	for i, a := range s.SourceAddresses {
		if _, err := ParseSourceAddress(a); err != nil {
			bad("source_addresses[%d]: %v", i, err)
		}
	}
	if d := s.ConnectTimeout.D(); d <= 0 || d > time.Minute {
		bad("connect_timeout must be positive and at most 1m")
	}
	if d := s.HostCertValidity.D(); d <= 0 || d > MaxHostCertValidity {
		bad("host_cert_validity must be positive and at most 87600h")
	}
	for i, k := range s.HostCAs {
		if err := checkHostCA(k); err != nil {
			bad("host_cas[%d]: %v", i, err)
		}
	}
	for i, k := range s.RevokedHostKeys {
		pk, err := ParsePublicKey(k)
		if err != nil {
			bad("revoked_host_keys[%d]: %v", i, err)
		} else if _, isCert := pk.(*ssh.Certificate); isCert {
			bad("revoked_host_keys[%d]: list the host's key or the CA's key, not a certificate", i)
		}
	}
	return errs
}

// checkRevokedPins reports each pin of t that is listed in revoked
// (docs/08 D9): a pinned key that is also revoked is a contradiction in
// the config, not something to resolve at run time.
func checkRevokedPins(t *SSHTarget, revoked []string) []error {
	var errs []error
	set := map[string]bool{}
	for _, k := range revoked {
		if pk, err := ParsePublicKey(k); err == nil {
			set[string(pk.Marshal())] = true
		}
	}
	for i, k := range t.HostKeys {
		if pk, err := ParsePublicKey(k); err == nil && set[string(pk.Marshal())] {
			errs = append(errs, fmt.Errorf("host_keys[%d] is listed in ssh.revoked_host_keys", i))
		}
	}
	return errs
}

func checkHostCA(k string) error {
	pk, err := ParsePublicKey(k)
	if err != nil {
		return err
	}
	if _, isCert := pk.(*ssh.Certificate); isCert {
		return errors.New("must be a CA public key, not a certificate")
	}
	return nil
}

func validateSSHTarget(t *SSHTarget) []error {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if _, _, err := SplitAddress(t.Address); err != nil {
		bad("address: %v", err)
	}
	for i, k := range t.HostKeys {
		pk, err := ParsePublicKey(k)
		if err != nil {
			bad("host_keys[%d]: %v", i, err)
		} else if _, isCert := pk.(*ssh.Certificate); isCert {
			bad("host_keys[%d]: a certificate is not a host key; put its CA in host_cas", i)
		}
	}
	for i, k := range t.HostCAs {
		if err := checkHostCA(k); err != nil {
			bad("host_cas[%d]: %v", i, err)
		}
	}
	return errs
}

// DefaultSSHPort is the port of an SSH address that names none
// (docs/08 D11).
const DefaultSSHPort = "22"

// withDefaultPort adds DefaultSSHPort to an address without a port: a
// DNS name, an IPv4 address, or an IPv6 address, bare or in brackets.
// Anything else is returned as is, for SplitAddress to judge.
func withDefaultPort(a string) string {
	if ip, err := netip.ParseAddr(a); err == nil && ip.Zone() == "" {
		return net.JoinHostPort(a, DefaultSSHPort)
	}
	if strings.HasPrefix(a, "[") && strings.HasSuffix(a, "]") {
		if ip, err := netip.ParseAddr(a[1 : len(a)-1]); err == nil && ip.Is6() && ip.Zone() == "" {
			return net.JoinHostPort(ip.String(), DefaultSSHPort)
		}
		return a
	}
	if a != "" && !strings.Contains(a, ":") {
		return net.JoinHostPort(a, DefaultSSHPort)
	}
	return a
}

var hostname = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// SplitAddress splits an SSH target's address, host:port, and checks
// both: the host is a DNS name or an IP address, the port 1–65535.
func SplitAddress(a string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(a)
	if err != nil {
		return "", 0, errors.New("must be host:port")
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
		return "", 0, errors.New("port must be 1 to 65535")
	}
	if _, err := netip.ParseAddr(h); err != nil && !hostname.MatchString(h) {
		return "", 0, errors.New("host must be a DNS name or an IP address")
	}
	return h, n, nil
}

// ParsePublicKey parses one key in authorized_keys format, with no
// options.
func ParsePublicKey(s string) (ssh.PublicKey, error) {
	pk, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		return nil, errors.New("not an SSH public key")
	}
	if len(opts) > 0 || len(strings.TrimSpace(string(rest))) > 0 {
		return nil, errors.New("must be exactly one key, without options")
	}
	return pk, nil
}

var base64Only = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)

// ParseUserCAKey parses a user CA public key: ed25519 only
// (docs/07 D6, D16).
func ParseUserCAKey(s string) (ssh.PublicKey, error) {
	fields := strings.Fields(s)
	if len(fields) < 2 || fields[0] != ssh.KeyAlgoED25519 || !base64Only.MatchString(fields[1]) {
		return nil, errors.New("must be an ssh-ed25519 public key")
	}
	pk, err := ParsePublicKey(s)
	if err != nil {
		return nil, err
	}
	if pk.Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("must be an ssh-ed25519 public key")
	}
	return pk, nil
}

// ParseSourceAddress parses one of Nyyrikki's source addresses: a CIDR
// in canonical form, as both sshd's from= and the certificate's
// source-address take it (docs/07 D4, D5).
func ParseSourceAddress(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || p.String() != s || p.Masked() != p {
		return netip.Prefix{}, errors.New("must be a CIDR in canonical form, such as 203.0.113.10/32")
	}
	// The setup script refuses IPv4-mapped IPv6, and nothing it refuses
	// is served (docs/07 D16): write the IPv4 range itself.
	if p.Addr().Is4In6() {
		return netip.Prefix{}, errors.New("must not be IPv4-mapped IPv6; write the IPv4 range, such as 10.0.0.0/8")
	}
	return p, nil
}
