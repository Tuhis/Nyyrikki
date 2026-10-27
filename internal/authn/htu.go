package authn

import (
	"net/url"
	"strings"
)

// normalizeHTU normalises a URL for comparing a proof's htu (docs/01 D9):
// query and fragment removed, scheme and host lowercased, default port
// dropped, percent-encoding normalised and an empty path made "/"
// (RFC 3986 §6.2.2–6.2.3). It returns "" for anything that isn't an
// absolute http(s) URL.
func normalizeHTU(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	path := u.EscapedPath()
	// Decoding and re-escaping normalises %7e vs ~ and the case of %xx.
	if p, err := url.PathUnescape(path); err == nil {
		path = (&url.URL{Path: p}).EscapedPath()
	} else {
		return ""
	}
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path
}
