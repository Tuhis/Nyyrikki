package request

import "strings"

// allowedCommands are the command paths of docs/04 §5.4. Everything else,
// including D5's list, is refused.
var allowedCommands = map[string]bool{
	"get": true, "describe": true, "logs": true, "events": true,
	"top node": true, "top pod": true,
	"explain": true, "api-resources": true, "api-versions": true,
	"version": true, "cluster-info": true,
	"auth can-i": true, "auth whoami": true, "auth reconcile": true,
	"wait": true, "create": true,
	"apply": true, "apply view-last-applied": true, "apply set-last-applied": true,
	"delete": true, "patch": true, "replace": true, "label": true,
	"annotate": true, "scale": true, "autoscale": true, "expose": true,
	"run": true, "cordon": true, "uncordon": true, "drain": true,
	"taint": true, "certificate approve": true, "certificate deny": true,
	"exec": true, "attach": true, "debug": true,
}

// allowedTrees are the commands whose subcommands are all allowed
// (docs/04 §5.4: "create and its subcommands", and so on). The bare
// parent is allowed only when allowedCommands lists it: bare "set" and
// "rollout" only print help.
var allowedTrees = map[string]bool{"create": true, "set": true, "rollout": true}

func commandAllowed(path []string) bool {
	if len(path) == 0 {
		return false
	}
	return allowedCommands[strings.Join(path, " ")] || (len(path) > 1 && allowedTrees[path[0]])
}

// deniedFlags are refused for every command, by resolved long name
// (docs/04 D4). The value is the reason shown to the agent.
var deniedFlags = map[string]string{
	// Connection and identity: the request can't name another cluster,
	// user or identity (docs/04 D4, D10).
	"kubeconfig":               "connection and identity are set by Nyyrikki",
	"context":                  "connection and identity are set by Nyyrikki",
	"cluster":                  "connection and identity are set by Nyyrikki",
	"user":                     "connection and identity are set by Nyyrikki",
	"server":                   "connection and identity are set by Nyyrikki",
	"token":                    "connection and identity are set by Nyyrikki",
	"username":                 "connection and identity are set by Nyyrikki",
	"password":                 "connection and identity are set by Nyyrikki",
	"client-certificate":       "connection and identity are set by Nyyrikki",
	"client-key":               "connection and identity are set by Nyyrikki",
	"certificate-authority":    "connection and identity are set by Nyyrikki",
	"insecure-skip-tls-verify": "connection and identity are set by Nyyrikki",
	"tls-server-name":          "connection and identity are set by Nyyrikki",
	"as":                       "the request runs as your human, set by Nyyrikki",
	"as-group":                 "the request runs as your human, set by Nyyrikki",
	"as-uid":                   "the request runs as your human, set by Nyyrikki",
	"cache-dir":                "it touches Nyyrikki's disk",
	"kuberc":                   "kuberc is off",
	"profile":                  "it writes to Nyyrikki's disk",
	"profile-output":           "it writes to Nyyrikki's disk",
	// Flags that read Nyyrikki's own disk or network (docs/04 D4, M7).
	"kustomize":     "it reads Nyyrikki's disk",
	"from-file":     "it reads Nyyrikki's disk",
	"from-env-file": "it reads Nyyrikki's disk",
	"custom":        "it reads Nyyrikki's disk",
	"edit":          "it needs an editor",
	// Not in docs/04 D4's list, found reading kubectl v0.37.1: each reads
	// a file from the machine kubectl runs on (patch.go, create_secret_tls.go).
	"patch-file": "it reads Nyyrikki's disk",
	"cert":       "it reads Nyyrikki's disk",
	"key":        "it reads Nyyrikki's disk",
}

// fileOutputFormats are the --output formats that read a template from a
// local file. The path can be in the --output value or in --template, so
// the format alone is refused (docs/04 D4; custom-columns-file found in
// kubectl's get/customcolumn_flags.go).
var fileOutputFormats = []string{"jsonpath-file", "go-template-file", "templatefile", "custom-columns-file"}

// flagDenied returns why f is refused, or "" when it is allowed.
func flagDenied(f flagValue) string {
	if reason, ok := deniedFlags[f.name]; ok {
		return reason
	}
	switch f.name {
	case "filename":
		// docs/04 D4: only stdin.
		if len(f.values) != 1 || f.values[0] != "-" {
			return "only -f - (stdin) is allowed"
		}
	case "output":
		for _, v := range f.values {
			// kubectl lowercases some formats before matching; compare
			// case-insensitively so no spelling slips through.
			format := strings.ToLower(strings.TrimSpace(v))
			for _, ff := range fileOutputFormats {
				if format == ff || strings.HasPrefix(format, ff+"=") {
					return "file-based output formats read Nyyrikki's disk"
				}
			}
		}
	}
	return ""
}
