// Package sopstarget runs SOPS operations on files encrypted with Google
// Cloud KMS (docs/10): the request, its canonical form, digest and
// display (D2, D3, D8), the check of the file before any approval (D4),
// the key service that wraps SOPS's own Google key source (D5), the
// credential loader (D6), the request reason (D7) and the runner.
// Nothing outside this package imports the SOPS library (docs/10 §5.2).
package sopstarget

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	sopsconfig "github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/gcpkms"
	sopsjson "github.com/getsops/sops/v3/stores/json"
	sopsversion "github.com/getsops/sops/v3/version"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/textsafe"
)

// The operations offered (docs/10 OD4).
const (
	opDecrypt = "decrypt"
	opSet     = "set"
	opUnset   = "unset"
	opEncrypt = "encrypt"
)

// The flags a request may set (docs/10 D2).
const (
	flagInputType         = "input-type"
	flagOutputType        = "output-type"
	flagFilename          = "filename-override"
	flagExtract           = "extract"
	flagGCPKMS            = "gcp-kms"
	flagEncryptedRegex    = "encrypted-regex"
	flagUnencryptedRegex  = "unencrypted-regex"
	flagEncryptedSuffix   = "encrypted-suffix"
	flagUnencryptedSuffix = "unencrypted-suffix"
)

// Limits on what a request may hold.
const (
	// MaxFileName is the longest --filename-override (docs/10 D2).
	MaxFileName = 200
	// maxRule is the longest regex or suffix of an encrypt.
	maxRule = 200
	// maxDepth is the deepest tree a file may hold.
	maxDepth = 64
	// The cap on the "The file says" lines (docs/10 D8).
	maxSaysValues = 12
	maxSaysChars  = 400
)

// Detail values of the refusals Parse returns: all codes.InvalidRequest.
const (
	DetailNoCommand        = "no_command"
	DetailUnknownCommand   = "unknown_command"
	DetailUnknownFlag      = "unknown_flag"
	DetailFlagValue        = "flag_value"
	DetailDuplicateFlag    = "duplicate_flag"
	DetailMissingFlag      = "missing_flag"
	DetailArguments        = "arguments"
	DetailPath             = "path"
	DetailInteractive      = "interactive"
	DetailNoFile           = "no_file"
	DetailFileNotParsed    = "file_not_parsed"
	DetailNotEncrypted     = "file_not_encrypted"
	DetailAlreadyEncrypted = "file_already_encrypted"
	DetailDocuments        = "file_documents"
	DetailTooDeep          = "file_too_deep"
	DetailFileRules        = "file_rules"
	DetailKeyGroups        = "key_groups"
	DetailKeyType          = "key_type"
	DetailDuplicateKey     = "duplicate_key"
	// DetailKeyNotAllowed is also the runner's (docs/10 D9).
	DetailKeyNotAllowed = "key_not_allowed"
	// DetailPathNotFound is also the runner's (docs/10 D9).
	DetailPathNotFound = "path_not_found"
)

// The flags each operation takes besides --input-type and
// --filename-override (docs/10 D2).
var opFlags = map[string][]string{
	opDecrypt: {flagExtract, flagOutputType},
	opSet:     {},
	opUnset:   {},
	opEncrypt: {flagGCPKMS, flagEncryptedRegex, flagUnencryptedRegex, flagEncryptedSuffix, flagUnencryptedSuffix},
}

// How many positional arguments each operation takes.
var opArgs = map[string]int{opDecrypt: 0, opSet: 2, opUnset: 1, opEncrypt: 0}

var fileTypes = map[string]formats.Format{"yaml": formats.Yaml, "json": formats.Json, "dotenv": formats.Dotenv}

// Request is a parsed, checked SOPS request (docs/10 D2, D3). It is
// immutable once Parse returns it.
type Request struct {
	op          string
	flags       map[string]string
	positionals []string
	argv        []string // canonical: op, sorted --name=value, positionals
	stdin       []byte

	path  []any // --extract, or the path of set and unset
	value any   // set's value, as SOPS inserts it

	facts fileFacts
}

// fileFacts is what the check of the file before the approval found
// (docs/10 D4), and what the message says of it (D8).
type fileFacts struct {
	keys         []string // the KMS keys the run may call, in the file's order
	asks         string
	says         []string
	saysNote     string
	lastModified time.Time
}

// invalid is a refusal of the request, with a fixed message.
func invalid(detail, format string, args ...any) error {
	return codes.WithDetail(codes.InvalidRequest, detail, format, args...)
}

// shown makes agent text safe to put in an error message: quoted, with
// invisible characters escaped, and cut.
func shown(s string) string {
	if r := []rune(s); len(r) > 60 {
		s = string(r[:60]) + "…"
	}
	return textsafe.Quote(s)
}

// Parse reads args as a SOPS command line without the leading "sops"
// (docs/10 D2), checks stdin, the file, without any key (D4), and
// returns the canonical request. keys are the target's Cloud KMS keys.
// Every refusal is a *codes.Error with codes.InvalidRequest and a
// Detail; none of them holds text from the SOPS library.
func Parse(args []string, stdin []byte, interactive bool, keys []string) (*Request, error) {
	if interactive {
		return nil, invalid(DetailInteractive, "a sops target has no interactive runs")
	}
	if len(args) == 0 {
		return nil, invalid(DetailNoCommand, "no command; one of decrypt, set, unset, encrypt")
	}
	op := args[0]
	allowed, ok := opFlags[op]
	if !ok {
		return nil, invalid(DetailUnknownCommand, "sops command %s is not offered; one of decrypt, set, unset, encrypt", shown(op))
	}
	r := &Request{op: op, flags: map[string]string{}, stdin: bytes.Clone(stdin)}
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if a == "--" {
			r.positionals = append(r.positionals, rest[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			r.positionals = append(r.positionals, a)
			continue
		}
		if !strings.HasPrefix(a, "--") {
			return nil, invalid(DetailUnknownFlag, "flag %s is not offered; a value that starts with - goes after --", shown(a))
		}
		name, value, hasValue := strings.Cut(a[2:], "=")
		if name != flagInputType && name != flagFilename && !slices.Contains(allowed, name) {
			return nil, invalid(DetailUnknownFlag, "flag %s is not offered for sops %s", shown("--"+name), op)
		}
		if !hasValue {
			if i+1 >= len(rest) {
				return nil, invalid(DetailFlagValue, "flag --%s needs a value", name)
			}
			i++
			value = rest[i]
		}
		if _, dup := r.flags[name]; dup {
			return nil, invalid(DetailDuplicateFlag, "flag --%s is given twice", name)
		}
		r.flags[name] = value
	}
	if len(r.positionals) != opArgs[op] {
		return nil, invalid(DetailArguments, "sops %s takes %d arguments besides its flags, not %d", op, opArgs[op], len(r.positionals))
	}
	if err := r.checkFlags(keys); err != nil {
		return nil, err
	}
	if err := r.checkPositionals(); err != nil {
		return nil, err
	}
	r.argv = r.render()
	if len(r.stdin) == 0 {
		return nil, invalid(DetailNoFile, "stdin is the file, and it is empty")
	}
	var facts fileFacts
	err := guarded(func() error {
		var err error
		facts, err = r.checkFile(keys)
		return err
	})
	if err != nil {
		if _, ok := err.(*codes.Error); !ok {
			// A panic, or an error of the library's: its text is not passed on.
			err = invalid(DetailFileNotParsed, "the file could not be read as %s", r.flags[flagInputType])
		}
		return nil, err
	}
	r.facts = facts
	return r, nil
}

// guarded runs f, turning a panic of the SOPS library into an error, so
// that no file can take the process down.
func guarded(f func() error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("sopstarget: the SOPS library panicked")
		}
	}()
	return f()
}

func (r *Request) checkFlags(keys []string) error {
	for _, name := range []string{flagInputType, flagFilename} {
		if _, ok := r.flags[name]; !ok {
			return invalid(DetailMissingFlag, "flag --%s is required", name)
		}
	}
	if _, ok := fileTypes[r.flags[flagInputType]]; !ok {
		return invalid(DetailFlagValue, "--input-type must be yaml, json or dotenv")
	}
	if v, ok := r.flags[flagOutputType]; ok {
		if _, known := fileTypes[v]; !known {
			return invalid(DetailFlagValue, "--output-type must be yaml, json or dotenv")
		}
	}
	name := r.flags[flagFilename]
	if n := utf8.RuneCountInString(name); !utf8.ValidString(name) || n == 0 || n > MaxFileName {
		return invalid(DetailFlagValue, "--filename-override must be 1 to %d characters", MaxFileName)
	}
	for _, c := range name {
		if textsafe.Invisible(c) {
			return invalid(DetailFlagValue, "--filename-override may hold printable characters only")
		}
	}
	if v, ok := r.flags[flagExtract]; ok {
		p, err := parsePath(v)
		if err != nil {
			return err
		}
		r.path = p
	}
	if r.op != opEncrypt {
		return nil
	}
	key, ok := r.flags[flagGCPKMS]
	if !ok {
		return invalid(DetailMissingFlag, "flag --gcp-kms is required for sops encrypt")
	}
	// One key, by its full name, from the target's list (docs/10 D4):
	// SOPS's comma-separated list isn't a resource name.
	if !config.IsKMSKeyName(key) {
		return invalid(DetailFlagValue, "--gcp-kms must be one full CryptoKey resource name")
	}
	if !slices.Contains(keys, key) {
		return invalid(DetailKeyNotAllowed, "--gcp-kms names a key this target doesn't use")
	}
	rules := 0
	for _, name := range []string{flagEncryptedRegex, flagUnencryptedRegex, flagEncryptedSuffix, flagUnencryptedSuffix} {
		v, ok := r.flags[name]
		if !ok {
			continue
		}
		rules++
		if v == "" || len(v) > maxRule {
			return invalid(DetailFlagValue, "--%s must be 1 to %d bytes", name, maxRule)
		}
		if strings.HasSuffix(name, "regex") {
			if _, err := regexp.Compile(v); err != nil {
				return invalid(DetailFlagValue, "--%s is not a regular expression", name)
			}
		}
	}
	if rules > 1 {
		return invalid(DetailArguments, "at most one of --encrypted-regex, --unencrypted-regex, --encrypted-suffix and --unencrypted-suffix")
	}
	return nil
}

func (r *Request) checkPositionals() error {
	if r.op != opSet && r.op != opUnset {
		return nil
	}
	p, err := parsePath(r.positionals[0])
	if err != nil {
		return err
	}
	r.path = p
	if r.op == opSet {
		v, err := insertable(r.positionals[1])
		if err != nil {
			return err
		}
		r.value = v
	}
	return nil
}

// render is the canonical argv (docs/10 D3): the command, the set flags
// as --name=value sorted by name, then the positional arguments, after
// "--" when one of them starts with "-".
func (r *Request) render() []string {
	names := make([]string, 0, len(r.flags))
	for n := range r.flags {
		names = append(names, n)
	}
	sort.Strings(names)
	out := []string{r.op}
	for _, n := range names {
		out = append(out, "--"+n+"="+r.flags[n])
	}
	for _, p := range r.positionals {
		if strings.HasPrefix(p, "-") {
			out = append(out, "--")
			break
		}
	}
	return append(out, r.positionals...)
}

// parsePath reads SOPS's tree path, `["a"][0]['b']` (docs/10 D2). It is
// stricter than SOPS's own reader, which can't express a key holding
// "[" either: a key may hold neither bracket nor its own quote, so a
// path reads one way only.
func parsePath(s string) ([]any, error) {
	bad := func() ([]any, error) {
		return nil, invalid(DetailPath, `a path is written as ["key"][0]["key"], and a key may not hold [, ] or its quote`)
	}
	var out []any
	for rest := s; rest != ""; {
		if rest[0] != '[' {
			return bad()
		}
		end := strings.IndexByte(rest, ']')
		if end < 2 {
			return bad()
		}
		comp := rest[1:end]
		rest = rest[end+1:]
		if q := comp[0]; q == '"' || q == '\'' {
			if len(comp) < 2 || comp[len(comp)-1] != q {
				return bad()
			}
			key := comp[1 : len(comp)-1]
			if strings.ContainsAny(key, "[]") || strings.IndexByte(key, q) >= 0 || !utf8.ValidString(key) {
				return bad()
			}
			out = append(out, key)
			continue
		}
		n, err := strconv.Atoi(comp)
		if err != nil || n < 0 || strconv.Itoa(n) != comp {
			return bad()
		}
		out = append(out, n)
	}
	if len(out) == 0 || len(out) > maxDepth {
		return bad()
	}
	return out, nil
}

// showPath renders a path in SOPS's form with every key JSON-quoted, and
// invisible characters escaped (docs/10 D8): a key can't end its own
// string, so a path reads one way only.
func showPath(p []any) string {
	var b strings.Builder
	for _, c := range p {
		b.WriteByte('[')
		if n, ok := c.(int); ok {
			b.WriteString(strconv.Itoa(n))
		} else {
			b.WriteString(jsonText(c))
		}
		b.WriteByte(']')
	}
	return b.String()
}

// jsonText is v as JSON, without HTML escaping, with invisible
// characters and long runs of combining marks shown as \u{…}.
func jsonText(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return `"‹not shown›"`
	}
	var b strings.Builder
	run := 0
	for _, c := range strings.TrimSuffix(buf.String(), "\n") {
		if textsafe.IsCombining(c) {
			run++
		} else {
			run = 0
		}
		if textsafe.Invisible(c) || run > textsafe.MaxCombiningRun || c == utf8.RuneError {
			fmt.Fprintf(&b, `\u{%x}`, c)
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

// insertable reads set's VALUE as SOPS does (jsonValueToTreeInsertableValue
// in cmd/sops, which can't be imported: docs/10 M1): JSON, and an object
// or array becomes a tree branch through SOPS's JSON store.
func insertable(s string) (any, error) {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil, invalid(DetailFlagValue, "the value of sops set must be JSON, for example '\"text\"'")
	}
	if k := reflect.ValueOf(v).Kind(); k != reflect.Map && k != reflect.Slice {
		return v, nil
	}
	var out any
	err := guarded(func() error {
		branches, err := (&sopsjson.Store{}).LoadPlainFile([]byte(s))
		if err != nil {
			return err
		}
		if len(branches) == 0 {
			return fmt.Errorf("no branch")
		}
		out = branches[0]
		return nil
	})
	if err != nil {
		return nil, invalid(DetailFlagValue, "the value of sops set must be a JSON scalar or object")
	}
	return out, nil
}

// store is SOPS's store for a file type, as its command line makes it.
func store(typ string) common.Store {
	return common.StoreForFormat(fileTypes[typ], sopsconfig.NewStoresConfig())
}

const encPrefix = "ENC[AES256_GCM,data:"

// leaf is one value of a file, with its path.
type leaf struct {
	path      []any
	value     any
	encrypted bool
}

// leaves lists every value under v that isn't a comment, depth first,
// in the file's order. A slice index counts comments, as SOPS's own
// paths do.
func leaves(v any, path []any, depth int, out *[]leaf) error {
	if depth > maxDepth {
		return invalid(DetailTooDeep, "the file is nested more than %d levels deep", maxDepth)
	}
	switch v := v.(type) {
	case sops.TreeBranch:
		for _, it := range v {
			if _, comment := it.Key.(sops.Comment); comment {
				continue
			}
			key, ok := it.Key.(string)
			if !ok {
				key = fmt.Sprint(it.Key)
			}
			if err := leaves(it.Value, append(slices.Clone(path), key), depth+1, out); err != nil {
				return err
			}
		}
	case []any:
		for i, e := range v {
			if err := leaves(e, append(slices.Clone(path), i), depth+1, out); err != nil {
				return err
			}
		}
	case sops.Comment:
	default:
		s, isString := v.(string)
		*out = append(*out, leaf{path: path, value: v, encrypted: isString && strings.HasPrefix(s, encPrefix)})
	}
	return nil
}

// lookup returns what is at path in branch, without the type assertions
// of SOPS's Truncate, which panic on a path through a scalar.
func lookup(branch sops.TreeBranch, path []any) (any, bool) {
	var cur any = branch
	for _, c := range path {
		switch c := c.(type) {
		case string:
			b, ok := cur.(sops.TreeBranch)
			if !ok {
				return nil, false
			}
			found := false
			for _, it := range b {
				if it.Key == c {
					cur, found = it.Value, true
					break
				}
			}
			if !found {
				return nil, false
			}
		case int:
			s, ok := cur.([]any)
			if !ok || c >= len(s) {
				return nil, false
			}
			cur = s[c]
		}
	}
	if _, comment := cur.(sops.Comment); comment {
		return nil, false
	}
	return cur, true
}

func isBranch(v any) bool {
	switch v.(type) {
	case sops.TreeBranch, []any:
		return true
	}
	return false
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// checkFile is the check of the file before any approval (docs/10 D4),
// and builds what the message says of it (D8). It uses no key and makes
// no call.
func (r *Request) checkFile(keys []string) (fileFacts, error) {
	st := store(r.flags[flagInputType])
	if r.op == opEncrypt {
		return r.checkPlainFile(st)
	}
	tree, err := st.LoadEncryptedFile(r.stdin)
	if err != nil {
		if err == sops.MetadataNotFound {
			return fileFacts{}, invalid(DetailNotEncrypted, "the file has no sops metadata: it is not a SOPS file")
		}
		return fileFacts{}, invalid(DetailFileNotParsed, "the file could not be read as %s", r.flags[flagInputType])
	}
	if len(tree.Branches) != 1 {
		return fileFacts{}, invalid(DetailDocuments, "the file must hold exactly one document")
	}
	if len(tree.Metadata.KeyGroups) != 1 {
		return fileFacts{}, invalid(DetailKeyGroups, "the file must have exactly one key group")
	}
	var f fileFacts
	for _, k := range tree.Metadata.KeyGroups[0] {
		g, ok := k.(*gcpkms.MasterKey)
		if !ok {
			return fileFacts{}, invalid(DetailKeyType, "the file names a key that isn't a Google Cloud KMS key; a sops target takes files with Google Cloud KMS keys only")
		}
		if !slices.Contains(keys, g.ResourceID) {
			return fileFacts{}, invalid(DetailKeyNotAllowed, "the file names a Cloud KMS key this target doesn't use")
		}
		if slices.Contains(f.keys, g.ResourceID) {
			return fileFacts{}, invalid(DetailDuplicateKey, "the file names a Cloud KMS key twice")
		}
		f.keys = append(f.keys, g.ResourceID)
	}
	if len(f.keys) == 0 {
		return fileFacts{}, invalid(DetailKeyType, "the file names no Google Cloud KMS key")
	}
	// The file's own rules are within what an encrypt may ask for: SOPS
	// compiles a regular expression again for every value it walks, so
	// a long one in a large file would hold a run for minutes.
	m := tree.Metadata
	for _, rule := range []struct {
		value string
		regex bool
	}{{m.EncryptedRegex, true}, {m.UnencryptedRegex, true}, {m.EncryptedCommentRegex, true}, {m.UnencryptedCommentRegex, true},
		{m.EncryptedSuffix, false}, {m.UnencryptedSuffix, false}} {
		if len(rule.value) > maxRule {
			return fileFacts{}, invalid(DetailFileRules, "one of the file's encryption rules is longer than %d bytes", maxRule)
		}
		if rule.regex && rule.value != "" {
			if _, err := regexp.Compile(rule.value); err != nil {
				return fileFacts{}, invalid(DetailFileRules, "one of the file's encryption rules is not a regular expression")
			}
		}
	}
	f.lastModified = tree.Metadata.LastModified

	var all []leaf
	if err := leaves(tree.Branches[0], nil, 0, &all); err != nil {
		return fileFacts{}, err
	}
	encrypted := 0
	var clear []leaf
	for _, l := range all {
		if l.encrypted {
			encrypted++
		} else {
			clear = append(clear, l)
		}
	}
	at, found := lookup(tree.Branches[0], r.path)
	under := 0 // values under the path, when it is a branch
	if found && isBranch(at) {
		var sub []leaf
		if err := leaves(at, nil, 0, &sub); err != nil {
			return fileFacts{}, err
		}
		under = len(sub)
	}
	path := showPath(r.path)
	switch r.op {
	case opDecrypt:
		switch {
		case r.path == nil:
			f.asks = "Decrypt and return the whole file (" + plural(encrypted, "encrypted value", "encrypted values") + ")"
		case !found:
			return fileFacts{}, invalid(DetailPathNotFound, "the file has nothing at the path of --extract")
		case isBranch(at):
			f.asks = "Decrypt and return everything under: " + path + " (" + plural(under, "value", "values") + ")"
		default:
			f.asks = "Decrypt and return one value: " + path
		}
	case opSet:
		// A path that runs through a value replaces that value with a
		// branch (SOPS's Set): the message names what is lost.
		through := -1
		for n := 1; n < len(r.path); n++ {
			if v, ok := lookup(tree.Branches[0], r.path[:n]); ok && !isBranch(v) {
				through = n
				break
			}
		}
		switch {
		case through > 0:
			f.asks = "Replace the value at " + showPath(r.path[:through]) + " with a branch, to add: " + path + " (new value not shown)"
		case !found:
			f.asks = "Add a value: " + path + " (new value not shown)"
		case isBranch(at):
			f.asks = "Replace everything under: " + path + " (" + plural(under, "value", "values") + "; new value not shown)"
		default:
			f.asks = "Change one value: " + path + " (new value not shown)"
		}
	case opUnset:
		switch {
		case !found:
			return fileFacts{}, invalid(DetailPathNotFound, "the file has nothing at the path to unset")
		case isBranch(at):
			f.asks = "Remove everything under: " + path + " (" + plural(under, "value", "values") + ")"
		default:
			f.asks = "Remove one value: " + path
		}
	}

	// "The file says" (docs/10 D8): the cleartext values, which the MAC
	// covers, unless the file says it doesn't.
	switch {
	case tree.Metadata.MACOnlyEncrypted:
		f.saysNote = "cleartext not verifiable, not shown"
	case len(clear) == 0:
		f.saysNote = "nothing in cleartext"
	default:
		total := 0
		for _, l := range clear {
			line := showPath(l.path) + " = " + jsonText(scalar(l.value))
			total += utf8.RuneCountInString(line)
			f.says = append(f.says, line)
		}
		if len(clear) > maxSaysValues || total > maxSaysChars {
			f.says = nil
			f.saysNote = plural(len(clear), "cleartext value", "cleartext values") + ", not shown"
		}
	}
	return f, nil
}

// scalar is a leaf as JSON can show it.
func scalar(v any) any {
	switch v := v.(type) {
	case nil, string, bool, int, int64, float64:
		return v
	case time.Time:
		return v.Format(time.RFC3339Nano)
	case []byte:
		return string(v)
	}
	return fmt.Sprint(v)
}

// countingCipher stands in for SOPS's cipher to learn which values a
// file's rules would encrypt, by SOPS's own rules: it encrypts nothing.
type countingCipher struct{ values int }

func (c *countingCipher) Encrypt(plaintext any, _ []byte, _ string) (string, error) {
	if _, comment := plaintext.(sops.Comment); !comment {
		c.values++
	}
	return "", nil
}

func (c *countingCipher) Decrypt(string, []byte, string) (any, error) {
	return nil, fmt.Errorf("sopstarget: the counting cipher decrypts nothing")
}

// checkPlainFile is checkFile for encrypt, whose stdin is plaintext: no
// value of it is shown (docs/10 D8).
func (r *Request) checkPlainFile(st common.Store) (fileFacts, error) {
	branches, err := st.LoadPlainFile(r.stdin)
	if err != nil {
		return fileFacts{}, invalid(DetailFileNotParsed, "the file could not be read as %s", r.flags[flagInputType])
	}
	if len(branches) != 1 {
		return fileFacts{}, invalid(DetailDocuments, "the file must hold exactly one document")
	}
	if st.HasSopsTopLevelKey(branches[0]) {
		return fileFacts{}, invalid(DetailAlreadyEncrypted, "the file already has sops metadata: it is encrypted already")
	}
	var all []leaf
	if err := leaves(branches[0], nil, 0, &all); err != nil {
		return fileFacts{}, err
	}
	// The count is SOPS's own: its Encrypt walks the tree with the
	// rules of the request and calls the cipher for each value it would
	// encrypt.
	tree := sops.Tree{Branches: branches, Metadata: r.metadata()}
	cc := &countingCipher{}
	if _, err := tree.Encrypt(make([]byte, 32), cc); err != nil {
		return fileFacts{}, invalid(DetailFileNotParsed, "the file could not be encrypted as %s", r.flags[flagInputType])
	}
	left := len(all) - cc.values
	if left < 0 {
		left = 0
	}
	return fileFacts{
		keys: []string{r.flags[flagGCPKMS]},
		asks: "Encrypt a new file: " + plural(cc.values, "value", "values") + " encrypted, " + strconv.Itoa(left) + " left in cleartext",
	}, nil
}

// metadata is the SOPS metadata of a file encrypt makes: one key group
// with the one key the request names, and its rule, if any.
func (r *Request) metadata() sops.Metadata {
	return sops.Metadata{
		KeyGroups:         []sops.KeyGroup{{gcpkms.NewMasterKeyFromResourceID(r.flags[flagGCPKMS])}},
		EncryptedRegex:    r.flags[flagEncryptedRegex],
		UnencryptedRegex:  r.flags[flagUnencryptedRegex],
		EncryptedSuffix:   r.flags[flagEncryptedSuffix],
		UnencryptedSuffix: r.flags[flagUnencryptedSuffix],
		Version:           sopsversion.Version,
	}
}

// Type is the target type SOPS requests are for.
func (r *Request) Type() string { return codes.TypeSOPS }

// Interactive is always false: a sops target has no interactive runs
// (docs/10 D1).
func (r *Request) Interactive() bool { return false }

// Argv returns the canonical argv.
func (r *Request) Argv() []string { return slices.Clone(r.argv) }

// Stdin returns the file, as sent.
func (r *Request) Stdin() []byte { return bytes.Clone(r.stdin) }

// Keys are the Cloud KMS keys the run may call: the ones the file
// names, in its order, or the one an encrypt names.
func (r *Request) Keys() []string { return slices.Clone(r.facts.keys) }

const digestPrefix = "nyyrikki-sops-request-v1\x00"

// Digest is what an approval binds to (docs/10 D3): docs/04 §5.3's
// encoding with its own prefix, over the target, the canonical argv and
// stdin. Who it runs as is no part of it: that is the target's
// credential, which the target names.
func (r *Request) Digest(target, _ string) [32]byte {
	h := sha256.New()
	h.Write([]byte(digestPrefix))
	h.Write([]byte(target))
	h.Write([]byte{0})
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(r.argv)))
	h.Write(n[:])
	for _, a := range r.argv {
		binary.BigEndian.PutUint64(n[:], uint64(len(a)))
		h.Write(n[:])
		h.Write([]byte(a))
	}
	h.Write([]byte{0})
	h.Write(r.stdin)
	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}

// redactedArgv is the canonical argv with set's value replaced by its
// size and hash (docs/10 D8, docs/04 D14): it is the last element.
func (r *Request) redactedArgv() []string {
	out := slices.Clone(r.argv)
	if r.op == opSet {
		v := []byte(out[len(out)-1])
		sum := sha256.Sum256(v)
		out[len(out)-1] = fmt.Sprintf("‹redacted: %d bytes, sha256:%s›", len(v), hex.EncodeToString(sum[:])[:12])
	}
	return out
}

// Audit is the audited form (docs/10 D10): the canonical argv with
// set's value redacted, and stdin's size and hash.
func (r *Request) Audit() audit.Request {
	sum := sha256.Sum256(r.stdin)
	return audit.Request{Argv: r.redactedArgv(), StdinBytes: len(r.stdin), StdinSHA256: hex.EncodeToString(sum[:])}
}

// DisplayCommand is what the approver sees of the command line: "sops "
// and the redacted canonical argv, each element shell-quoted when
// needed (docs/04 §5.2). It is not HTML-escaped.
func (r *Request) DisplayCommand() string {
	var b strings.Builder
	b.WriteString("sops")
	for _, a := range r.redactedArgv() {
		b.WriteByte(' ')
		b.WriteString(textsafe.Quote(a))
	}
	return b.String()
}

// DisplayStdin is the file as the approver sees it: its kind, size and
// hash, and for an encrypted file when it was last modified; never its
// contents (docs/10 D8).
func (r *Request) DisplayStdin() string {
	sum := sha256.Sum256(r.stdin)
	kind := "sops " + r.flags[flagInputType]
	when := ", last modified " + r.facts.lastModified.UTC().Format(time.RFC3339)
	if r.op == opEncrypt {
		kind, when = "plaintext "+r.flags[flagInputType], ""
	}
	return fmt.Sprintf("‹%s, %d bytes, sha256:%s%s›", kind, len(r.stdin), hex.EncodeToString(sum[:])[:12], when)
}

// Prompt is what the approver is shown of the request besides the
// command (docs/10 D8).
func (r *Request) Prompt() *approval.SOPSRequest {
	return &approval.SOPSRequest{
		Asks:     r.facts.asks,
		FileName: r.flags[flagFilename],
		// encrypt has no "The file says" line at all.
		ShowSays: r.op != opEncrypt,
		Says:     slices.Clone(r.facts.says),
		SaysNote: r.facts.saysNote,
		KMSKeys:  slices.Clone(r.facts.keys),
	}
}
