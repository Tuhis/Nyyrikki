package decision_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestOnlyDecisionMakesGrants checks docs/02 G7: outside the decision
// package tree, no production file imports the packages that can make a
// Grant. decisiontest is for _test.go files only.
func TestOnlyDecisionMakesGrants(t *testing.T) {
	root := filepath.Join("..", "..")
	forbidden := map[string]bool{
		"github.com/Tuhis/Nyyrikki/internal/decision/decisiontest":   true,
		"github.com/Tuhis/Nyyrikki/internal/decision/internal/grant": true,
	}
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata" || d.Name() == "canaries") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		slash := filepath.ToSlash(path)
		if strings.Contains(slash, "internal/decision/") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		checked++
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if forbidden[p] {
				t.Errorf("%s imports %s: only the decision point makes grants", path, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 10 {
		t.Fatalf("scanned only %d files; the walk is broken", checked)
	}
}
