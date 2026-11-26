package logs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// logReceiver reports whether x, the receiver of a Debug/Info/Warn/Error
// call, is a logger by this tree's names: a Log(), log() or logs.Or() call,
// or a variable or field named Logger, logger or lg.
func logReceiver(x ast.Expr) bool {
	switch v := x.(type) {
	case *ast.CallExpr:
		switch f := v.Fun.(type) {
		case *ast.SelectorExpr:
			return f.Sel.Name == "Log" || f.Sel.Name == "log" || f.Sel.Name == "Or"
		case *ast.Ident:
			return f.Name == "log"
		}
	case *ast.SelectorExpr:
		return v.Sel.Name == "Logger" || v.Sel.Name == "logger"
	case *ast.Ident:
		return v.Name == "Logger" || v.Name == "logger" || v.Name == "lg"
	}
	return false
}

// TestOneLogger walks cmd/ and internal/: no file imports the standard log
// package (everything goes through log/slog), internal/ reaches for no
// process-wide logger and keeps none in a package variable, writes to no
// standard stream, and every log line's message is a string constant (its
// values are attributes, which the handler can drop by key).
func TestOneLogger(t *testing.T) {
	for _, top := range []string{"../../cmd", "../../internal"} {
		internal := strings.HasSuffix(top, "internal")
		err := filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") {
				return nil
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			isTest := strings.HasSuffix(p, "_test.go")
			at := func(n ast.Node) string { return fset.Position(n.Pos()).String() }
			for _, im := range f.Imports {
				if path, _ := strconv.Unquote(im.Path.Value); path == "log" {
					t.Errorf("%s: imports log; use the server's log/slog logger", at(im))
				}
			}
			if internal {
				for _, decl := range f.Decls {
					g, ok := decl.(*ast.GenDecl)
					if !ok || g.Tok != token.VAR {
						continue
					}
					for _, spec := range g.Specs {
						vs := spec.(*ast.ValueSpec)
						held := false
						if st, ok := vs.Type.(*ast.StarExpr); ok {
							if sel, ok := st.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "Logger" {
								held = true
							}
						}
						for _, v := range vs.Values {
							if c, ok := v.(*ast.CallExpr); ok {
								if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
									if x, ok := sel.X.(*ast.Ident); ok && (x.Name == "slog" || x.Name == "logs") {
										held = true
									}
								}
							}
						}
						if held {
							t.Errorf("%s: a logger in a package variable", at(vs))
						}
					}
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.SelectorExpr:
					x, ok := v.X.(*ast.Ident)
					if !ok || !internal {
						return true
					}
					if x.Name == "slog" {
						switch v.Sel.Name {
						case "Default", "SetDefault", "Debug", "Info", "Warn", "Error", "Log", "LogAttrs",
							"DebugContext", "InfoContext", "WarnContext", "ErrorContext", "SetLogLoggerLevel":
							t.Errorf("%s: slog.%s is the process-wide logger; use the one handed down", at(v), v.Sel.Name)
						}
					}
					if x.Name == "os" && !isTest && (v.Sel.Name == "Stderr" || v.Sel.Name == "Stdout") {
						t.Errorf("%s: os.%s in internal/; write through the logger", at(v), v.Sel.Name)
					}
				case *ast.CallExpr:
					sel, ok := v.Fun.(*ast.SelectorExpr)
					if !ok || isTest || !logReceiver(sel.X) {
						return true
					}
					msg := -1
					switch sel.Sel.Name {
					case "Debug", "Info", "Warn", "Error":
						msg = 0
					case "DebugContext", "InfoContext", "WarnContext", "ErrorContext":
						msg = 1
					case "Log", "LogAttrs":
						msg = 2
					}
					if msg < 0 || msg >= len(v.Args) {
						return true
					}
					if lit, ok := v.Args[msg].(*ast.BasicLit); !ok || lit.Kind != token.STRING {
						t.Errorf("%s: the message of a log line is a string constant; values go in attributes", at(v))
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
