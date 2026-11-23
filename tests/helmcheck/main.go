// A stand-in for `helm template`, for places where Helm is not installed.
// It renders the chart with Go's text/template (the engine Helm uses) and the
// handful of Sprig/Helm functions the chart needs. It does not replace
// `helm lint` against a cluster; it proves the templates parse and render.
//
// usage: go run main.go CHART_DIR VALUES_JSON [RELEASE_NAME]
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
)

func toYaml(v any) string {
	var b strings.Builder
	emit(&b, v, 0, false)
	return strings.TrimRight(b.String(), "\n")
}

func scalar(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		q, _ := json.Marshal(x)
		return string(q)
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%v", x)
	default:
		return fmt.Sprintf("%v", x)
	}
}

func emit(b *strings.Builder, v any, depth int, inList bool) {
	pad := strings.Repeat("  ", depth)
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			p := pad
			if inList && i == 0 {
				p = ""
			}
			switch c := x[k].(type) {
			case map[string]any:
				if len(c) == 0 {
					fmt.Fprintf(b, "%s%s: {}\n", p, k)
				} else {
					fmt.Fprintf(b, "%s%s:\n", p, k)
					emit(b, c, depth+1, false)
				}
			case []any:
				if len(c) == 0 {
					fmt.Fprintf(b, "%s%s: []\n", p, k)
				} else {
					fmt.Fprintf(b, "%s%s:\n", p, k)
					emit(b, c, depth, false)
				}
			default:
				fmt.Fprintf(b, "%s%s: %s\n", p, k, scalar(c))
			}
		}
	case []any:
		for _, item := range x {
			switch c := item.(type) {
			case map[string]any:
				fmt.Fprintf(b, "%s- ", pad)
				emit(b, c, depth+1, true)
			default:
				fmt.Fprintf(b, "%s- %s\n", pad, scalar(c))
			}
		}
	default:
		fmt.Fprintf(b, "%s%s\n", pad, scalar(x))
	}
}

func empty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case bool:
		return !x
	case float64:
		return x == 0
	case int:
		return x == 0
	case map[string]any:
		return len(x) == 0
	case []any:
		return len(x) == 0
	}
	return false
}

func toInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	}
	return 0
}

func main() {
	chart, valuesPath := os.Args[1], os.Args[2]
	release := "demo"
	if len(os.Args) > 3 {
		release = os.Args[3]
	}
	raw, err := os.ReadFile(valuesPath)
	if err != nil {
		panic(err)
	}
	var values map[string]any
	if err := json.Unmarshal(raw, &values); err != nil {
		panic(err)
	}
	var chartMeta map[string]any
	metaRaw, _ := os.ReadFile(filepath.Join(filepath.Dir(valuesPath), "chart.json"))
	_ = json.Unmarshal(metaRaw, &chartMeta)

	t := template.New("root")
	funcs := template.FuncMap{
		"default": func(d, v any) any {
			if empty(v) {
				return d
			}
			return v
		},
		"trunc":      func(n int, s string) string { if len(s) > n { return s[:n] }; return s },
		"trimSuffix": func(suffix, s string) string { return strings.TrimSuffix(s, suffix) },
		"contains":   func(sub, s string) bool { return strings.Contains(s, sub) },
		"quote":      func(v any) string { q, _ := json.Marshal(fmt.Sprintf("%v", fmtVal(v))); return string(q) },
		"nindent": func(n int, s string) string {
			pad := strings.Repeat(" ", n)
			return "\n" + pad + strings.ReplaceAll(s, "\n", "\n"+pad)
		},
		"toYaml":       toYaml,
		"lookup":       func(a, b, c, d string) map[string]any { return map[string]any{} },
		"b64enc":       func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) },
		"randAlphaNum": func(n int) string { return strings.Repeat("x", n) },
		"sha256sum":    func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) },
		"ternary":      func(a, b any, cond bool) any { if cond { return a }; return b },
		"required": func(msg string, v any) (any, error) {
			if empty(v) {
				return nil, fmt.Errorf("%s", msg)
			}
			return v, nil
		},
		"add": func(a, b any) int { return toInt(a) + toInt(b) },
		"int": toInt,
	}
	funcs["include"] = func(name string, data any) (string, error) {
		var buf bytes.Buffer
		err := t.ExecuteTemplate(&buf, name, data)
		return buf.String(), err
	}
	t.Funcs(funcs)
	files, _ := filepath.Glob(filepath.Join(chart, "templates", "*"))
	sort.Strings(files)
	for _, f := range files {
		src, _ := os.ReadFile(f)
		if _, err := t.New(filepath.Base(f)).Parse(string(src)); err != nil {
			fmt.Fprintln(os.Stderr, "PARSE ERROR", err)
			os.Exit(1)
		}
	}
	ctx := map[string]any{
		"Values":  values,
		"Release": map[string]any{"Name": release, "Namespace": "mail", "Service": "Helm"},
		"Chart":   map[string]any{"Name": chartMeta["name"], "Version": chartMeta["version"], "AppVersion": chartMeta["appVersion"]},
	}
	for _, f := range files {
		name := filepath.Base(f)
		if strings.HasPrefix(name, "_") {
			continue
		}
		var buf bytes.Buffer
		if err := t.ExecuteTemplate(&buf, name, ctx); err != nil {
			fmt.Fprintln(os.Stderr, "RENDER ERROR", name, err)
			os.Exit(1)
		}
		if strings.TrimSpace(buf.String()) == "" {
			continue
		}
		if name == "NOTES.txt" {
			fmt.Fprintf(os.Stderr, "--- NOTES ---\n%s\n", strings.TrimSpace(buf.String()))
			continue
		}
		fmt.Printf("---\n# Source: templates/%s\n%s\n", name, strings.TrimSpace(buf.String()))
	}
}

func fmtVal(v any) any {
	if f, ok := v.(float64); ok && f == float64(int64(f)) {
		return int64(f)
	}
	return v
}
