package localsync_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/gpicchiarelli/integris/internal/localsync"
	"github.com/gpicchiarelli/integris/internal/path"
)

func FuzzValidateJoinedNoEscape(f *testing.F) {
	f.Add("a/b")
	f.Add("café")
	f.Add("..")
	f.Add("../x")
	f.Add("/abs")
	f.Add("a/./b")
	f.Fuzz(func(t *testing.T, s string) {
		comps, err := path.ValidateJoined(s, path.DefaultProfile)
		if err != nil {
			return
		}
		for _, c := range comps {
			if string(c) == ".." || string(c) == "." {
				t.Fatalf("accepted dangerous component %q in %q", c, s)
			}
			if strings.Contains(string(c), "/") || strings.Contains(string(c), "\\") {
				t.Fatalf("separator in component")
			}
		}
		joined := strings.Join(func() []string {
			out := make([]string, len(comps))
			for i := range comps {
				out[i] = string(comps[i])
			}
			return out
		}(), "/")
		roots := localsync.Roots{Source: t.TempDir(), Destination: t.TempDir()}
		plan := localsync.Plan{Ops: []localsync.Op{{
			Action:            localsync.ActionSkip,
			Rel:               joined,
			Reason:            localsync.ReasonIdentical,
			ExpectedDigestHex: "",
		}}}
		// Skip apply path validation via Apply on skip — still validates rel.
		_, err = localsync.Apply(roots, plan, nil)
		if err != nil && !localsync.IsKind(err, localsync.KindPathUnsafe) {
			// skip may succeed for valid names
			if joined == "" {
				t.Fatal(err)
			}
		}
	})
}

func FuzzPlanDeterminism(f *testing.F) {
	f.Add("a.txt", "hello")
	f.Add("b/c.txt", "")
	f.Fuzz(func(t *testing.T, name, body string) {
		if name == "" || strings.Contains(name, string(filepath.Separator)) {
			return
		}
		if _, err := path.ValidateJoined(filepath.ToSlash(name), path.DefaultProfile); err != nil {
			return
		}
		src := t.TempDir()
		dst := t.TempDir()
		pathName := filepath.Join(src, filepath.FromSlash(name))
		if err := osMkdirAll(filepath.Dir(pathName)); err != nil {
			return
		}
		if err := osWriteFile(pathName, []byte(body)); err != nil {
			return
		}
		m1, err := localsync.Scan(src)
		if err != nil {
			return
		}
		p1, err := localsync.BuildPlan(m1, localsync.Manifest{Root: dst})
		if err != nil {
			return
		}
		p2, err := localsync.BuildPlan(m1, localsync.Manifest{Root: dst})
		if err != nil {
			return
		}
		j1, _ := p1.FormatJSON()
		j2, _ := p2.FormatJSON()
		if string(j1) != string(j2) {
			t.Fatalf("nondeterministic")
		}
		raw, err := p1.FormatJSON()
		if err != nil {
			t.Fatal(err)
		}
		back, err := localsync.ParsePlanJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		j3, _ := back.FormatJSON()
		if string(raw) != string(j3) {
			t.Fatalf("roundtrip")
		}
	})
}

func osMkdirAll(p string) error {
	return mkdirAll(p)
}

func osWriteFile(p string, b []byte) error {
	return writeFile(p, b)
}
