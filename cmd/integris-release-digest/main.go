package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type manifest struct {
	Kind       string            `json:"kind"`
	ProducedAt string            `json:"produced_at"`
	Revision   string            `json:"source_revision"`
	GoVersion  string            `json:"go_version"`
	Platform   string            `json:"platform"`
	Files      []fileDigest      `json:"files"`
	Modules    []moduleEntry     `json:"modules"`
	ModuleDig  string            `json:"modules_digest_sha256"`
	Residual   []string          `json:"residual_gaps"`
	Extra      map[string]string `json:"extra,omitempty"`
}

type fileDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type moduleEntry struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

func main() {
	root := flag.String("root", ".", "repository root")
	out := flag.String("out", "evidence/releases/EVD-RELEASE-001-engineering-manifest.json", "output path")
	flag.Parse()
	if err := run(*root, *out); err != nil {
		fmt.Fprintf(os.Stderr, "integris-release-digest: %v\n", err)
		os.Exit(1)
	}
}

func run(root, out string) error {
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	rev, _ := git(abs, "rev-parse", "HEAD")
	paths := []string{
		"go.mod", "go.sum", "Makefile", "README.md", "ROADMAP.md",
		"assurance/requirements.json", "assurance/evidence.json",
	}
	var files []fileDigest
	for _, p := range paths {
		fd, err := hashFile(filepath.Join(abs, p), p)
		if err != nil {
			if os.IsNotExist(err) && p == "go.sum" {
				continue
			}
			return err
		}
		files = append(files, fd)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	mods, err := listModules(abs)
	if err != nil {
		return err
	}
	modDig, err := modulesDigest(mods)
	if err != nil {
		return err
	}

	m := manifest{
		Kind:       "engineering-input-digest-manifest",
		ProducedAt: time.Now().UTC().Format(time.RFC3339),
		Revision:   rev,
		GoVersion:  runtime.Version(),
		Platform:   runtime.GOOS + "/" + runtime.GOARCH,
		Files:      files,
		Modules:    mods,
		ModuleDig:  modDig,
		Residual: []string{
			"not an independent two-party rebuild",
			"modules inventory is engineering-only (not SPDX/CycloneDX/SLSA)",
			"no release signatures in this artifact",
			"VER-RELEASE-001 remains planned",
		},
		Extra: map[string]string{"producer": "integris-release-digest"},
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := os.MkdirAll(filepath.Dir(filepath.Join(abs, out)), 0o755); err != nil {
		return err
	}
	outPath := filepath.Join(abs, out)
	if err := os.WriteFile(outPath, raw, 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	_ = os.WriteFile(outPath+".sha256", []byte(hex.EncodeToString(sum[:])+"  "+filepath.Base(out)+"\n"), 0o644)
	fmt.Printf("wrote %s (%d modules)\n", out, len(mods))
	return nil
}

func listModules(dir string) ([]moduleEntry, error) {
	cmd := exec.Command("go", "list", "-m", "-json", "all")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list -m: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	var mods []moduleEntry
	for {
		var m struct {
			Path    string
			Version string
			Main    bool
		}
		if err := dec.Decode(&m); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		ver := m.Version
		if m.Main || ver == "" {
			ver = "main"
		}
		mods = append(mods, moduleEntry{Path: m.Path, Version: ver})
	}
	sort.Slice(mods, func(i, j int) bool {
		if mods[i].Path != mods[j].Path {
			return mods[i].Path < mods[j].Path
		}
		return mods[i].Version < mods[j].Version
	})
	return mods, nil
}

func modulesDigest(mods []moduleEntry) (string, error) {
	h := sha256.New()
	for _, m := range mods {
		_, _ = fmt.Fprintf(h, "%s@%s\n", m.Path, m.Version)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashFile(abs, rel string) (fileDigest, error) {
	f, err := os.Open(abs)
	if err != nil {
		return fileDigest{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return fileDigest{}, err
	}
	return fileDigest{Path: rel, SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: n}, nil
}

func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(bytesTrim(out)), nil
}

func bytesTrim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
