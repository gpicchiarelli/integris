package path

import (
	"context"
	"testing"
)

func TestResolveSuccess(t *testing.T) {
	root := newMemRoot(1, map[string]any{
		"a": map[string]any{
			"b": "file",
		},
	})
	ctx := context.Background()
	chain, err := Resolve(ctx, root, comps("a", "b"), ResolveOpts{
		Root:        RootIdentity{Volume: 1},
		ExpectFinal: TypeFile,
	}, DefaultProfile)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Close()
	if len(chain.Files) != 2 {
		t.Fatalf("len=%d", len(chain.Files))
	}
	info, err := chain.Files[1].Info()
	if err != nil || info.Type != TypeFile {
		t.Fatalf("final info=%v err=%v", info, err)
	}
}

func TestResolveRejectsSymlink(t *testing.T) {
	root := newMemRoot(1, map[string]any{
		"link": "symlink",
	})
	_, err := Resolve(context.Background(), root, comps("link"), ResolveOpts{
		Root: RootIdentity{Volume: 1},
	}, DefaultProfile)
	if ruleOf(err) != RuleLink {
		t.Fatalf("got %v", err)
	}
}

func TestResolveRejectsVolumeChange(t *testing.T) {
	root := newMemRoot(1, map[string]any{
		"x": FileInfo{Type: TypeFile, ID: 9, Volume: 2, LinkCount: 1},
	})
	_, err := Resolve(context.Background(), root, comps("x"), ResolveOpts{
		Root: RootIdentity{Volume: 1},
	}, DefaultProfile)
	if ruleOf(err) != RuleVolume {
		t.Fatalf("got %v", err)
	}
}

func TestResolveRejectsHardLink(t *testing.T) {
	root := newMemRoot(1, map[string]any{
		"x": FileInfo{Type: TypeFile, ID: 9, Volume: 1, LinkCount: 2},
	})
	_, err := Resolve(context.Background(), root, comps("x"), ResolveOpts{
		Root: RootIdentity{Volume: 1},
	}, DefaultProfile)
	if ruleOf(err) != RulePolicy {
		t.Fatalf("got %v", err)
	}
}

func TestResolveGrammarBeforeOpen(t *testing.T) {
	root := newMemRoot(1, map[string]any{"..": "file"})
	_, err := Resolve(context.Background(), root, comps(".."), ResolveOpts{
		Root: RootIdentity{Volume: 1},
	}, DefaultProfile)
	if ruleOf(err) != RuleDotDot {
		t.Fatalf("got %v", err)
	}
}

func TestResolveClosesPartialOnFailure(t *testing.T) {
	root := newMemRoot(1, map[string]any{
		"a": map[string]any{
			"missing-child-not-present": nil,
		},
	})
	// Open a then fail on b.
	_, err := Resolve(context.Background(), root, comps("a", "b"), ResolveOpts{
		Root: RootIdentity{Volume: 1},
	}, DefaultProfile)
	if ruleOf(err) != RuleOpen {
		t.Fatalf("got %v", err)
	}
}

func TestResolveContextCancel(t *testing.T) {
	root := newMemRoot(1, map[string]any{"a": "file"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Resolve(ctx, root, comps("a"), ResolveOpts{
		Root: RootIdentity{Volume: 1},
	}, DefaultProfile)
	if ruleOf(err) != RuleOpen {
		t.Fatalf("got %v", err)
	}
}
