package path

import (
	"bytes"
	"context"
	"sync"
)

// memNode is an in-memory filesystem node for deterministic Resolve tests.
type memNode struct {
	name     string
	info     FileInfo
	children map[string]*memNode // directories only
	closed   bool
	mu       sync.Mutex
}

func (n *memNode) Info() (FileInfo, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return FileInfo{}, reject(RuleOpen, -1, "descriptor closed")
	}
	return n.info, nil
}

func (n *memNode) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.closed = true
	return nil
}

func (n *memNode) OpenNoFollow(ctx context.Context, name []byte) (File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, reject(RuleOpen, -1, "descriptor closed")
	}
	if n.info.Type != TypeDir {
		return nil, reject(RuleType, -1, "not a directory")
	}
	child, ok := n.children[string(name)]
	if !ok {
		return nil, reject(RuleOpen, -1, "not found")
	}
	// Return a live view sharing metadata but with its own close flag.
	out := &memNode{
		name:     child.name,
		info:     child.info,
		children: child.children,
	}
	return out, nil
}

// newMemRoot builds a directory tree from a nested map.
// values: nil → empty dir; map → dir; FileInfo → leaf with that info; string "file"|"symlink"|"other".
func newMemRoot(vol VolumeID, tree map[string]any) *memNode {
	return buildMem(".", TypeDir, vol, 1, tree)
}

func buildMem(name string, typ ObjectType, vol VolumeID, id Identity, tree map[string]any) *memNode {
	n := &memNode{
		name: name,
		info: FileInfo{Type: typ, ID: id, Volume: vol, LinkCount: 1},
	}
	if typ == TypeDir {
		n.children = make(map[string]*memNode)
		var next Identity = id + 1
		for k, v := range tree {
			switch child := v.(type) {
			case map[string]any:
				n.children[k] = buildMem(k, TypeDir, vol, next, child)
				next += Identity(countNodes(child) + 1)
			case FileInfo:
				c := &memNode{name: k, info: child}
				if c.info.ID == 0 {
					c.info.ID = next
					next++
				}
				if c.info.Volume == 0 {
					c.info.Volume = vol
				}
				if c.info.LinkCount == 0 {
					c.info.LinkCount = 1
				}
				n.children[k] = c
			case string:
				t := TypeFile
				switch child {
				case "dir":
					t = TypeDir
				case "symlink":
					t = TypeSymlink
				case "other":
					t = TypeOther
				}
				c := &memNode{
					name: k,
					info: FileInfo{Type: t, ID: next, Volume: vol, LinkCount: 1},
				}
				next++
				if t == TypeDir {
					c.children = make(map[string]*memNode)
				}
				n.children[k] = c
			case nil:
				c := &memNode{
					name:     k,
					info:     FileInfo{Type: TypeDir, ID: next, Volume: vol, LinkCount: 1},
					children: make(map[string]*memNode),
				}
				next++
				n.children[k] = c
			default:
				c := &memNode{
					name: k,
					info: FileInfo{Type: TypeFile, ID: next, Volume: vol, LinkCount: 1},
				}
				next++
				n.children[k] = c
			}
		}
	}
	return n
}

func countNodes(tree map[string]any) int {
	n := 0
	for _, v := range tree {
		n++
		if m, ok := v.(map[string]any); ok {
			n += countNodes(m)
		}
	}
	return n
}

// ensure component key lookup uses exact bytes (tests use ASCII names).
var _ Dir = (*memNode)(nil)
var _ File = (*memNode)(nil)

func comps(names ...string) [][]byte {
	out := make([][]byte, len(names))
	for i, n := range names {
		out[i] = []byte(n)
	}
	return out
}

// equalBytes reports identical component slices.
func equalBytes(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func b(s string) []byte { return []byte(s) }
