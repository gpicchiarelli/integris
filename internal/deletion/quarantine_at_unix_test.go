//go:build unix

package deletion_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/deletion"
)

func TestExecuteQuarantineMoveAT(t *testing.T) {
	root := t.TempDir()
	src := "victim-at"
	if err := os.WriteFile(filepath.Join(root, src), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := deletion.Evaluate(thOK(), obsOK(), authOK())
	if err != nil {
		t.Fatal(err)
	}
	qp, err := deletion.BuildQuarantinePlan([]byte(src), []byte("q-"+src), dig("obj"), dig("plan"), dig("auth"))
	if err != nil {
		t.Fatal(err)
	}
	if err := deletion.ExecuteQuarantineMoveAT(root, d, qp); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, src)); !os.IsNotExist(err) {
		t.Fatalf("source still present: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "quarantine", "q-"+src)); err != nil {
		t.Fatal(err)
	}
}

func TestExecuteQuarantineMoveATCollision(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "quarantine"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "a"), []byte("1"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "quarantine", "qa"), []byte("2"), 0o644)
	d, err := deletion.Evaluate(thOK(), obsOK(), authOK())
	if err != nil {
		t.Fatal(err)
	}
	qp, err := deletion.BuildQuarantinePlan([]byte("a"), []byte("qa"), dig("o"), dig("p"), dig("a"))
	if err != nil {
		t.Fatal(err)
	}
	err = deletion.ExecuteQuarantineMoveAT(root, d, qp)
	var e *deletion.Error
	if err == nil || !asDel(err, &e) || e.Code != "collision" {
		t.Fatalf("got %v", err)
	}
}
