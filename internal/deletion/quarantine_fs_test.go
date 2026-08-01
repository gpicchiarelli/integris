package deletion_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/deletion"
)

func TestExecuteQuarantineMove(t *testing.T) {
	root := t.TempDir()
	srcName := "victim"
	if err := os.WriteFile(filepath.Join(root, srcName), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := deletion.Evaluate(thOK(), obsOK(), authOK())
	if err != nil {
		t.Fatal(err)
	}
	qp, err := deletion.BuildQuarantinePlan([]byte(srcName), []byte("q-"+srcName), dig("obj"), dig("plan"), dig("auth"))
	if err != nil {
		t.Fatal(err)
	}
	if err := deletion.ExecuteQuarantineMove(root, d, qp); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, srcName)); !os.IsNotExist(err) {
		t.Fatalf("source still present: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "quarantine", "q-"+srcName)); err != nil {
		t.Fatal(err)
	}
}

func TestExecuteQuarantineMoveRejectsCollision(t *testing.T) {
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
	err = deletion.ExecuteQuarantineMove(root, d, qp)
	var e *deletion.Error
	if err == nil || !asDel(err, &e) || e.Code != "collision" {
		t.Fatalf("got %v", err)
	}
}

func TestExecuteQuarantineMoveRequiresDecision(t *testing.T) {
	err := deletion.ExecuteQuarantineMove(t.TempDir(), deletion.Decision{}, deletion.QuarantinePlan{
		SourceName: []byte("a"), QuarantineName: []byte("b"),
		ObjectID: dig("o"), PlanDigest: dig("p"), AuthDigest: dig("a"),
	})
	var e *deletion.Error
	if err == nil || !asDel(err, &e) || e.Code != "decision" {
		t.Fatalf("got %v", err)
	}
}
