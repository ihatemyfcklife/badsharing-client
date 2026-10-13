package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOutputPathRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"../escape", ".", "..", "bad/name", "bad\\name", ""} {
		if _, err := OutputPath(dir, name); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	path, err := OutputPath(dir, "data.bin")
	if err != nil || path != filepath.Join(dir, "data.bin") {
		t.Fatalf("got %q %v", path, err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}
