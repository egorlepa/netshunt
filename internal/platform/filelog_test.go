package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileLogRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log", "netshunt.log")
	l, err := openFileLog(path, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		_, _ = fmt.Fprintf(l, "line %02d padding padding\n", i) // 25 bytes, 4 per file
	}
	l.Close()

	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if got := read(path); !strings.HasPrefix(got, "line 16") || !strings.Contains(got, "line 19") {
		t.Errorf("active file = %q", got)
	}
	if got := read(path + ".1"); !strings.HasPrefix(got, "line 12") {
		t.Errorf(".1 = %q", got)
	}
	if got := read(path + ".2"); !strings.HasPrefix(got, "line 08") {
		t.Errorf(".2 = %q", got)
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Errorf(".3 should not exist, err = %v", err)
	}
}

func TestFileLogAppendsAndIgnoresWritesAfterClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netshunt.log")
	if err := os.WriteFile(path, []byte("old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	l, err := OpenFileLog(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintln(l, "new")
	l.Close()
	_, _ = fmt.Fprintln(l, "after close")
	l.Close()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "old\nnew\n" {
		t.Errorf("file = %q", b)
	}
}
