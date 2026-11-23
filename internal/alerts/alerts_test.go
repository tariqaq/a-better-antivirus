package alerts

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadRejectsInvalidIDs(t *testing.T) {
	if runtime.GOOS == "windows" {
		pd := t.TempDir()
		t.Setenv("ProgramData", pd)
		dataDir := filepath.Join(pd, "FileAccessMonitor")
		if err := os.MkdirAll(filepath.Join(dataDir, "alerts"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dataDir, "config.json"), []byte(`{"preset":"balanced"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for _, bad := range []string{"", "../config", `..\config`, "a/b", `a\b`, ".."} {
		_, err := Load(bad)
		if err == nil || !strings.Contains(err.Error(), "invalid alert id") {
			t.Fatalf("Load(%q) error = %v, want invalid alert id", bad, err)
		}
	}
}
