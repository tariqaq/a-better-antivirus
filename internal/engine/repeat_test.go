package engine

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestRepeatPrunesAndCaps(t *testing.T) {
	e := &Engine{seen: map[string]time.Time{}}
	base := time.Now().Add(-24 * time.Hour)
	for i := 0; i < 10; i++ {
		e.repeat(fmt.Sprintf(`C:\old%d.exe`, i), "aws", base)
	}
	if len(e.seen) != 10 {
		t.Fatalf("setup len(seen) = %d, want 10", len(e.seen))
	}

	now := time.Now()
	if e.repeat(`C:\cur.exe`, "aws", now) {
		t.Fatal("first seen should return false")
	}
	if _, ok := e.seen[`c:\old0.exe|aws`]; ok {
		t.Fatal("expired seen entry was not pruned")
	}
	if !e.repeat(`C:\cur.exe`, "aws", now.Add(time.Minute)) {
		t.Fatal("second seen within repeatWindow should return true")
	}

	for i := 0; i < maxSeenEntries+50; i++ {
		e.repeat(fmt.Sprintf(`C:\app%d.exe`, i), "aws", now.Add(time.Duration(i)*time.Millisecond))
	}
	if len(e.seen) > maxSeenEntries {
		t.Fatalf("len(seen) = %d exceeded maxSeenEntries %d", len(e.seen), maxSeenEntries)
	}
}

func TestEngineProtectedProcess(t *testing.T) {
	e := New(&fakeEngineOps{}, 999999)
	if runtime.GOOS == "windows" {
		if !e.ProtectedProcess(filepath.Join(`C:\Windows`, "explorer.exe")) {
			t.Fatal("explorer.exe should be protected")
		}
		if !e.ProtectedProcess(filepath.Join(`C:\Windows`, "System32", "svchost.exe")) {
			t.Fatal("svchost.exe should be protected")
		}
		if e.ProtectedProcess(`C:\Users\bob\Temp\svchost.exe`) {
			t.Fatal("Temp\\svchost.exe must not be protected")
		}
	}
}

type fakeEngineOps struct{ Ops }
