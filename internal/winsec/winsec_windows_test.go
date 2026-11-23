package winsec

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"unsafe"
)

func TestEmptyACL(t *testing.T) {
	a := EmptyACL()
	b := (*[8]byte)(unsafe.Pointer(a))
	if b[0] != 2 || *(*uint16)(unsafe.Pointer(&b[2])) != 8 || aclAceCount(a) != 0 {
		t.Fatalf("bad empty ACL header: % x", b[:])
	}
}

func makeJunction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd.exe", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J %s -> %s: %v (%s)", link, target, err, out)
	}
}

func TestNoReparseRejectsJunction(t *testing.T) {
	root := t.TempDir()
	targetDir := filepath.Join(root, "outside")
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(targetDir, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	linkDir := filepath.Join(root, "junction")
	makeJunction(t, linkDir, targetDir)

	viaLink := filepath.Join(linkDir, "sentinel.txt")
	newViaLink := filepath.Join(linkDir, "new.txt")
	nestedViaLink := filepath.Join(linkDir, "sub", "dir")

	if err := WriteFileNewNoReparse(newViaLink, []byte("pwn")); !errors.Is(err, ErrReparsePoint) {
		t.Fatalf("WriteFileNewNoReparse = %v, want ErrReparsePoint", err)
	}
	if _, err := os.Stat(filepath.Join(targetDir, "new.txt")); !os.IsNotExist(err) {
		t.Fatal("WriteFileNewNoReparse wrote through junction")
	}
	if err := OverwriteFileNoReparse(viaLink, []byte("pwn")); !errors.Is(err, ErrReparsePoint) {
		t.Fatalf("OverwriteFileNoReparse = %v, want ErrReparsePoint", err)
	}
	if _, err := ReadFileNoReparse(viaLink); !errors.Is(err, ErrReparsePoint) {
		t.Fatalf("ReadFileNoReparse = %v, want ErrReparsePoint", err)
	}
	if err := DeleteFileNoReparse(viaLink); !errors.Is(err, ErrReparsePoint) {
		t.Fatalf("DeleteFileNoReparse = %v, want ErrReparsePoint", err)
	}
	if err := RemoveEmptyDirNoReparse(linkDir); !errors.Is(err, ErrReparsePoint) {
		t.Fatalf("RemoveEmptyDirNoReparse = %v, want ErrReparsePoint", err)
	}
	if _, err := StatNoReparse(viaLink); !errors.Is(err, ErrReparsePoint) {
		t.Fatalf("StatNoReparse = %v, want ErrReparsePoint", err)
	}
	if err := MkdirAllNoReparse(nestedViaLink); !errors.Is(err, ErrReparsePoint) {
		t.Fatalf("MkdirAllNoReparse = %v, want ErrReparsePoint", err)
	}
	if b, err := os.ReadFile(sentinel); err != nil || string(b) != "keep" {
		t.Fatalf("sentinel was modified or removed: err=%v data=%q", err, b)
	}
}

func TestReadFileNoReparseLimit(t *testing.T) {
	root := t.TempDir()
	okFile := filepath.Join(root, "ok.txt")
	if err := os.WriteFile(okFile, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := ReadFileNoReparseLimit(okFile, 16)
	if err != nil || string(b) != "hello" {
		t.Fatalf("ReadFileNoReparseLimit(ok) = %q, %v", b, err)
	}

	bigFile := filepath.Join(root, "big.txt")
	if err := os.WriteFile(bigFile, make([]byte, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFileNoReparseLimit(bigFile, 16); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("ReadFileNoReparseLimit(big) = %v, want ErrFileTooLarge", err)
	}

	targetDir := filepath.Join(root, "target")
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(targetDir, "secret.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(root, "link")
	makeJunction(t, linkDir, targetDir)
	if _, err := ReadFileNoReparseLimit(filepath.Join(linkDir, "secret.txt"), 16); !errors.Is(err, ErrReparsePoint) {
		t.Fatalf("ReadFileNoReparseLimit(junction) = %v, want ErrReparsePoint", err)
	}
}
