package service

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestHashCacheBounded(t *testing.T) {
	hashCacheMu.Lock()
	orig := hashCache
	hashCache = make(map[string]string)
	hashCacheMu.Unlock()
	defer func() {
		hashCacheMu.Lock()
		hashCache = orig
		hashCacheMu.Unlock()
	}()

	tmp := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(tmp, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &server{}
	if h := s.Hash(tmp); h == "" {
		t.Fatal("Hash returned empty string")
	}

	// Simulate many distinct paths entering hashCache without creating thousands of files.
	hashCacheMu.Lock()
	for i := 0; i < maxHashCache+25; i++ {
		if len(hashCache) >= maxHashCache {
			hashCache = make(map[string]string, maxHashCache/2)
		}
		hashCache[fmt.Sprintf("k%d", i)] = "h"
	}
	n := len(hashCache)
	hashCacheMu.Unlock()
	if n > maxHashCache {
		t.Fatalf("len(hashCache) = %d, want <= %d", n, maxHashCache)
	}

	// Also verify s.Hash itself triggers the reset cleanly when hashCache is full.
	hashCacheMu.Lock()
	for i := len(hashCache); i < maxHashCache; i++ {
		hashCache[fmt.Sprintf("fill%d", i)] = "h"
	}
	hashCacheMu.Unlock()
	tmp2 := filepath.Join(t.TempDir(), "sample2.bin")
	if err := os.WriteFile(tmp2, []byte("def"), 0o644); err != nil {
		t.Fatal(err)
	}
	if h := s.Hash(tmp2); h == "" {
		t.Fatal("Hash after cache cap returned empty")
	}
	hashCacheMu.Lock()
	after := len(hashCache)
	hashCacheMu.Unlock()
	if after > maxHashCache {
		t.Fatalf("len(hashCache) after s.Hash = %d, want <= %d", after, maxHashCache)
	}
}
