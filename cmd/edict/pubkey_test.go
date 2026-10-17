package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildWithoutKeyRefusesToSync(t *testing.T) {
	if _, err := trustedPublicKey("", "REPLACE WITH YOUR ED25519 PUBLIC KEY (PEM)"); err == nil || !strings.Contains(err.Error(), "no trusted public key") {
		t.Fatalf("placeholder key accepted: %v", err)
	}
	builtIn := "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"
	if got, err := trustedPublicKey("", builtIn); err != nil || got != builtIn {
		t.Fatalf("built-in key: %q %v", got, err)
	}
	file := filepath.Join(t.TempDir(), "key.pem")
	os.WriteFile(file, []byte("from file"), 0600)
	if got, err := trustedPublicKey(file, "REPLACE WITH YOUR ED25519 PUBLIC KEY (PEM)"); err != nil || got != "from file" {
		t.Fatalf("-pubkey file: %q %v", got, err)
	}
	if _, err := trustedPublicKey(filepath.Join(t.TempDir(), "missing.pem"), builtIn); err == nil {
		t.Fatal("missing -pubkey file accepted")
	}
}
