package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ryandunton/agent-edict/internal/platform"
)

const (
	roleStateFile    = "role-state.json"
	roleStateVersion = 1
	maxRoleState     = 1024 * 1024
	maxOriginalBytes = 5 * 1024 * 1024
)

// RoleState is the vault record that lets a machine keep its last proven
// policy across logouts and restarts. Installed maps each target path to the
// SHA-256 of the bytes AgentEdict last installed there.
type RoleState struct {
	Version     int                    `json:"version"`
	BundleHash  string                 `json:"bundle_hash"`
	ProvenAt    time.Time              `json:"proven_at"`
	Users       []platform.SessionUser `json:"users"`
	Assignments []Assignment           `json:"assignments"`
	Installed   map[string]string      `json:"installed"`
	CreatedDirs []string               `json:"created_dirs"`
	Originals   []OriginalCopy         `json:"originals"`
	Released    []string               `json:"released"`
}

// OriginalCopy records a file that was in place before AgentEdict first
// replaced it. It is kept for manual recovery and never restored automatically.
type OriginalCopy struct {
	Path    string    `json:"path"`
	Copy    string    `json:"copy"`
	SHA256  string    `json:"sha256"`
	SavedAt time.Time `json:"saved_at"`
}

// LoadRoleState returns nil, nil when no state has been saved. A corrupt or
// unknown state is an error so callers keep the installed files.
func LoadRoleState(vault string) (*RoleState, error) {
	data, err := readRegularFile(filepath.Join(vault, roleStateFile), maxRoleState)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read role state: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var state RoleState
	if err := dec.Decode(&state); err != nil {
		return nil, fmt.Errorf("decode role state: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("role state must contain exactly one JSON document")
	}
	if state.Version != roleStateVersion {
		return nil, fmt.Errorf("unsupported role state version %d", state.Version)
	}
	return &state, nil
}

// SaveRoleState replaces the state file atomically with a private copy.
func SaveRoleState(vault string, state *RoleState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFile(vault, roleStateFile, append(data, '\n'))
}

// SaveOriginal copies a pre-existing target file into vault/originals.
func SaveOriginal(vault, targetPath string, data []byte) (OriginalCopy, error) {
	if len(data) > maxOriginalBytes {
		return OriginalCopy{}, fmt.Errorf("original %s exceeds the %d byte copy limit", targetPath, maxOriginalBytes)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	dir := filepath.Join(vault, "originals")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return OriginalCopy{}, err
	}
	name := digest + ".orig"
	if err := writePrivateFile(dir, name, data); err != nil {
		return OriginalCopy{}, err
	}
	return OriginalCopy{Path: targetPath, Copy: filepath.Join("originals", name), SHA256: digest, SavedAt: time.Now().UTC()}, nil
}

// writePrivateFile writes dir/name through a synced temporary file and a
// rename, so a crash leaves either the old or the new contents.
func writePrivateFile(dir, name string, data []byte) error {
	temp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, filepath.Join(dir, name))
}
