package agent

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// PolicyMapV2 selects a policy per managed agent from the groups of the
// users logged in to a machine. The standard covers every managed agent.
type PolicyMapV2 struct {
	Version       int          `yaml:"version"`
	ManagedAgents []string     `yaml:"managed_agents"`
	SyncWSL       bool         `yaml:"sync_wsl,omitempty"`
	Standard      StandardRule `yaml:"standard"`
	Rules         []RoleRule   `yaml:"rules"`
}

// StandardRule is the policy every managed agent gets when no rule that
// covers it matches, competing at its own priority.
type StandardRule struct {
	Profile  string `yaml:"profile"`
	Priority int    `yaml:"priority"`
}

// RoleRule assigns a profile to the listed agents for users in any of the
// matched groups. A lower priority number wins.
type RoleRule struct {
	Priority    int                 `yaml:"priority"`
	Profile     string              `yaml:"profile"`
	Description string              `yaml:"description,omitempty"`
	Agents      []string            `yaml:"agents"`
	MatchGroups map[string][]string `yaml:"match_groups"`
}

// ProfileAgent is one compiled profile for one agent.
type ProfileAgent struct {
	Profile, Agent string
}

// BundleMap holds whichever map version a snapshot carries.
type BundleMap struct {
	V1 *PolicyMap
	V2 *PolicyMapV2
}

var (
	windowsSIDPattern = regexp.MustCompile(`^[Ss]-1(-[0-9]+)+$`)
	entraIDPattern    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

func supportedManagedAgent(name string) bool {
	return name == "codex" || name == "claude" || name == "opencode" || nativeProduct(name)
}

// ParsePolicyMapV2 decodes and validates a version 2 map. The result has
// [all] expanded and Windows entra: groups converted to their SIDs.
func ParsePolicyMapV2(data []byte) (*PolicyMapV2, error) {
	var m PolicyMapV2
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("decode policy map: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("policy map must contain exactly one YAML document")
	}
	if m.Version != 2 {
		return nil, fmt.Errorf("policy map requires version 2")
	}
	if m.SyncWSL {
		return nil, fmt.Errorf("sync_wsl is not supported with version 2 maps")
	}
	if len(m.ManagedAgents) == 0 {
		return nil, fmt.Errorf("managed_agents must be a nonempty list of agent names")
	}
	seen := map[string]bool{}
	for _, name := range m.ManagedAgents {
		if name == "all" {
			return nil, fmt.Errorf("managed_agents must list agents explicitly, not all")
		}
		if !supportedManagedAgent(name) {
			return nil, fmt.Errorf("unsupported managed agent %q", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate managed agent %q", name)
		}
		seen[name] = true
	}
	if m.Standard.Profile == "" {
		return nil, fmt.Errorf("standard requires a profile and a priority")
	}
	if !profileNamePattern.MatchString(m.Standard.Profile) {
		return nil, fmt.Errorf("standard profile %q is not a safe profile name", m.Standard.Profile)
	}
	// A missing priority decodes as 0, which would silently outrank every rule.
	if m.Standard.Priority < 1 {
		return nil, fmt.Errorf("standard priority must be 1 or higher")
	}
	priorities := map[int]string{m.Standard.Priority: "standard"}
	for i := range m.Rules {
		rule := &m.Rules[i]
		where := fmt.Sprintf("rule %d (%s)", i+1, rule.Profile)
		if !profileNamePattern.MatchString(rule.Profile) {
			return nil, fmt.Errorf("%s: profile %q is not a safe profile name", where, rule.Profile)
		}
		if rule.Priority < 1 {
			return nil, fmt.Errorf("%s: priority must be 1 or higher", where)
		}
		if owner, taken := priorities[rule.Priority]; taken {
			return nil, fmt.Errorf("%s: priority %d is already used by %s", where, rule.Priority, owner)
		}
		priorities[rule.Priority] = where
		agents, err := resolveRuleAgents(rule.Agents, m.ManagedAgents)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		rule.Agents = agents
		groups, err := normalizeMatchGroups(rule.MatchGroups)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		rule.MatchGroups = groups
	}
	return &m, nil
}

func resolveRuleAgents(agents, managed []string) ([]string, error) {
	if len(agents) == 0 {
		return nil, fmt.Errorf("agents must list at least one agent")
	}
	if slices.Contains(agents, "all") {
		if len(agents) != 1 {
			return nil, fmt.Errorf("agents: [all] cannot be mixed with agent names")
		}
		return slices.Clone(managed), nil
	}
	seen := map[string]bool{}
	for _, name := range agents {
		if !slices.Contains(managed, name) {
			return nil, fmt.Errorf("agent %q is not in managed_agents", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate agent %q", name)
		}
		seen[name] = true
	}
	return agents, nil
}

func normalizeMatchGroups(groups map[string][]string) (map[string][]string, error) {
	if len(groups) == 0 {
		return nil, fmt.Errorf("match_groups must name groups for at least one OS")
	}
	out := map[string][]string{}
	for osKey, entries := range groups {
		if osKey != "windows" && osKey != "linux" && osKey != "darwin" {
			return nil, fmt.Errorf("match_groups key %q must be windows, linux or darwin", osKey)
		}
		for _, entry := range entries {
			if entry == "" || strings.TrimSpace(entry) != entry || strings.IndexFunc(entry, unicode.IsControl) >= 0 {
				return nil, fmt.Errorf("match_groups.%s has an empty or padded group %q", osKey, entry)
			}
			if osKey == "windows" {
				normalized, err := normalizeWindowsGroup(entry)
				if err != nil {
					return nil, err
				}
				entry = normalized
			}
			out[osKey] = append(out[osKey], entry)
		}
	}
	return out, nil
}

func normalizeWindowsGroup(entry string) (string, error) {
	if windowsSIDPattern.MatchString(entry) {
		return "S" + entry[1:], nil
	}
	if strings.HasPrefix(strings.ToLower(entry), "entra:") {
		return EntraObjectIDToSID(entry[len("entra:"):])
	}
	domain, name, found := strings.Cut(entry, `\`)
	if found && domain != "" && name != "" && !strings.Contains(name, `\`) {
		return entry, nil
	}
	return "", fmt.Errorf(`windows group %q must be a SID, entra:<object-id>, .\Name or DOMAIN\Name`, entry)
}

// EntraObjectIDToSID converts an Entra ID group object ID to the SID that
// Windows puts in the login token: the GUID's bytes in Windows order read as
// four little-endian uint32 values after S-1-12-1.
func EntraObjectIDToSID(objectID string) (string, error) {
	if !entraIDPattern.MatchString(objectID) {
		return "", fmt.Errorf("entra object ID %q must be a GUID", objectID)
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(objectID, "-", ""))
	if err != nil {
		return "", fmt.Errorf("entra object ID %q: %w", objectID, err)
	}
	// Windows stores Data1, Data2 and Data3 little-endian, Data4 as written.
	windowsOrder := []byte{raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6]}
	windowsOrder = append(windowsOrder, raw[8:]...)
	parts := make([]string, 4)
	for i := range parts {
		parts[i] = fmt.Sprint(binary.LittleEndian.Uint32(windowsOrder[i*4:]))
	}
	return "S-1-12-1-" + strings.Join(parts, "-"), nil
}

// Pairs lists every profile-agent output the map can select, sorted.
func (m *PolicyMapV2) Pairs() []ProfileAgent {
	seen := map[ProfileAgent]bool{}
	var pairs []ProfileAgent
	add := func(profile string, agents []string) {
		for _, agent := range agents {
			pair := ProfileAgent{profile, agent}
			if !seen[pair] {
				seen[pair] = true
				pairs = append(pairs, pair)
			}
		}
	}
	add(m.Standard.Profile, m.ManagedAgents)
	for _, rule := range m.Rules {
		add(rule.Profile, rule.Agents)
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Profile != pairs[j].Profile {
			return pairs[i].Profile < pairs[j].Profile
		}
		return pairs[i].Agent < pairs[j].Agent
	})
	return pairs
}

// UsesWindowsNames reports whether any Windows rule matches DOMAIN\Name,
// which needs SID-to-name translation that can fail offline.
func (m *PolicyMapV2) UsesWindowsNames() bool {
	for _, rule := range m.Rules {
		for _, entry := range rule.MatchGroups["windows"] {
			if !strings.HasPrefix(entry, "S-1-") && !strings.HasPrefix(entry, `.\`) {
				return true
			}
		}
	}
	return false
}

func mapVersion(data []byte) int {
	var header struct {
		Version int `yaml:"version"`
	}
	if yaml.Unmarshal(data, &header) != nil {
		return 0
	}
	return header.Version
}

// LoadBundleMap reads a snapshot's policy-map.yaml as version 1 or 2.
func LoadBundleMap(snapshotPath string) (*BundleMap, error) {
	data, err := readRegularFile(filepath.Join(snapshotPath, "policy-map.yaml"), 1024*1024)
	if err != nil {
		return nil, fmt.Errorf("read policy map: %w", err)
	}
	if mapVersion(data) == 2 {
		m, err := ParsePolicyMapV2(data)
		if err != nil {
			return nil, err
		}
		return &BundleMap{V2: m}, nil
	}
	pm, err := parsePolicyMapV1(data)
	if err != nil {
		return nil, err
	}
	return &BundleMap{V1: pm}, nil
}
