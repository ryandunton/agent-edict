package agent

import (
	"slices"
	"sort"
	"strings"

	"github.com/ryandunton/agent-edict/internal/platform"
)

// Assignment is the policy one managed agent gets on this machine. Source is
// "standard" or "rule"; Users names who produced the winning candidate.
type Assignment struct {
	Agent    string   `json:"agent"`
	Profile  string   `json:"profile"`
	Priority int      `json:"priority"`
	Source   string   `json:"source"`
	Users    []string `json:"users,omitempty"`
}

// StandardAssignments gives every managed agent the standard policy.
func StandardAssignments(m *PolicyMapV2) []Assignment {
	out := make([]Assignment, 0, len(m.ManagedAgents))
	for _, agent := range m.ManagedAgents {
		out = append(out, Assignment{Agent: agent, Profile: m.Standard.Profile, Priority: m.Standard.Priority, Source: "standard"})
	}
	return out
}

// SelectAssignments picks each agent's policy. Every user's candidate is the
// lowest-priority matching rule that covers the agent, or the standard; the
// lowest-priority candidate across users wins. No users means the standard.
func SelectAssignments(m *PolicyMapV2, osName string, users []platform.SessionUser) []Assignment {
	if len(users) == 0 {
		return StandardAssignments(m)
	}
	unique := map[string]platform.SessionUser{}
	for _, user := range users {
		unique[user.Key] = user
	}
	out := make([]Assignment, 0, len(m.ManagedAgents))
	for _, agent := range m.ManagedAgents {
		var winner *Assignment
		for _, user := range unique {
			candidate := userCandidate(m, osName, agent, user)
			switch {
			case winner == nil || candidate.Priority < winner.Priority:
				candidate.Users = []string{user.Name}
				winner = &candidate
			case candidate.Priority == winner.Priority:
				winner.Users = append(winner.Users, user.Name)
			}
		}
		sort.Strings(winner.Users)
		out = append(out, *winner)
	}
	return out
}

// userCandidate is the user's lowest-priority matching rule that covers the
// agent, whatever its number, or the standard when no such rule matches.
func userCandidate(m *PolicyMapV2, osName, agent string, user platform.SessionUser) Assignment {
	var best *Assignment
	for _, rule := range m.Rules {
		if (best == nil || rule.Priority < best.Priority) && slices.Contains(rule.Agents, agent) && groupsMatch(osName, rule.MatchGroups[osName], user.Groups) {
			best = &Assignment{Agent: agent, Profile: rule.Profile, Priority: rule.Priority, Source: "rule"}
		}
	}
	if best == nil {
		return Assignment{Agent: agent, Profile: m.Standard.Profile, Priority: m.Standard.Priority, Source: "standard"}
	}
	return *best
}

// Windows group names are case-insensitive; Unix group names are exact.
func groupsMatch(osName string, wanted, have []string) bool {
	for _, w := range wanted {
		for _, h := range have {
			if w == h || (osName == "windows" && strings.EqualFold(w, h)) {
				return true
			}
		}
	}
	return false
}
