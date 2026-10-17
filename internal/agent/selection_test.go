package agent

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ryandunton/agent-edict/internal/platform"
)

func designMap(t *testing.T, edit func(string) string) *PolicyMapV2 {
	t.Helper()
	text := designExampleMap
	if edit != nil {
		text = edit(text)
	}
	m, err := ParsePolicyMapV2([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func assignmentFor(t *testing.T, got []Assignment, agent string) Assignment {
	t.Helper()
	for _, a := range got {
		if a.Agent == agent {
			return a
		}
	}
	t.Fatalf("no assignment for %s in %+v", agent, got)
	return Assignment{}
}

var (
	engineer   = platform.SessionUser{Key: "1001", Name: "eve", Groups: []string{"engineers"}}
	contractor = platform.SessionUser{Key: "1002", Name: "carl", Groups: []string{"contractors"}}
)

func TestSelectDesignExample(t *testing.T) {
	got := SelectAssignments(designMap(t, nil), "linux", []platform.SessionUser{engineer, contractor})
	if codex := assignmentFor(t, got, "codex"); codex.Profile != "contractor-readonly" || codex.Priority != 10 || codex.Source != "rule" {
		t.Errorf("codex = %+v", codex)
	}
	if claude := assignmentFor(t, got, "claude"); claude.Profile != "contractor-claude" || claude.Priority != 11 {
		t.Errorf("claude = %+v", claude)
	}
	if cursor := assignmentFor(t, got, "cursor"); cursor.Profile != "engineering" || cursor.Priority != 20 || !slices.Equal(cursor.Users, []string{"eve"}) {
		t.Errorf("cursor = %+v", cursor)
	}
	var order []string
	for _, a := range got {
		order = append(order, a.Agent)
	}
	if !slices.Equal(order, []string{"codex", "claude", "cursor"}) {
		t.Errorf("assignments are not in managed_agents order: %v", order)
	}
}

func TestSelectFallsBackToStandardThenPriority(t *testing.T) {
	withoutClaudeRule := designMap(t, func(s string) string {
		start := strings.Index(s, "  - priority: 11")
		end := strings.Index(s, "  - priority: 20")
		return s[:start] + s[end:]
	})
	got := SelectAssignments(withoutClaudeRule, "linux", []platform.SessionUser{engineer, contractor})
	if claude := assignmentFor(t, got, "claude"); claude.Profile != "engineering" || claude.Priority != 20 {
		t.Errorf("contractor's standard (100) must lose to engineering (20): %+v", claude)
	}
	alone := SelectAssignments(withoutClaudeRule, "linux", []platform.SessionUser{contractor})
	if claude := assignmentFor(t, alone, "claude"); claude.Profile != "standard" || claude.Source != "standard" {
		t.Errorf("a contractor alone gets the standard for claude: %+v", claude)
	}
}

func TestSelectUnmatchedUserGetsStandard(t *testing.T) {
	m := designMap(t, nil)
	got := SelectAssignments(m, "linux", []platform.SessionUser{{Key: "1003", Name: "uma"}})
	for _, a := range got {
		if a.Profile != "standard" || a.Priority != 100 || a.Source != "standard" || !slices.Equal(a.Users, []string{"uma"}) {
			t.Errorf("unmatched user: %+v", a)
		}
	}
	if none := SelectAssignments(m, "linux", nil); !reflect.DeepEqual(none, StandardAssignments(m)) {
		t.Errorf("no users = %+v, want the standard", none)
	}
}

func TestSelectMatchingCase(t *testing.T) {
	m := designMap(t, nil)
	windows := SelectAssignments(m, "windows", []platform.SessionUser{{Key: "S-1-5-21-9", Name: `CORP\eve`, Groups: []string{`corp\sg-engineers`}}})
	if codex := assignmentFor(t, windows, "codex"); codex.Profile != "engineering" {
		t.Errorf("Windows group names match case-insensitively: %+v", codex)
	}
	linux := SelectAssignments(m, "linux", []platform.SessionUser{{Key: "1001", Name: "eve", Groups: []string{"Engineers"}}})
	if codex := assignmentFor(t, linux, "codex"); codex.Profile != "standard" {
		t.Errorf("Linux group names match exactly: %+v", codex)
	}
	local := SelectAssignments(m, "windows", []platform.SessionUser{{Key: "S-1-5-21-8", Name: `LAPTOP\carl`, Groups: []string{`.\contractors`}}})
	if codex := assignmentFor(t, local, "codex"); codex.Profile != "contractor-readonly" {
		t.Errorf(".\\Name matches local groups: %+v", codex)
	}
}

func TestSelectDeduplicatesAndSortsUsers(t *testing.T) {
	m := designMap(t, nil)
	zed := platform.SessionUser{Key: "1009", Name: "zed", Groups: []string{"engineers"}}
	got := SelectAssignments(m, "linux", []platform.SessionUser{zed, engineer, zed})
	if cursor := assignmentFor(t, got, "cursor"); !slices.Equal(cursor.Users, []string{"eve", "zed"}) {
		t.Errorf("Users = %v, want each user once, sorted", cursor.Users)
	}
}

// A user's matching rule is their candidate whatever its number; ranking the
// standard first only decides contests between users.
func TestSelectRuleWinsForItsUserWhenStandardRanksFirst(t *testing.T) {
	m := designMap(t, func(s string) string {
		return strings.Replace(s, "  profile: standard\n  priority: 100\n", "  profile: standard\n  priority: 1\n", 1)
	})
	alone := SelectAssignments(m, "linux", []platform.SessionUser{engineer})
	if codex := assignmentFor(t, alone, "codex"); codex.Profile != "engineering" || codex.Priority != 20 {
		t.Errorf("an engineer alone must get engineering: %+v", codex)
	}
	shared := SelectAssignments(m, "linux", []platform.SessionUser{engineer, {Key: "1003", Name: "uma"}})
	if codex := assignmentFor(t, shared, "codex"); codex.Profile != "standard" || codex.Priority != 1 {
		t.Errorf("the standard ranked first must win on a shared machine: %+v", codex)
	}
}
