package main

import (
	"reflect"
	"testing"
	"time"
)

func TestServiceArgumentsContainOnlyCredentialFilePath(t *testing.T) {
	args := daemonServiceArguments("https://registry.example/bundle", `C:\ProgramData\AgentEdict\credentials\deploy-token`, time.Minute, 0)
	want := []string{"daemon", "-bundle-url", "https://registry.example/bundle", "-deploy-token-file", `C:\ProgramData\AgentEdict\credentials\deploy-token`, "-interval", "1m0s"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("service args: %#v", args)
	}
}
func TestPublicBundleServiceHasNoCredentialArgument(t *testing.T) {
	if got := daemonServiceArguments("", "", 0, 0); !reflect.DeepEqual(got, []string{"daemon"}) {
		t.Fatalf("args=%v", got)
	}
}

func TestDaemonServiceArgumentsIncludeSessionInterval(t *testing.T) {
	got := daemonServiceArguments("", "", 0, 45*time.Second)
	if want := []string{"daemon", "-session-interval", "45s"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("args=%v, want %v", got, want)
	}
}
