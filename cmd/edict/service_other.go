//go:build !windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ryandunton/agent-edict/internal/agent"
)

func isServiceEnvironment() bool {
	return false
}

func runDaemonAsService() {}

func runPlatformService(ag *agent.Agent) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		cancel()
	}()

	return ag.Run(ctx, make(chan struct{}))
}

func handleServiceCommand(action string, bundleURL string, deployTokenFile string, interval, sessionInterval time.Duration) error {
	return fmt.Errorf("native service management via 'service' command is currently supported on Windows. On Linux use systemd, or run 'edict daemon' directly")
}
