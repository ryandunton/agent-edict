//go:build windows

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/ryandunton/agent-edict/internal/agent"
	"github.com/ryandunton/agent-edict/internal/platform"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "AgentEdictService"
const serviceDisplayName = "AgentEdict Universal AI Policy Enforcer"
const serviceDescription = "Installs and protects signed machine policy for AI coding agents."

type edictWindowsService struct {
	ag *agent.Agent
}

func isServiceEnvironment() bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isService
}

func runDaemonAsService() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "daemon" {
		args = args[1:]
	}
	runDaemon(args)
}

func runPlatformService(ag *agent.Agent) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}

	if !isService {
		log.Println("[Main] Running in interactive console mode (Press Ctrl+C to terminate)...")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		return ag.Run(ctx, make(chan struct{}))
	}

	// Direct logs to C:\ProgramData\AgentEdict\service.log when running in Session 0
	logDir := `C:\ProgramData\AgentEdict`
	file, err := platform.OpenServiceLog(logDir)
	if err != nil {
		return fmt.Errorf("initialize secure service log: %w", err)
	}
	previousOutput := log.Writer()
	log.SetOutput(file)
	defer func() {
		log.SetOutput(previousOutput)
		file.Close()
	}()

	return svc.Run(serviceName, &edictWindowsService{ag: ag})
}

func (m *edictWindowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptSessionChange
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sessionChangeCh := make(chan struct{}, 1)
	errCh := make(chan error, 1)

	go func() {
		errCh <- m.ag.Run(ctx, sessionChangeCh)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				cancel()
				break loop
			case svc.SessionChange:
				select {
				case sessionChangeCh <- struct{}{}:
				default:
				}
			}
		case err := <-errCh:
			if err != nil {
				log.Printf("[Service] Fatal agent error: %v", err)
				return false, 1
			}
			break loop
		}
	}

	changes <- svc.Status{State: svc.StopPending}
	time.Sleep(250 * time.Millisecond)
	return false, 0
}

func handleServiceCommand(action string, bundleURL string, deployTokenFile string, interval, sessionInterval time.Duration) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	switch action {
	case "install":
		exePath, err := os.Executable()
		if err != nil {
			return err
		}
		exePath, err = filepath.Abs(exePath)
		if err != nil {
			return err
		}
		if err := platform.ValidateServiceExecutable(exePath); err != nil {
			return err
		}

		if deployTokenFile != "" {
			if !filepath.IsAbs(deployTokenFile) {
				return fmt.Errorf("credential file path must be absolute for a Windows service")
			}
			if _, err := platform.ReadDeployTokenFile(deployTokenFile); err != nil {
				return err
			}
		}
		serviceArgs := daemonServiceArguments(bundleURL, deployTokenFile, interval, sessionInterval)

		cfg := mgr.Config{
			ServiceType: windows.SERVICE_WIN32_OWN_PROCESS,
			StartType:   mgr.StartAutomatic,
			DisplayName: serviceDisplayName,
			Description: serviceDescription,
		}

		s, err := m.CreateService(serviceName, exePath, cfg, serviceArgs...)
		if err != nil {
			return fmt.Errorf("create service: %w", err)
		}
		defer s.Close()

		// Configure recovery on failure: restart after 5s
		recoveryActions := []mgr.RecoveryAction{
			{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		}
		_ = s.SetRecoveryActions(recoveryActions, 86400)

		fmt.Printf("Service %q installed successfully.\n", serviceName)
		return nil

	case "uninstall":
		s, err := m.OpenService(serviceName)
		if err != nil {
			return fmt.Errorf("open service: %w", err)
		}
		defer s.Close()

		_, _ = s.Control(svc.Stop)
		if err := s.Delete(); err != nil {
			return fmt.Errorf("delete service: %w", err)
		}
		fmt.Printf("Service %q uninstalled successfully.\n", serviceName)
		return nil

	case "start":
		s, err := m.OpenService(serviceName)
		if err != nil {
			return fmt.Errorf("open service: %w", err)
		}
		defer s.Close()

		if err := s.Start(); err != nil {
			return fmt.Errorf("start service: %w", err)
		}
		fmt.Printf("Service %q started.\n", serviceName)
		return nil

	case "stop":
		s, err := m.OpenService(serviceName)
		if err != nil {
			return fmt.Errorf("open service: %w", err)
		}
		defer s.Close()

		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("stop service: %w", err)
		}
		fmt.Printf("Service %q stopped.\n", serviceName)
		return nil

	default:
		return fmt.Errorf("unknown service action: %s (choose install, uninstall, start, stop)", action)
	}
}
