package main

import "time"

func daemonServiceArguments(bundleURL, tokenFile string, interval, sessionInterval time.Duration) []string {
	args := []string{"daemon"}
	if bundleURL != "" {
		args = append(args, "-bundle-url", bundleURL)
	}
	if tokenFile != "" {
		args = append(args, "-deploy-token-file", tokenFile)
	}
	if interval > 0 {
		args = append(args, "-interval", interval.String())
	}
	if sessionInterval > 0 {
		args = append(args, "-session-interval", sessionInterval.String())
	}
	return args
}
