//go:build !windows

package main

import "context"

// runAsService is a no-op off Windows.
//
// systemd and launchd run a daemon as an ordinary foreground process and stop
// it with SIGTERM, which `signal.NotifyContext` already handles. Only the
// Windows SCM needs a process to answer a control channel.
func runAsService(_ func(context.Context)) (handled bool, err error) {
	return false, nil
}
