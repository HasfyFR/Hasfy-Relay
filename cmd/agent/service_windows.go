//go:build windows

package main

// Running as a Windows service.
//
// The MSI registers the daemon with the service control manager so it starts
// at boot with no logged-in user — the same role systemd plays on Linux and
// launchd on macOS. That is not something a plain executable can do: the SCM
// starts the process, then expects it to connect back over a control channel
// and report SERVICE_RUNNING. A process that stays silent is killed after
// about 30 seconds, which is exactly what the earlier scheduled-task workaround
// was avoiding rather than solving.

import (
	"context"
	"time"

	"golang.org/x/sys/windows/svc"
)

// serviceName must match the name the MSI registers.
const serviceName = "HasfyAgent"

// Controls the service answers. Shutdown is included so a machine powering off
// gives the daemon the same clean stop as an explicit `sc stop`.
const acceptedControls = svc.AcceptStop | svc.AcceptShutdown

type agentService struct {
	run func(context.Context)
}

// Execute is the SCM's entry point.
//
// The daemon runs on its own goroutine so this one stays free to answer the
// control channel. A handler that blocks is a service Windows reports as
// "not responding" and eventually kills, however healthy the work underneath.
func (s *agentService) Execute(
	_ []string,
	r <-chan svc.ChangeRequest,
	status chan<- svc.Status,
) (bool, uint32) {
	// Enrolment on a fresh install waits on a human to approve a device code,
	// so first start can take minutes. StartPending with a WaitHint keeps the
	// SCM patient instead of declaring the start failed.
	status <- svc.Status{State: svc.StartPending, WaitHint: uint32(30 * time.Second / time.Millisecond)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.run(ctx)
	}()

	status <- svc.Status{State: svc.Running, Accepts: acceptedControls}

	for {
		select {
		case <-done:
			// The daemon returned on its own — an unrecoverable start error,
			// for instance. Reporting Stopped lets the SCM's restart policy
			// take over rather than leaving a service stuck in Running.
			status <- svc.Status{State: svc.Stopped}
			return false, 1

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				// The SCM polls; echo back what it asked about.
				status <- c.CurrentStatus

			case svc.Stop, svc.Shutdown:
				status <- svc.Status{
					State:    svc.StopPending,
					WaitHint: uint32(20 * time.Second / time.Millisecond),
				}
				cancel()

				// Wait for the daemon to unwind: it has a relay connection to
				// close and an audit batch to flush. Bounded, because a stop
				// that never completes is a machine that will not reboot.
				select {
				case <-done:
				case <-time.After(20 * time.Second):
				}

				status <- svc.Status{State: svc.Stopped}
				return false, 0

			default:
				// Unknown control: ignore rather than stop. Stopping on an
				// unrecognised code would let any future SCM addition take the
				// fleet down.
			}
		}
	}
}

// runAsService hands control to the SCM when the process was started by it.
//
// `IsWindowsService` is what separates the two: run from a console — an
// administrator debugging, or `hasfy-agent --version` — it returns false and
// the caller takes the ordinary signal-driven path.
func runAsService(run func(context.Context)) (handled bool, err error) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, nil
	}
	return true, svc.Run(serviceName, &agentService{run: run})
}
