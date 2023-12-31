package cmd

import (
	"context"
	"os"
	"os/exec"
	"syscall"
)

// Type of service signals currently supported.
type serviceSignal int

const (
	serviceRestart       serviceSignal = iota // Restarts the server.
	serviceStop                               // Stops the server.
	serviceReloadDynamic                      // Reload dynamic config values.
	// Add new service requests here.
)

// Global service signal channel.
var globalServiceSignalCh chan serviceSignal

// GlobalServiceDoneCh - Global service done channel.
var GlobalServiceDoneCh <-chan struct{}

// GlobalContext context that is canceled when server is requested to shut down.
var GlobalContext context.Context

// cancelGlobalContext can be used to indicate server shutdown.
var cancelGlobalContext context.CancelFunc

func initGlobalContext() {
	GlobalContext, cancelGlobalContext = context.WithCancel(context.Background())
	GlobalServiceDoneCh = GlobalContext.Done()
	globalServiceSignalCh = make(chan serviceSignal)
}

// restartProcess starts a new process passing it the active fd's. It
// doesn't fork, but starts a new process using the same environment and
// arguments as when it was originally started. This allows for a newly
// deployed binary to be started. It returns the pid of the newly started
// process when successful.
func restartProcess() error {
	// Use the original binary location. This works with symlinks such that if
	// the file it points to has been changed we will use the updated symlink.
	argv0, err := exec.LookPath(os.Args[0])
	if err != nil {
		return err
	}

	// Invokes the execve system call.
	// Re-uses the same pid. This preserves the pid over multiple server-respawns.
	return syscall.Exec(argv0, os.Args, os.Environ())
}
