//go:build !windows

package sigctx

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// New returns a context cancelled on shutdown signals; dumpStats runs on SIGUSR1 where supported.
func New(parent context.Context, dumpStats func()) (context.Context, context.CancelFunc) {
	ctx, cancel := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	statsCh := make(chan os.Signal, 1)
	signal.Notify(statsCh, syscall.SIGUSR1)
	go func() {
		defer signal.Stop(statsCh)
		for {
			select {
			case <-ctx.Done():
				return
			case <-statsCh:
				dumpStats()
			}
		}
	}()
	return ctx, cancel
}
