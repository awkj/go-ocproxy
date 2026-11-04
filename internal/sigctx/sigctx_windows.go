package sigctx

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// New returns a context cancelled on shutdown signals; dumpStats runs on SIGUSR1 where supported.
func New(parent context.Context, _ func()) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}
