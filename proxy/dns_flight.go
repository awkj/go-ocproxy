package proxy

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sync"
)

// A flight is shared only while a lookup is running, never as an extra cache.
// Caller cancellation is independent; the last departing caller cancels I/O.
type dnsLookupGroup struct {
	mu      sync.Mutex
	flights map[string]*dnsLookup
}

type dnsLookup struct {
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int
	ip      net.IP
	err     error
}

func (g *dnsLookupGroup) do(ctx context.Context, name string, lookup func(context.Context) (net.IP, error)) (net.IP, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	g.mu.Lock()
	if g.flights == nil {
		g.flights = make(map[string]*dnsLookup)
	}
	flight := g.flights[name]
	if flight == nil {
		queryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), socksDialTimeout)
		flight = &dnsLookup{done: make(chan struct{}), cancel: cancel}
		g.flights[name] = flight
		go g.run(queryCtx, name, flight, lookup)
	}
	flight.waiters++
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		flight.waiters--
		if flight.waiters == 0 && g.flights[name] == flight {
			delete(g.flights, name)
			flight.cancel()
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-flight.done:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return slices.Clone(flight.ip), flight.err
	}
}

func (g *dnsLookupGroup) run(ctx context.Context, name string, flight *dnsLookup, lookup func(context.Context) (net.IP, error)) {
	defer func() {
		// Preserve the server's per-connection panic isolation even though lookup
		// now runs in a separate goroutine.
		if recovered := recover(); recovered != nil {
			flight.err = fmt.Errorf("dns lookup panic: %v", recovered)
		}
		flight.cancel()
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.flights[name] == flight {
			delete(g.flights, name)
		}
		close(flight.done)
	}()
	flight.ip, flight.err = lookup(ctx)
}
