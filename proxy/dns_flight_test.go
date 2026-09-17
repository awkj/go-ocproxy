package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestDNSFlightsCoalesceConcurrentMisses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var group dnsLookupGroup
		var queries atomic.Int64
		gate := make(chan struct{})
		lookup := func(context.Context) (net.IP, error) {
			queries.Add(1)
			<-gate
			return net.IPv4(1, 2, 3, 4), nil
		}
		var wg sync.WaitGroup
		for range 64 {
			wg.Go(func() {
				ip, err := group.do(context.Background(), "same.example", lookup)
				if err != nil || !ip.Equal(net.IPv4(1, 2, 3, 4)) {
					t.Errorf("lookup: %v, %v", ip, err)
				}
			})
		}
		synctest.Wait()
		if queries.Load() != 1 {
			t.Fatalf("upstream queries = %d, want 1", queries.Load())
		}
		close(gate)
		wg.Wait()
		// Completed flights are not a cache: TTL=0 must allow a fresh lookup.
		_, _ = group.do(context.Background(), "same.example", lookup)
		if queries.Load() != 2 {
			t.Fatalf("fresh queries = %d, want 2", queries.Load())
		}
	})
}

func TestDNSFlightsOneCancellationDoesNotCancelOtherWaiter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var group dnsLookupGroup
		gate := make(chan struct{})
		lookup := func(ctx context.Context) (net.IP, error) {
			select {
			case <-gate:
				return net.IPv4(1, 2, 3, 4), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		first, second := make(chan error, 1), make(chan error, 1)
		go func() { _, err := group.do(ctx, "same.example", lookup); first <- err }()
		synctest.Wait()
		go func() { _, err := group.do(context.Background(), "same.example", lookup); second <- err }()
		synctest.Wait()
		cancel()
		if !errors.Is(<-first, context.Canceled) {
			t.Fatal("first waiter did not cancel")
		}
		close(gate)
		if err := <-second; err != nil {
			t.Fatalf("second waiter: %v", err)
		}
	})
}

func TestDNSFlightsLastCancellationCancelsQueryAndAllowsRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var group dnsLookupGroup
		ctx, cancel := context.WithCancel(context.Background())
		queryStopped := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			_, err := group.do(ctx, "same.example", func(queryCtx context.Context) (net.IP, error) {
				<-queryCtx.Done()
				close(queryStopped)
				return nil, queryCtx.Err()
			})
			done <- err
		}()
		synctest.Wait()
		cancel()
		if !errors.Is(<-done, context.Canceled) {
			t.Fatal("waiter did not cancel")
		}
		<-queryStopped
		ip, err := group.do(context.Background(), "same.example", func(context.Context) (net.IP, error) { return net.IPv4(1, 2, 3, 4), nil })
		if err != nil || ip == nil {
			t.Fatalf("retry: %v, %v", ip, err)
		}
	})
}

func TestDNSFlightsDifferentNamesAndBoundedLifetime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var group dnsLookupGroup
		done := make(chan error, 1)
		go func() {
			_, err := group.do(context.Background(), "slow.example", func(ctx context.Context) (net.IP, error) { <-ctx.Done(); return nil, ctx.Err() })
			done <- err
		}()
		synctest.Wait()
		_, err := group.do(context.Background(), "fast.example", func(context.Context) (net.IP, error) { return net.IPv4(1, 2, 3, 4), nil })
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(socksDialTimeout)
		if !errors.Is(<-done, context.DeadlineExceeded) {
			t.Fatal("unbounded DNS query")
		}
	})
}

func TestCancelledDNSDoesNotPoisonNegativeCache(t *testing.T) {
	s := NewServer(nil, "", nil, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.resolveUncached(ctx, "cancelled.example")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lookup: %v", err)
	}
	if _, found, _ := s.cache.get("cancelled.example"); found {
		t.Fatal("cancelled lookup was cached")
	}
}

func TestDNSFlightsOldCancellationCannotRemoveNewFlight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var group dnsLookupGroup
		ctx, cancel := context.WithCancel(context.Background())
		oldGate, newGate := make(chan struct{}), make(chan struct{})
		oldDone := make(chan error, 1)
		go func() {
			_, err := group.do(ctx, "same.example", func(ctx context.Context) (net.IP, error) {
				<-ctx.Done()
				<-oldGate // Simulate I/O completing late after cancellation.
				return nil, ctx.Err()
			})
			oldDone <- err
		}()
		synctest.Wait()
		cancel()
		<-oldDone
		var queries atomic.Int64
		lookup := func(context.Context) (net.IP, error) { queries.Add(1); <-newGate; return net.IPv4(1, 2, 3, 4), nil }
		var wg sync.WaitGroup
		wg.Go(func() { _, _ = group.do(context.Background(), "same.example", lookup) })
		synctest.Wait()
		close(oldGate)
		synctest.Wait()
		wg.Go(func() { _, _ = group.do(context.Background(), "same.example", lookup) })
		synctest.Wait()
		if queries.Load() != 1 {
			t.Fatalf("late old completion removed new flight: %d queries", queries.Load())
		}
		close(newGate)
		wg.Wait()
	})
}

func TestDNSFlightsPanicIsIsolated(t *testing.T) {
	var group dnsLookupGroup
	_, err := group.do(context.Background(), "panic.example", func(context.Context) (net.IP, error) { panic("scripted failure") })
	if err == nil {
		t.Fatal("lookup panic was not reported")
	}
	_, err = group.do(context.Background(), "panic.example", func(context.Context) (net.IP, error) { return net.IPv4(1, 2, 3, 4), nil })
	if err != nil {
		t.Fatalf("panic prevented retry: %v", err)
	}
}

func TestDNSFailureCachePolicy(t *testing.T) {
	for _, err := range []error{nil, context.Canceled, context.DeadlineExceeded, &net.DNSError{Err: "timeout", IsTimeout: true}, errors.Join(errors.New("UDP failed"), context.DeadlineExceeded)} {
		if cacheableDNSFailure(err) {
			t.Errorf("transient/cancelled result cached: %v", err)
		}
	}
	if !cacheableDNSFailure(errors.New("NXDOMAIN")) {
		t.Fatal("ordinary DNS failure should use short negative cache")
	}
}
