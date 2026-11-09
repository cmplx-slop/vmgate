package engine

import (
	"time"

	"github.com/cmplx-slop/vmgate/internal/svc"
)

// options collects the optional knobs New understands.
type options struct {
	dialer        svc.Dialer
	relayIdle     time.Duration
	maxConns      int
	maxPathsTotal int
}

// Option customises an engine. Four of these exist for tests rather than for
// cmd/vmgate, which sets everything through the configuration file; they stay
// exported because the tests drive the engine the way a caller would, from
// outside the package.
type Option func(*options)

// WithDialer replaces the dialer used for host side sockets. Tests point the
// "internet" at local listeners with it.
func WithDialer(d svc.Dialer) Option {
	return func(o *options) { o.dialer = d }
}

// WithRelayIdle shortens how long an unused on-demand relay is kept. The
// default suits a running gateway; tests need something faster.
func WithRelayIdle(d time.Duration) Option {
	return func(o *options) { o.relayIdle = d }
}

// WithMaxConns caps how many translations one gateway runs at once.
func WithMaxConns(n int) Option {
	return func(o *options) { o.maxConns = n }
}

// WithMaxPathsTotal caps how many datagram paths one gateway holds open at
// once, across every relay: the per-relay limit alone multiplies into what the
// host pays for in sockets.
func WithMaxPathsTotal(n int) Option {
	return func(o *options) { o.maxPathsTotal = n }
}
