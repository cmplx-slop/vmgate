package nsnet

import (
	"log/slog"
	"runtime/debug"
)

// Guard is the deferred call that keeps a panic inside the goroutine that met
// it. It belongs with these helpers because the panics worth expecting come from
// reading the stack: the netstack demands that a writer which reports no error
// took the whole packet, and panics otherwise, which is exactly what one
// oversized datagram from a guest used to do to every other guest's gateway
// (see sliceWriter in udp.go). Whatever shape trips the next invariant, the
// honest unit of recovery is the one flow that met it: the defers already running
// close what that flow was holding, the budget it claimed is given back, and the
// stack is written down rather than swallowed. A gateway that carries on without
// saying anything would be hiding the bug rather than surviving it.
//
// Use it on a goroutine that reads packets, not around everything: a panic in
// code that builds the gateway is a reason to stop, not to continue.
func Guard(log *slog.Logger, what string) {
	p := recover()
	if p == nil {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	log.Error("panic recovered", "where", what, "panic", p,
		"stack", string(debug.Stack()))
}
