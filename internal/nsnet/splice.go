package nsnet

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
)

// Splice copies bytes in both directions between two connections and returns
// when both directions have ended. It is shared by the two forwarding paths
// (a guest relayed by the gateway, and a host connection dialled into the
// guest) because a splice that forgets half-close breaks protocols that finish
// by sending FIN, and because the two copies of this function would otherwise
// drift apart one direction at a time.
//
// kind names the connection for the log ("tcp relay", "forward"), and aName
// and bName say what each side is ("guest" and "host", or the other way
// round), so a debug line says which way the bytes were going.
func Splice(a, b net.Conn, log *slog.Logger, kind, aName, bName string) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(b, a); err != nil && !errors.Is(err, io.EOF) {
			log.Debug(kind+": copy failed", "from", aName, "to", bName, "err", err)
		}
		closeWrite(b)
	}()
	go func() {
		defer wg.Done()
		if _, err := io.Copy(a, b); err != nil && !errors.Is(err, io.EOF) {
			log.Debug(kind+": copy failed", "from", bName, "to", aName, "err", err)
		}
		closeWrite(a)
	}()
	wg.Wait()
}

// closeWrite shuts down one direction, which is what lets the other direction
// drain instead of being cut off; a connection that cannot half-close is
// closed outright.
func closeWrite(c net.Conn) {
	if hc, ok := c.(interface{ CloseWrite() error }); ok {
		_ = hc.CloseWrite()
		return
	}
	_ = c.Close()
}
