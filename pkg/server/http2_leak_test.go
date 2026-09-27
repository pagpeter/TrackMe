package server

import (
	"bytes"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// parsers counts the goroutines still running parseHTTP2.
func parsers() int {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return strings.Count(string(buf[:n]), "server.parseHTTP2(")
}

// serveH2 starts a listener that hands every connection to handleHTTP2, the
// way HandleTLSConnection does once it has read the preface, and reports on
// done when a handler returns.
func serveH2(t *testing.T, srv *Server) (addr string, done chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	done = make(chan struct{}, 64)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				srv.handleHTTP2(conn, nil)
				done <- struct{}{}
			}()
		}
	}()
	return ln.Addr().String(), done
}

// dial opens a connection and sends what a client sends after the preface:
// its SETTINGS and then the given header block on stream 1.
func dial(t *testing.T, addr string, block []byte) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	return conn
}

func requestBlock() []byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":authority", Value: "tls.peet.ws"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/api/clean"},
		{Name: "user-agent", Value: "test"},
	} {
		enc.WriteField(f)
	}
	return buf.Bytes()
}

// waitFor polls until cond holds or the deadline passes.
func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

// Issue #15: every HTTP/2 connection left a goroutine behind. The handler
// stops reading the frame channel once the request's END_STREAM arrives, and
// the parser then blocks for good on its next send, which comes at the latest
// when the closed connection makes ReadFrame fail.
func TestHTTP2ConnectionsDoNotLeaveTheParserBehind(t *testing.T) {
	addr, done := serveH2(t, NewServer())
	before := parsers()

	const conns = 10
	for i := 0; i < conns; i++ {
		conn := dial(t, addr, requestBlock())
		// Read until the server closes, as a client that waits for the
		// response does.
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var sink [4096]byte
		for {
			if _, err := conn.Read(sink[:]); err != nil {
				break
			}
		}
		conn.Close()
	}
	for i := 0; i < conns; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d handlers returned", i, conns)
		}
	}

	if !waitFor(2*time.Second, func() bool { return parsers() == before }) {
		t.Errorf("%d parseHTTP2 goroutines are still running after %d connections finished", parsers()-before, conns)
	}
}

// A header block that does not decode used to end the parser without a word,
// and the handler then waited on the channel for good with the connection
// still open.
func TestAnUndecodableHeaderBlockEndsTheConnection(t *testing.T) {
	addr, done := serveH2(t, NewServer())

	conn := dial(t, addr, []byte{0xff, 0xff, 0xff, 0xff})
	defer conn.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the handler is still waiting for a frame after the parser gave up")
	}
}
