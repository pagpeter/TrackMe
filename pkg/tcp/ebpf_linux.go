//go:build linux

package tcp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/pagpeter/trackme/pkg/server"
	"github.com/pagpeter/trackme/pkg/types"
	"golang.org/x/sys/unix"
)

// Must match struct syn_event in ebpf/syn_capture.h
type synEvent struct {
	SrcAddr       [16]byte
	SrcPort       uint16
	DstPort       uint16
	IPVersion     uint8
	IPTTL         uint8
	IPOptionsLen  uint8
	_             uint8
	TCPWindowSize uint16
	TCPQuirks     uint16
	TCPOptionsLen uint8
	TCPHasPayload uint8
	TCPOptionsRaw [40]byte
	SynTsNs       uint64
}

func SniffEBPF(device string, tlsPort int, srv *server.Server, ebpfObjPath string) {
	if ebpfObjPath == "" {
		ebpfObjPath = "ebpf/syn_capture.o"
	}

	spec, err := ebpf.LoadCollectionSpec(ebpfObjPath)
	if err != nil {
		log.Fatalf("ebpf: failed to load %s: %v", ebpfObjPath, err)
	}

	// .rodata global — avoids per-packet map lookup for port filtering.
	port := uint16(tlsPort)
	if v, ok := spec.Variables["target_port"]; ok {
		if err := v.Set(port); err != nil {
			log.Printf("ebpf: warning: failed to set target_port: %v", err)
		}
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("ebpf: failed to create collection: %v", err)
	}
	defer coll.Close()

	// Try XDP first, fall back to socket filter.
	attached := false
	if xdpProg := coll.Programs["syn_capture_xdp"]; xdpProg != nil {
		iface, err := net.InterfaceByName(device)
		if err == nil {
			xdpLink, err := link.AttachXDP(link.XDPOptions{
				Program:   xdpProg,
				Interface: iface.Index,
			})
			if err == nil {
				defer xdpLink.Close()
				log.Printf("ebpf: XDP attached to %s (port %d)", device, tlsPort)
				attached = true
			} else {
				log.Printf("ebpf: XDP failed, falling back: %v", err)
			}
		}
	}

	if !attached {
		prog := coll.Programs["syn_capture_socket"]
		if prog == nil {
			prog = coll.Programs["syn_capture"]
		}
		if prog == nil {
			log.Fatal("ebpf: no capture program found")
		}

		sock, err := openRawSocket(device)
		if err != nil {
			log.Fatalf("ebpf: raw socket on %s: %v", device, err)
		}
		defer unix.Close(sock)

		if err := unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, prog.FD()); err != nil {
			log.Fatalf("ebpf: attach BPF: %v", err)
		}
		log.Printf("ebpf: socket filter attached to %s (port %d)", device, tlsPort)
	}

	synEvents := coll.Maps["SYN_EVENTS"]
	if synEvents == nil {
		log.Fatal("ebpf: SYN_EVENTS map not found")
	}

	rd, err := ringbuf.NewReader(synEvents)
	if err != nil {
		log.Fatalf("ebpf: ringbuf reader: %v", err)
	}
	defer rd.Close()

	for {
		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			log.Printf("ebpf: ringbuf read: %v", err)
			continue
		}

		const packedSize = 78 // sizeof(struct syn_event)
		if len(record.RawSample) < packedSize {
			continue
		}

		event := decodeSynEvent(record.RawSample)
		details := synEventToDetails(event)

		src := net.JoinHostPort(details.IP.SrcIP, strconv.Itoa(details.SrcPort))
		srv.GetFingerprints().Store(src, details)
	}
}

func openRawSocket(device string) (int, error) {
	proto := htons(unix.ETH_P_ALL)
	sock, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(proto))
	if err != nil {
		return -1, fmt.Errorf("socket: %w", err)
	}

	if device != "" && device != "any" {
		iface, err := net.InterfaceByName(device)
		if err != nil {
			unix.Close(sock)
			return -1, fmt.Errorf("interface %s: %w", device, err)
		}
		sll := unix.SockaddrLinklayer{
			Protocol: proto,
			Ifindex:  iface.Index,
		}
		if err := unix.Bind(sock, &sll); err != nil {
			unix.Close(sock)
			return -1, fmt.Errorf("bind: %w", err)
		}
	}

	return sock, nil
}

func htons(v uint16) uint16 { return (v << 8) | (v >> 8) }

func decodeSynEvent(b []byte) synEvent {
	var e synEvent
	copy(e.SrcAddr[:], b[0:16])
	e.SrcPort = binary.LittleEndian.Uint16(b[16:18])
	e.DstPort = binary.LittleEndian.Uint16(b[18:20])
	e.IPVersion = b[20]
	e.IPTTL = b[21]
	e.IPOptionsLen = b[22]
	e.TCPWindowSize = binary.LittleEndian.Uint16(b[24:26])
	e.TCPQuirks = binary.LittleEndian.Uint16(b[26:28])
	e.TCPOptionsLen = b[28]
	e.TCPHasPayload = b[29]
	copy(e.TCPOptionsRaw[:], b[30:70])
	e.SynTsNs = binary.LittleEndian.Uint64(b[70:78])
	return e
}

func synEventToDetails(e synEvent) types.TCPIPDetails {
	var srcIP string
	if e.IPVersion == 4 {
		srcIP = net.IP(e.SrcAddr[12:16]).String()
	} else {
		srcIP = net.IP(e.SrcAddr[:]).String()
	}

	opts := parseRawOptions(e.TCPOptionsRaw[:e.TCPOptionsLen])
	mss, windowScale, timestamp, tsEchoReply := extractOptionValues(opts)

	return types.TCPIPDetails{
		SrcPort: int(e.SrcPort),
		DstPort: int(e.DstPort),
		IP: types.IPDetails{
			SrcIP:     srcIP,
			TTL:       int(e.IPTTL),
			IPVersion: int(e.IPVersion),
		},
		TCP: types.TCPDetails{
			Window:             int(e.TCPWindowSize),
			MSS:                mss,
			WindowScale:        windowScale,
			Timestamp:          timestamp,
			TimestampEchoReply: tsEchoReply,
			Options:            formatOptions(opts),
			OptionsOrder:       formatOptionsOrder(opts),
			Flags:              0x02,
		},
	}
}
