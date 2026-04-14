//go:build linux

package tcp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/pagpeter/trackme/pkg/server"
	"github.com/pagpeter/trackme/pkg/types"
	"golang.org/x/sys/unix"
)

// Must match struct syn_event in ebpf/syn_capture.c
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

// SniffEBPF captures SYN packets using eBPF instead of pcap.
func SniffEBPF(device string, tlsPort int, srv *server.Server, ebpfObjPath string) {
	if ebpfObjPath == "" {
		ebpfObjPath = "ebpf/syn_capture.o"
	}

	spec, err := ebpf.LoadCollectionSpec(ebpfObjPath)
	if err != nil {
		log.Fatalf("ebpf: failed to load %s: %v", ebpfObjPath, err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("ebpf: failed to create collection: %v", err)
	}
	defer coll.Close()

	// Set port filter
	if targetPortMap, ok := coll.Maps["TARGET_PORT"]; ok {
		port := uint16(tlsPort)
		if err := targetPortMap.Put(uint32(0), port); err != nil {
			log.Printf("ebpf: warning: failed to set TARGET_PORT: %v", err)
		}
	}

	// Prefer socket filter (works everywhere), fall back to TC classifier
	prog := coll.Programs["syn_capture_socket"]
	if prog == nil {
		prog = coll.Programs["syn_capture"]
	}
	if prog == nil {
		log.Fatal("ebpf: no capture program found in object file")
	}

	sock, err := openRawSocket(device)
	if err != nil {
		log.Fatalf("ebpf: failed to open raw socket on %s: %v", device, err)
	}
	defer unix.Close(sock)

	if err := unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, prog.FD()); err != nil {
		log.Fatalf("ebpf: failed to attach BPF to socket: %v", err)
	}

	log.Printf("ebpf: attached SYN capture to %s (port %d)", device, tlsPort)

	synEvents := coll.Maps["SYN_EVENTS"]
	if synEvents == nil {
		log.Fatal("ebpf: map 'SYN_EVENTS' not found")
	}

	rd, err := ringbuf.NewReader(synEvents)
	if err != nil {
		log.Fatalf("ebpf: failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	log.Println("ebpf: reading SYN events")

	for {
		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			log.Printf("ebpf: ringbuf read error: %v", err)
			continue
		}

		// C struct is __attribute__((packed)) = 78 bytes, but Go adds
		// padding before the uint64 field. Parse manually.
		const packedSize = 78
		if len(record.RawSample) < packedSize {
			continue
		}

		event := decodeSynEvent(record.RawSample)
		details := synEventToDetails(event)

		src := net.JoinHostPort(details.IP.SrcIP, strconv.Itoa(details.SrcPort))
		srv.GetTCPFingerprints().Store(src, details)
	}
}

// openRawSocket creates an AF_PACKET socket bound to the given interface.
func openRawSocket(device string) (int, error) {
	sock, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC,
		int(htons(unix.ETH_P_ALL)))
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
			Protocol: htons(unix.ETH_P_ALL),
			Ifindex:  iface.Index,
		}
		if err := unix.Bind(sock, &sll); err != nil {
			unix.Close(sock)
			return -1, fmt.Errorf("bind: %w", err)
		}
	}

	return sock, nil
}

func htons(v uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func decodeSynEvent(b []byte) synEvent {
	var e synEvent
	copy(e.SrcAddr[:], b[0:16])
	e.SrcPort = binary.LittleEndian.Uint16(b[16:18])
	e.DstPort = binary.LittleEndian.Uint16(b[18:20])
	e.IPVersion = b[20]
	e.IPTTL = b[21]
	e.IPOptionsLen = b[22]
	// b[23] = pad
	e.TCPWindowSize = binary.LittleEndian.Uint16(b[24:26])
	e.TCPQuirks = binary.LittleEndian.Uint16(b[26:28])
	e.TCPOptionsLen = b[28]
	e.TCPHasPayload = b[29]
	copy(e.TCPOptionsRaw[:], b[30:70])
	e.SynTsNs = binary.LittleEndian.Uint64(b[70:78])
	return e
}

func synEventToDetails(e synEvent) types.TCPIPDetails {
	srcIP := formatAddr(e.SrcAddr[:], e.IPVersion)

	opts := parseRawTCPOptions(e.TCPOptionsRaw[:e.TCPOptionsLen])

	var mss, windowScale, timestamp, tsEchoReply int
	for _, o := range opts {
		switch o.kind {
		case optKindMSS:
			mss = o.intVal
		case optKindWindowScale:
			windowScale = o.intVal
		case optKindTimestamps:
			timestamp = o.intVal
			tsEchoReply = o.intVal2
		}
	}

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
			Options:            formatParsedOptions(opts),
			OptionsOrder:       formatParsedOptionsOrder(opts),
			Flags:              0x02, // SYN
		},
	}
}

func formatAddr(addr []byte, ipVersion uint8) string {
	if ipVersion == 4 {
		return net.IP(addr[12:16]).String()
	}
	return net.IP(addr).String()
}

type rawOption struct {
	kind    uint8
	length  uint8
	intVal  int
	intVal2 int
}

func parseRawTCPOptions(raw []byte) []rawOption {
	var opts []rawOption
	i := 0
	for i < len(raw) {
		kind := raw[i]
		switch kind {
		case optKindEOL:
			opts = append(opts, rawOption{kind: kind})
			return opts
		case optKindNOP:
			opts = append(opts, rawOption{kind: kind})
			i++
			continue
		default:
			if i+1 >= len(raw) {
				return opts
			}
			optLen := int(raw[i+1])
			if optLen < 2 || i+optLen > len(raw) {
				return opts
			}
			o := rawOption{kind: kind, length: uint8(optLen)}
			data := raw[i+2 : i+optLen]

			switch kind {
			case optKindMSS:
				if len(data) >= 2 {
					o.intVal = int(binary.BigEndian.Uint16(data[:2]))
				}
			case optKindWindowScale:
				if len(data) >= 1 {
					o.intVal = int(data[0])
				}
			case optKindTimestamps:
				if len(data) >= 8 {
					o.intVal = int(binary.BigEndian.Uint32(data[:4]))
					o.intVal2 = int(binary.BigEndian.Uint32(data[4:8]))
				}
			}

			opts = append(opts, o)
			i += optLen
		}
	}
	return opts
}

func formatParsedOptions(opts []rawOption) string {
	var parts []string
	for _, o := range opts {
		switch o.kind {
		case optKindEOL:
			parts = append(parts, "EOL")
		case optKindNOP:
			parts = append(parts, "NOP")
		case optKindMSS:
			parts = append(parts, fmt.Sprintf("MSS:%d", o.intVal))
		case optKindWindowScale:
			parts = append(parts, fmt.Sprintf("WS:%d", o.intVal))
		case optKindSACKPerm:
			parts = append(parts, "SACK_PERM")
		case optKindSACK:
			parts = append(parts, "SACK")
		case optKindTimestamps:
			parts = append(parts, fmt.Sprintf("TS:%d:%d", o.intVal, o.intVal2))
		default:
			parts = append(parts, fmt.Sprintf("?%d", o.kind))
		}
	}
	return strings.Join(parts, ",")
}

func formatParsedOptionsOrder(opts []rawOption) string {
	var parts []string
	for _, o := range opts {
		parts = append(parts, optKindName(o.kind))
	}
	return strings.Join(parts, ",")
}

func EBPFSupported() bool {
	_, err := os.Stat("/sys/fs/bpf")
	return err == nil
}
