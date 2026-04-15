package tcp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pagpeter/trackme/pkg/server"
	"github.com/pagpeter/trackme/pkg/types"
)

const (
	optKindEOL         = 0
	optKindNOP         = 1
	optKindMSS         = 2
	optKindWindowScale = 3
	optKindSACKPerm    = 4
	optKindSACK        = 5
	optKindTimestamps  = 8
)

var optKindNames = [9]string{
	"EOL", "NOP", "MSS", "WS", "SACK_PERM", "SACK", "", "", "TS",
}

type tcpOption struct {
	kind    uint8
	intVal  int
	intVal2 int
}

func optKindName(kind uint8) string {
	if int(kind) < len(optKindNames) && optKindNames[kind] != "" {
		return optKindNames[kind]
	}
	return fmt.Sprintf("?%d", kind)
}

func parseRawOptions(raw []byte) []tcpOption {
	opts := make([]tcpOption, 0, 8)
	i := 0
	for i < len(raw) {
		kind := raw[i]
		switch kind {
		case optKindEOL:
			opts = append(opts, tcpOption{kind: kind})
			return opts
		case optKindNOP:
			opts = append(opts, tcpOption{kind: kind})
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
			o := tcpOption{kind: kind}
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

func gopacketToRaw(options []layers.TCPOption) []byte {
	var buf []byte
	for _, opt := range options {
		kind := uint8(opt.OptionType)
		if kind == optKindEOL {
			buf = append(buf, 0)
			break
		}
		if kind == optKindNOP {
			buf = append(buf, 1)
			continue
		}
		buf = append(buf, kind, opt.OptionLength)
		buf = append(buf, opt.OptionData...)
	}
	return buf
}

func formatOptions(opts []tcpOption) string {
	var b strings.Builder
	b.Grow(len(opts) * 12)
	for i, o := range opts {
		if i > 0 {
			b.WriteByte(',')
		}
		switch o.kind {
		case optKindMSS:
			b.WriteString("MSS:")
			b.WriteString(strconv.Itoa(o.intVal))
		case optKindWindowScale:
			b.WriteString("WS:")
			b.WriteString(strconv.Itoa(o.intVal))
		case optKindTimestamps:
			b.WriteString("TS:")
			b.WriteString(strconv.Itoa(o.intVal))
			b.WriteByte(':')
			b.WriteString(strconv.Itoa(o.intVal2))
		case optKindSACKPerm:
			b.WriteString("SACK_PERM")
		case optKindSACK:
			b.WriteString("SACK")
		case optKindEOL:
			b.WriteString("EOL")
		case optKindNOP:
			b.WriteString("NOP")
		default:
			b.WriteByte('?')
			b.WriteString(strconv.Itoa(int(o.kind)))
		}
	}
	return b.String()
}

func formatOptionsOrder(opts []tcpOption) string {
	var b strings.Builder
	b.Grow(len(opts) * 6)
	for i, o := range opts {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(optKindName(o.kind))
	}
	return b.String()
}

func extractOptionValues(opts []tcpOption) (mss, windowScale, timestamp, tsEchoReply int) {
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
	return
}

func parseIP(packet gopacket.Packet) *types.IPDetails {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)

		df, mf, rf := 0, 0, 0
		if ip.Flags&layers.IPv4DontFragment != 0 {
			df = 1
		}
		if ip.Flags&layers.IPv4MoreFragments != 0 {
			mf = 1
		}
		if ip.Flags&layers.IPv4EvilBit != 0 {
			rf = 1
		}

		return &types.IPDetails{
			DstIp:       ip.DstIP.String(),
			SrcIP:       ip.SrcIP.String(),
			ID:          int(ip.Id),
			TOS:         int(ip.TOS),
			TTL:         int(ip.TTL),
			IPVersion:   4,
			DF:          df,
			MF:          mf,
			RF:          rf,
			HDRLength:   int(ip.IHL * 4),
			TotalLength: int(ip.Length),
			Protocol:    int(ip.Protocol),
			OFF:         int(ip.FragOffset),
		}
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip := ipLayer.(*layers.IPv6)
		return &types.IPDetails{
			DstIp:     ip.DstIP.String(),
			SrcIP:     ip.SrcIP.String(),
			TTL:       int(ip.HopLimit),
			IPVersion: 6,
			PLEN:      int(ip.Length),
			NXT:       int(ip.NextHeader),
		}
	}

	return nil
}

func tcpFlagsToInt(tcp *layers.TCP) int {
	var flags int
	if tcp.FIN {
		flags |= 0x01
	}
	if tcp.SYN {
		flags |= 0x02
	}
	if tcp.RST {
		flags |= 0x04
	}
	if tcp.PSH {
		flags |= 0x08
	}
	if tcp.ACK {
		flags |= 0x10
	}
	if tcp.URG {
		flags |= 0x20
	}
	if tcp.ECE {
		flags |= 0x40
	}
	if tcp.CWR {
		flags |= 0x80
	}
	if tcp.NS {
		flags |= 0x100
	}
	return flags
}

func SniffTCP(device string, tlsPort int, srv *server.Server) {
	var (
		snapshotLen int32         = 256 // SYN with IP opts + TCP opts can reach ~134 bytes
		promiscuous bool          = false
		timeout     time.Duration = 10 * time.Millisecond
	)

	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// SYN-only BPF filter. Parens around the bitmask test are required
	// for portable libpcap parsing; single = is the documented equality op.
	filter := fmt.Sprintf(
		"(tcp dst port %d and (tcp[tcpflags] & (tcp-syn|tcp-ack)) = tcp-syn) or "+
			"(ip6 and tcp dst port %d and (ip6[6+13] & 0x12) = 0x02)",
		tlsPort, tlsPort)
	if err := handle.SetBPFFilter(filter); err != nil {
		filter = fmt.Sprintf("tcp dst port %d", tlsPort)
		if err2 := handle.SetBPFFilter(filter); err2 != nil {
			log.Printf("pcap: BPF filter failed: %v", err2)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		ip := parseIP(packet)
		if ip == nil || ip.IPVersion == 0 {
			continue
		}

		tcp := tcpLayer.(*layers.TCP)

		if !tcp.SYN || tcp.ACK {
			continue
		}

		opts := parseRawOptions(gopacketToRaw(tcp.Options))
		mss, windowScale, timestamp, tsEchoReply := extractOptionValues(opts)

		pack := types.TCPIPDetails{
			CapLen:  packet.Metadata().CaptureLength,
			DstPort: int(tcp.DstPort),
			SrcPort: int(tcp.SrcPort),
			IP:      *ip,
			TCP: types.TCPDetails{
				Ack:                int(tcp.Ack),
				Checksum:           int(tcp.Checksum),
				Flags:              tcpFlagsToInt(tcp),
				HeaderLength:       int(tcp.DataOffset * 4),
				MSS:                mss,
				OFF:                int(tcp.DataOffset),
				Options:            formatOptions(opts),
				OptionsOrder:       formatOptionsOrder(opts),
				Seq:                int(tcp.Seq),
				Timestamp:          timestamp,
				TimestampEchoReply: tsEchoReply,
				URP:                int(tcp.Urgent),
				Window:             int(tcp.Window),
				WindowScale:        windowScale,
			},
		}

		src := net.JoinHostPort(pack.IP.SrcIP, strconv.Itoa(pack.SrcPort))
		srv.GetFingerprints().Store(src, pack)
	}
}
