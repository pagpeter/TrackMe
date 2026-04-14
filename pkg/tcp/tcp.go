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

var (
	snapshot_len int32         = 1500
	promiscuous  bool          = false
	timeout      time.Duration = 1 * time.Millisecond
)

func optKindName(kind uint8) string {
	switch kind {
	case optKindEOL:
		return "EOL"
	case optKindNOP:
		return "NOP"
	case optKindMSS:
		return "MSS"
	case optKindWindowScale:
		return "WS"
	case optKindSACKPerm:
		return "SACK_PERM"
	case optKindSACK:
		return "SACK"
	case optKindTimestamps:
		return "TS"
	default:
		return fmt.Sprintf("?%d", kind)
	}
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

func parseTCPOptions(options []layers.TCPOption) string {
	if len(options) == 0 {
		return ""
	}

	var parts []string
	for _, opt := range options {
		kind := uint8(opt.OptionType)
		switch kind {
		case optKindEOL:
			parts = append(parts, "EOL")
		case optKindNOP:
			parts = append(parts, "NOP")
		case optKindMSS:
			if len(opt.OptionData) >= 2 {
				mss := binary.BigEndian.Uint16(opt.OptionData[:2])
				parts = append(parts, fmt.Sprintf("MSS:%d", mss))
			} else {
				parts = append(parts, "MSS:?")
			}
		case optKindWindowScale:
			if len(opt.OptionData) >= 1 {
				parts = append(parts, fmt.Sprintf("WS:%d", opt.OptionData[0]))
			} else {
				parts = append(parts, "WS:?")
			}
		case optKindSACKPerm:
			parts = append(parts, "SACK_PERM")
		case optKindSACK:
			parts = append(parts, "SACK")
		case optKindTimestamps:
			if len(opt.OptionData) >= 8 {
				tsVal := binary.BigEndian.Uint32(opt.OptionData[:4])
				tsEcr := binary.BigEndian.Uint32(opt.OptionData[4:8])
				parts = append(parts, fmt.Sprintf("TS:%d:%d", tsVal, tsEcr))
			} else {
				parts = append(parts, "TS:?")
			}
		default:
			parts = append(parts, fmt.Sprintf("?%d", kind))
		}
	}
	return strings.Join(parts, ",")
}

func parseTCPOptionsOrder(options []layers.TCPOption) string {
	if len(options) == 0 {
		return ""
	}

	var parts []string
	for _, opt := range options {
		parts = append(parts, optKindName(uint8(opt.OptionType)))
	}
	return strings.Join(parts, ",")
}

func extractTCPOptionValues(options []layers.TCPOption) (mss, windowScale, timestamp, tsEchoReply int) {
	for _, opt := range options {
		switch uint8(opt.OptionType) {
		case optKindMSS:
			if len(opt.OptionData) >= 2 {
				mss = int(binary.BigEndian.Uint16(opt.OptionData[:2]))
			}
		case optKindWindowScale:
			if len(opt.OptionData) >= 1 {
				windowScale = int(opt.OptionData[0])
			}
		case optKindTimestamps:
			if len(opt.OptionData) >= 8 {
				timestamp = int(binary.BigEndian.Uint32(opt.OptionData[:4]))
				tsEchoReply = int(binary.BigEndian.Uint32(opt.OptionData[4:8]))
			}
		}
	}
	return
}

func SniffTCP(device string, tlsPort int, srv *server.Server) {
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Filter by port — SYN check is done in userspace since
	// tcp[tcpflags] doesn't work for IPv6 in classic BPF.
	filter := fmt.Sprintf("tcp dst port %d", tlsPort)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Printf("Warning: BPF filter failed (%v), falling back to unfiltered capture", err)
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

		// SYN only
		if !tcp.SYN || tcp.ACK {
			continue
		}

		mss, windowScale, timestamp, tsEchoReply := extractTCPOptionValues(tcp.Options)

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
				Options:            parseTCPOptions(tcp.Options),
				OptionsOrder:       parseTCPOptionsOrder(tcp.Options),
				Seq:                int(tcp.Seq),
				Timestamp:          timestamp,
				TimestampEchoReply: tsEchoReply,
				URP:                int(tcp.Urgent),
				Window:             int(tcp.Window),
				WindowScale:        windowScale,
			},
		}

		src := net.JoinHostPort(pack.IP.SrcIP, strconv.Itoa(pack.SrcPort))
		srv.GetTCPFingerprints().Store(src, pack)
	}
}
