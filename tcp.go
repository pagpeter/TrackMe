package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device string = "eth0"
	// device       string = "en0"
	snapshot_len int32 = 1024
	promiscuous  bool  = false
	err          error
	timeout      time.Duration = 1 * time.Millisecond
	handle       *pcap.Handle
)

type IPDetails struct {
	DF          int    `json:"df,omitempty"`
	HDRLength   int    `json:"hdr_length,omitempty"`
	ID          int    `json:"id,omitempty"`
	MF          int    `json:"mf,omitempty"`
	NXT         int    `json:"nxt,omitempty"`
	OFF         int    `json:"off,omitempty"`
	PLEN        int    `json:"plen,omitempty"`
	Protocol    int    `json:"protocol,omitempty"`
	RF          int    `json:"rf,omitempty"`
	TOS         int    `json:"tos,omitempty"`
	TotalLength int    `json:"total_length,omitempty"`
	TTL         int    `json:"ttl,omitempty"`
	IPVersion   int    `json:"ip_version,omitempty"`
	DstIp       string `json:"dst_ip,omitempty"`
	SrcIP       string `json:"src_ip,omitempty"`
}
type TCPDetails struct {
	Ack                int    `json:"ack,omitempty"`
	Checksum           int    `json:"checksum,omitempty"`
	Flags              int    `json:"flags,omitempty"`
	HeaderLength       int    `json:"header_length,omitempty"`
	MSS                int    `json:"mss,omitempty"`
	OFF                int    `json:"off,omitempty"`
	Options            string `json:"options,omitempty"`
	OptionsOrder       string `json:"options_order,omitempty"`
	Seq                int    `json:"seq,omitempty"`
	Timestamp          int    `json:"timestamp,omitempty"`
	TimestampEchoReply int    `json:"timestamp_echo_reply,omitempty"`
	URP                int    `json:"urp,omitempty"`
	Window             int    `json:"window,omitempty"`
	// WindowSize         int    `json:"window_size,omitempty"`
}
type TCPIPDetails struct {
	CapLen    int        `json:"cap_length,omitempty"`
	DstPort   int        `json:"dst_port,omitempty"`
	SrcPort   int        `json:"src_port,omitempty"`
	HeaderLen int        `json:"header_length,omitempty"`
	TS        []int      `json:"ts,omitempty"`
	IP        IPDetails  `json:"ip,omitempty"`
	TCP       TCPDetails `json:"tcp,omitempty"`
}

// func devices() {
// 	// Find all devices
// 	devices, err := pcap.FindAllDevs()
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	// Print device information
// 	fmt.Println("Devices found:")
// 	for _, device := range devices {
// 		fmt.Println("\nName: ", device.Name)
// 		fmt.Println("Description: ", device.Description)
// 		fmt.Println("Devices addresses: ", device.Description)
// 		for _, address := range device.Addresses {
// 			fmt.Println("- IP address: ", address.IP)
// 			fmt.Println("- Subnet mask: ", address.Netmask)
// 		}
// 	}
// }

func parseIP(packet gopacket.Packet) *IPDetails {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer == nil {
		if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer == nil {
			// fmt.Println("Returning - no ip layer")
			return nil
		} else {
			// IPv6
			ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			return &IPDetails{
				DstIp:     ip.DstIP.String(),
				SrcIP:     ip.SrcIP.String(),
				TTL:       int(ip.HopLimit),
				IPVersion: 6,
			}
		}

	} else {
		// IPv4
		ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		return &IPDetails{
			DstIp:     ip.DstIP.String(),
			SrcIP:     ip.SrcIP.String(),
			ID:        int(ip.Id),
			TOS:       int(ip.TOS),
			TTL:       int(ip.TTL),
			IPVersion: 4,
		}
	}
}

func sniffTCP() {
	// devices()
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {

			ip := parseIP(packet) //
			tcp := tcpLayer.(*layers.TCP)
			if !tcp.ACK || tcp.DstPort != 443 || ip.IPVersion == 0 {
				continue
			}
			// Process packet here

			// fmt.Println("TCP Packet!", tcp.Seq, ip.TTL)
			pack := TCPIPDetails{
				CapLen:  packet.Metadata().CaptureLength,
				DstPort: int(tcp.DstPort),
				// HeaderLen: ,
				SrcPort: int(tcp.SrcPort),
				// TS: ,
				IP: *ip,
				TCP: TCPDetails{
					Ack:      int(tcp.Ack),
					Checksum: int(tcp.Checksum),
					// Flags              int
					// Flags: tcp.,
					// HeaderLength       int
					// MSS                int
					// MSS: tcp.
					// OFF                int
					Options:      parseTCPOptions(tcp.Options),
					OptionsOrder: parseTCPOptionsOrder(tcp.Options),
					// Seq                int
					Seq: int(tcp.Seq),
					// TimestampEchoReply int
					// URP                int
					Window: int(tcp.Window),
					// WindowSize         int

				},
			}
			src := fmt.Sprintf("%s:%v", pack.IP.SrcIP, pack.SrcPort)
			// dst := fmt.Sprintf("%s:%v", pack.IP.DstIp, pack.DstPort)
			// fmt.Printf("TCP Packet %v -> %v\n", src, dst)
			TCPFingerprints[src] = pack
		}
	}
}

func parseTCPOptions(TCPOption []layers.TCPOption) string {
	// for _, opt := range TCPOption {
	// 	 fmt.Println("OPTION:", opt.OptionType.String(), opt.String())
	// }
	return ""
}

func parseTCPOptionsOrder(TCPOption []layers.TCPOption) string {
	return ""
}
