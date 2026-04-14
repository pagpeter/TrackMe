//go:build !linux

package tcp

import (
	"log"

	"github.com/pagpeter/trackme/pkg/server"
)

func SniffEBPF(device string, tlsPort int, srv *server.Server, ebpfObjPath string) {
	log.Fatal("ebpf: only supported on Linux, use pcap mode instead")
}

func EBPFSupported() bool {
	return false
}
