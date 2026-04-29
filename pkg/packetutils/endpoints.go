package packetutils

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// EndpointMetadata holds normalized packet endpoint data for both IPv4 and IPv6.
type EndpointMetadata struct {
	SrcIP     string // Source IP as string (works for both IPv4 and IPv6)
	DstIP     string // Destination IP as string
	IPVersion int    // 4 or 6
	TTL       uint8  // TTL (IPv4) or HopLimit (IPv6)
	HasIP     bool   // Whether a valid IP layer was found
	Protocol  string // "TCP", "UDP", "ICMP", "ICMPv6", or ""
	SrcPort   uint16
	DstPort   uint16
	Payload   []byte
}

// Extract pulls normalized endpoint metadata from a packet, supporting both IPv4 and IPv6.
// If no IP layer is present, HasIP is false and callers should skip processing.
func Extract(packet gopacket.Packet) EndpointMetadata {
	var meta EndpointMetadata

	// Try IPv4 first
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4, _ := ip4Layer.(*layers.IPv4)
		meta.SrcIP = ip4.SrcIP.String()
		meta.DstIP = ip4.DstIP.String()
		meta.IPVersion = 4
		meta.TTL = ip4.TTL
		meta.HasIP = true
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		// Fall back to IPv6
		ip6, _ := ip6Layer.(*layers.IPv6)
		meta.SrcIP = ip6.SrcIP.String()
		meta.DstIP = ip6.DstIP.String()
		meta.IPVersion = 6
		meta.TTL = ip6.HopLimit
		meta.HasIP = true
	} else {
		// Non-IP packet
		return meta
	}

	// Extract transport layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		meta.Protocol = "TCP"
		meta.SrcPort = uint16(tcp.SrcPort)
		meta.DstPort = uint16(tcp.DstPort)
		meta.Payload = tcp.Payload
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		meta.Protocol = "UDP"
		meta.SrcPort = uint16(udp.SrcPort)
		meta.DstPort = uint16(udp.DstPort)
		meta.Payload = udp.Payload
	} else if packet.Layer(layers.LayerTypeICMPv4) != nil {
		meta.Protocol = "ICMP"
	} else if packet.Layer(layers.LayerTypeICMPv6) != nil {
		meta.Protocol = "ICMPv6"
	}

	return meta
}
