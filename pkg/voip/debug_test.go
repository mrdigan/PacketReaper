package voip

import (
	"PacketReaper/pkg/pcap"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"strings"
	"testing"
)

func TestDebugVoIP(t *testing.T) {
	filename := `C:\Temp\PacketReaper\pcap samples\VoIP Calls FINAL.pcapng`

	sniffer, err := pcap.OpenFile(filename)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}
	defer sniffer.Close()

	extractor := NewExtractor()
	packetCount := 0
	sipCount := 0

	err = sniffer.Sniff(func(packet gopacket.Packet) {
		packetCount++

		// Debug SIP detection logic
		isUDP := packet.Layer(layers.LayerTypeUDP) != nil
		isTCP := packet.Layer(layers.LayerTypeTCP) != nil

		if isUDP || isTCP {
			// Manually check payload to see if we are missing it via ApplicationLayer()
			var payload []byte
			if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
				payload = tcp.(*layers.TCP).Payload
			} else if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
				payload = udp.(*layers.UDP).Payload
			}

			if len(payload) > 0 {
				content := string(payload)
				if strings.Contains(content, "SIP/2.0") {
					sipCount++
					if packet.ApplicationLayer() == nil {
						fmt.Printf(" Packet %d: Has SIP/2.0 but ApplicationLayer() is NIL\n", packetCount)
					}
				}
			}

			extractor.ScanPacket(packet, packetCount)
		}
	})

	if err != nil {
		t.Fatalf("Sniff error: %v", err)
	}

	calls := extractor.GetCalls()
	fmt.Printf("Total Packets: %d\n", packetCount)
	fmt.Printf("Potential SIP Packets (Raw Scan): %d\n", sipCount)
	fmt.Printf("Extracted Calls: %d\n", len(calls))

	for _, call := range calls {
		fmt.Printf("Call: %s | %s -> %s | State: %s\n", call.ID, call.From, call.To, call.State)
	}
}
