package credentials

import (
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func TestExtractor_ScanPacket_Kerberos(t *testing.T) {
	// Path to the provided PCAP sample
	pcapPath, _ := filepath.Abs("../../pcap samples/2018-11-13-UA-CTF-1-of-2.pcap")

	handle, err := pcap.OpenOffline(pcapPath)
	if err != nil {
		t.Fatalf("Failed to open PCAP: %v", err)
	}
	defer handle.Close()

	extractor := NewExtractor()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		extractor.ScanPacket(packet)
	}

	// We expect multiple Kerberos credentials
	// Based on the user's screenshot:
	// User: DNIPROMOTORS.COM\host\lyakh-win7-pc.dnipromotors.com
	// Hash: $krb5pa$18$...

	foundKerberos := false
	for _, cred := range extractor.Credentials {
		if cred.Protocol == "Kerberos" {
			foundKerberos = true
			t.Logf("Found Kerberos Cred: User=%s, Pass=%s", cred.Username, cred.Password)
		}
	}

	if !foundKerberos {
		t.Fatal("Expected to find Kerberos credentials, but found none")
	}
}

func TestExtractor_Synth_Protocols(t *testing.T) {
	extractor := NewExtractor()

	// Helper to create a fake TCP packet
	createPacket := func(srcPort, dstPort int, payload string) gopacket.Packet {
		// Minimal layers to satisfy the parser
		eth := &layers.Ethernet{
			SrcMAC:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
			DstMAC:       []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version:  4,
			IHL:      5,
			SrcIP:    []byte{192, 168, 1, 10},
			DstIP:    []byte{192, 168, 1, 20},
			Protocol: layers.IPProtocolTCP,
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
		}
		tcp.SetNetworkLayerForChecksum(ip)

		// stack them
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		gopacket.SerializeLayers(buf, opts,
			eth,
			ip,
			tcp,
			gopacket.Payload([]byte(payload)),
		)
		return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	}

	// FTP
	extractor.ScanPacket(createPacket(12345, 21, "USER ftpuser"))
	extractor.ScanPacket(createPacket(12345, 21, "PASS ftppass"))

	// POP3
	extractor.ScanPacket(createPacket(12345, 110, "USER popuser"))
	extractor.ScanPacket(createPacket(12345, 110, "PASS poppass"))

	// IMAP
	extractor.ScanPacket(createPacket(12345, 143, "TAG1 LOGIN imapuser imappass"))

	// SMTP - Auth Plain
	// "authuser\0authuser\0authpass" -> YXV0aHVzZXIAYXV0aHVzZXIAYXV0aHBhc3M=
	extractor.ScanPacket(createPacket(12345, 25, "AUTH PLAIN YXV0aHVzZXIAYXV0aHVzZXIAYXV0aHBhc3M="))

	// Check results
	findCred := func(proto, user, pass string) bool {
		for _, c := range extractor.Credentials {
			if c.Protocol == proto && c.Username == user && c.Password == pass {
				return true
			}
		}
		return false
	}

	if !findCred("FTP", "ftpuser", "ftppass") {
		t.Error("Failed to find FTP creds")
	}
	if !findCred("POP3", "popuser", "poppass") {
		t.Error("Failed to find POP3 creds")
	}
	if !findCred("IMAP", "imapuser", "imappass") {
		t.Error("Failed to find IMAP creds")
	}
	if !findCred("SMTP", "authuser", "authpass") {
		t.Error("Failed to find SMTP creds")
	}
}
