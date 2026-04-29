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

func TestExtractor_Kerberos_Synthetic(t *testing.T) {
	extractor := NewExtractor()

	createTCPPacket := func(srcPort, dstPort int, payload []byte) gopacket.Packet {
		eth := &layers.Ethernet{SrcMAC: []byte{0, 0, 0, 0, 0, 1}, DstMAC: []byte{0, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, IHL: 5, SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2}, Protocol: layers.IPProtocolTCP}
		tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort)}
		tcp.SetNetworkLayerForChecksum(ip)
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload))
		return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	}

	// 2. TCP payload shorter than 4 bytes
	extractor.ScanPacket(createTCPPacket(12345, 88, []byte{0x00, 0x00, 0x00}))
	if len(extractor.Credentials) != 0 {
		t.Error("Expected 0 creds for short TCP payload")
	}

	// 3. Port 8088 or 1883 traffic
	extractor.ScanPacket(createTCPPacket(12345, 8088, []byte("\x6a\x43\x30\x41"))) // Dummy valid-looking kerberos start
	extractor.ScanPacket(createTCPPacket(12345, 1883, []byte("\x6a\x43\x30\x41")))
	if len(extractor.Credentials) != 0 {
		t.Error("Expected 0 creds for non-88 ports")
	}

	// 4. Test Exact Numeric Matching (No Substring False Positives)
	// Telnet false positive (23 in 12323)
	extractor.ScanPacket(createTCPPacket(12345, 12323, []byte("login: falsepositive")))
	
	// FTP false positive (21 in 2100)
	extractor.ScanPacket(createTCPPacket(12345, 2100, []byte("USER ftpuser")))
	
	// POP3 false positive (110 in 25110)
	extractor.ScanPacket(createTCPPacket(12345, 25110, []byte("USER popuser")))
	
	// IMAP false positive (143 in 1433)
	extractor.ScanPacket(createTCPPacket(12345, 1433, []byte("TAG1 LOGIN imapuser imappass")))
	
	// SMTP false positive (25 in 2525)
	extractor.ScanPacket(createTCPPacket(12345, 2525, []byte("AUTH PLAIN YXV0aHVzZXIAYXV0aHVzZXIAYXV0aHBhc3M=")))

	if len(extractor.Credentials) != 0 {
		t.Errorf("Expected 0 creds for substring port matches, got %d", len(extractor.Credentials))
	}
}
