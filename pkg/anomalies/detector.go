package anomalies

import (
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Anomaly represents a detected suspicious activity
type Anomaly struct {
	FrameNumber int      `json:"frame_number"`
	Timestamp   string   `json:"timestamp"`
	Type        string   `json:"type"` // "Unusual Port", "Protocol Violation", etc.
	Severity    Severity `json:"severity"`
	Description string   `json:"description"` // Human-readable explanation
	SourceIP    string   `json:"source_ip"`
	SourcePort  int      `json:"source_port"`
	DestIP      string   `json:"dest_ip"`
	DestPort    int      `json:"dest_port"`
	Protocol    string   `json:"protocol"`
	Details     string   `json:"details"` // Additional context
}

// Detector scans packets for anomalous behavior
type Detector struct {
	mu         sync.Mutex
	Anomalies  []Anomaly
	dnsQueries map[string]int   // Track DNS query frequency per domain
	trafficVol map[string]int64 // Track traffic volume per IP
}

// NewDetector creates a new anomaly detector
func NewDetector() *Detector {
	return &Detector{
		Anomalies:  []Anomaly{},
		dnsQueries: make(map[string]int),
		trafficVol: make(map[string]int64),
	}
}

// ScanPacket analyzes a packet for anomalies
func (d *Detector) ScanPacket(packet gopacket.Packet, frameNum int) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}

	ip, _ := ipLayer.(*layers.IPv4)
	timestamp := packet.Metadata().Timestamp.Format("15:04:05")
	srcIP := ip.SrcIP.String()
	dstIP := ip.DstIP.String()

	d.mu.Lock()
	defer d.mu.Unlock()

	// Track traffic volume
	d.trafficVol[srcIP] += int64(len(packet.Data()))
	d.trafficVol[dstIP] += int64(len(packet.Data()))

	// Check for traffic anomalies
	if anomaly := d.detectTrafficAnomaly(srcIP, dstIP, int64(len(packet.Data())), frameNum, timestamp); anomaly != nil {
		d.Anomalies = append(d.Anomalies, *anomaly)
	}

	// TCP analysis
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort := int(tcp.SrcPort)
		dstPort := int(tcp.DstPort)

		// Unusual port detection
		if anomaly := d.detectUnusualPort(srcPort, dstPort, "TCP", frameNum, timestamp, srcIP, dstIP); anomaly != nil {
			d.Anomalies = append(d.Anomalies, *anomaly)
		}

		// HTTP analysis
		if len(tcp.Payload) > 0 {
			payload := string(tcp.Payload)

			// Suspicious user-agent
			if strings.Contains(payload, "User-Agent:") {
				if anomaly := d.detectSuspiciousUserAgent(payload, srcIP, dstPort, frameNum, timestamp, dstIP); anomaly != nil {
					d.Anomalies = append(d.Anomalies, *anomaly)
				}
			}

			// Cleartext credentials on unusual ports
			if strings.Contains(payload, "Authorization: Basic") || strings.Contains(payload, "USER ") || strings.Contains(payload, "PASS ") {
				if anomaly := d.detectCleartextCredentials(dstPort, "TCP", frameNum, timestamp, srcIP, srcPort, dstIP); anomaly != nil {
					d.Anomalies = append(d.Anomalies, *anomaly)
				}
			}

			// Suspicious patterns (SQL injection, path traversal, etc.)
			if isSus, pattern := ContainsSuspiciousPattern(payload); isSus {
				d.Anomalies = append(d.Anomalies, Anomaly{
					FrameNumber: frameNum,
					Timestamp:   timestamp,
					Type:        "Suspicious Pattern",
					Severity:    SeverityHigh,
					Description: fmt.Sprintf("Potential attack pattern detected: %s", pattern),
					SourceIP:    srcIP,
					SourcePort:  srcPort,
					DestIP:      dstIP,
					DestPort:    dstPort,
					Protocol:    "TCP",
					Details:     "Possible web attack or exploitation attempt",
				})
			}
		}
	}

	// UDP analysis
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort := int(udp.SrcPort)
		dstPort := int(udp.DstPort)

		// DNS analysis
		if dstPort == 53 || srcPort == 53 {
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				dns, _ := dnsLayer.(*layers.DNS)
				for _, q := range dns.Questions {
					domain := string(q.Name)
					d.dnsQueries[domain]++

					// DGA detection
					if anomaly := d.detectDGA(domain, srcIP, frameNum, timestamp, dstIP); anomaly != nil {
						d.Anomalies = append(d.Anomalies, *anomaly)
					}
				}

				// DNS tunneling detection (large TXT records)
				for _, ans := range dns.Answers {
					if ans.Type == layers.DNSTypeTXT && len(ans.TXT) > 0 {
						txtData := string(ans.TXT)
						if len(txtData) > DNSTxtMaxNormalSize {
							d.Anomalies = append(d.Anomalies, Anomaly{
								FrameNumber: frameNum,
								Timestamp:   timestamp,
								Type:        "DNS Tunneling",
								Severity:    SeverityHigh,
								Description: fmt.Sprintf("Large DNS TXT record (%d bytes)", len(txtData)),
								SourceIP:    srcIP,
								SourcePort:  srcPort,
								DestIP:      dstIP,
								DestPort:    dstPort,
								Protocol:    "DNS",
								Details:     "Possible data exfiltration via DNS",
							})
						}
					}
				}
			}
		}

		// Unusual port detection for UDP
		if anomaly := d.detectUnusualPort(srcPort, dstPort, "UDP", frameNum, timestamp, srcIP, dstIP); anomaly != nil {
			d.Anomalies = append(d.Anomalies, *anomaly)
		}
	}

	// ICMP analysis
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)

		// ICMP tunneling detection (large payloads)
		if len(icmp.Payload) > ICMPMaxNormalSize {
			d.Anomalies = append(d.Anomalies, Anomaly{
				FrameNumber: frameNum,
				Timestamp:   timestamp,
				Type:        "ICMP Tunneling",
				Severity:    SeverityHigh,
				Description: fmt.Sprintf("Large ICMP payload (%d bytes)", len(icmp.Payload)),
				SourceIP:    srcIP,
				SourcePort:  0,
				DestIP:      dstIP,
				DestPort:    0,
				Protocol:    "ICMP",
				Details:     "Possible data exfiltration via ICMP",
			})
		}
	}
}

// detectUnusualPort checks for services on non-standard ports
func (d *Detector) detectUnusualPort(srcPort, dstPort int, protocol string, frameNum int, timestamp, srcIP, dstIP string) *Anomaly {
	// Check if well-known service is on unusual port
	if dstPort == 8080 || dstPort == 8443 || dstPort == 8888 {
		return &Anomaly{
			FrameNumber: frameNum,
			Timestamp:   timestamp,
			Type:        "Unusual Port",
			Severity:    SeverityLow,
			Description: fmt.Sprintf("%s service on alternative port %d", protocol, dstPort),
			SourceIP:    srcIP,
			SourcePort:  srcPort,
			DestIP:      dstIP,
			DestPort:    dstPort,
			Protocol:    protocol,
			Details:     "Common alternative port, likely legitimate",
		}
	}

	// High-numbered ephemeral ports (>49152) used as destination
	if dstPort > 49152 && protocol == "TCP" {
		return &Anomaly{
			FrameNumber: frameNum,
			Timestamp:   timestamp,
			Type:        "Unusual Port",
			Severity:    SeverityLow,
			Description: fmt.Sprintf("Service on ephemeral port %d", dstPort),
			SourceIP:    srcIP,
			SourcePort:  srcPort,
			DestIP:      dstIP,
			DestPort:    dstPort,
			Protocol:    protocol,
			Details:     "May indicate non-standard service or P2P",
		}
	}

	return nil
}

// detectSuspiciousUserAgent checks for known malicious/scanning user-agents
func (d *Detector) detectSuspiciousUserAgent(payload, srcIP string, dstPort, frameNum int, timestamp, dstIP string) *Anomaly {
	if isSus, agent := IsSuspiciousUserAgent(payload); isSus {
		return &Anomaly{
			FrameNumber: frameNum,
			Timestamp:   timestamp,
			Type:        "Suspicious User-Agent",
			Severity:    SeverityMedium,
			Description: fmt.Sprintf("Known scanning/malware user-agent: %s", agent),
			SourceIP:    srcIP,
			SourcePort:  0, // Not always available in payload
			DestIP:      dstIP,
			DestPort:    dstPort,
			Protocol:    "HTTP",
			Details:     "Commonly used by automated tools, scripts, or malware",
		}
	}
	return nil
}

// detectCleartextCredentials checks for authentication on unusual ports
func (d *Detector) detectCleartextCredentials(port int, protocol string, frameNum int, timestamp, srcIP string, srcPort int, dstIP string) *Anomaly {
	// HTTP Basic Auth on non-standard ports
	if !IsStandardPort(port, "HTTP") && !IsStandardPort(port, "HTTPS") && port != 8080 && port != 8443 {
		return &Anomaly{
			FrameNumber: frameNum,
			Timestamp:   timestamp,
			Type:        "Cleartext Credentials",
			Severity:    SeverityCritical,
			Description: fmt.Sprintf("Authentication on non-standard port %d", port),
			SourceIP:    srcIP,
			SourcePort:  srcPort,
			DestIP:      dstIP,
			DestPort:    port,
			Protocol:    protocol,
			Details:     "Credentials transmitted over potentially insecure channel",
		}
	}
	return nil
}

// detectDGA uses Shannon entropy to detect domain generation algorithms
func (d *Detector) detectDGA(domain, srcIP string, frameNum int, timestamp, dstIP string) *Anomaly {
	// Remove TLD for entropy calculation
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return nil
	}

	// Check subdomain or main domain
	domainPart := parts[0]
	if len(domainPart) < 6 {
		return nil // Too short to be meaningful
	}

	entropy := calculateEntropy(domainPart)

	if entropy > DGAEntropyThreshold {
		return &Anomaly{
			FrameNumber: frameNum,
			Timestamp:   timestamp,
			Type:        "DGA Domain",
			Severity:    SeverityHigh,
			Description: fmt.Sprintf("High-entropy domain: %s (entropy: %.2f)", domain, entropy),
			SourceIP:    srcIP,
			SourcePort:  0,
			DestIP:      dstIP,
			DestPort:    53,
			Protocol:    "DNS",
			Details:     "Possible Domain Generation Algorithm (malware C2)",
		}
	}

	return nil
}

// detectTrafficAnomaly checks for unusual traffic patterns
func (d *Detector) detectTrafficAnomaly(srcIP, dstIP string, size int64, frameNum int, timestamp string) *Anomaly {
	// Check if total traffic from IP exceeds threshold
	if d.trafficVol[srcIP] > HighTrafficThreshold {
		// Only report once per IP
		if d.trafficVol[srcIP]-size <= HighTrafficThreshold {
			return &Anomaly{
				FrameNumber: frameNum,
				Timestamp:   timestamp,
				Type:        "High Traffic Volume",
				Severity:    SeverityMedium,
				Description: fmt.Sprintf("IP %s has sent >10MB of data", srcIP),
				SourceIP:    srcIP,
				SourcePort:  0,
				DestIP:      dstIP,
				DestPort:    0,
				Protocol:    "IP",
				Details:     "Possible data exfiltration or bulk transfer",
			}
		}
	}

	// Check for very large packets
	if size > LargePacketThreshold {
		return &Anomaly{
			FrameNumber: frameNum,
			Timestamp:   timestamp,
			Type:        "Large Packet",
			Severity:    SeverityLow,
			Description: fmt.Sprintf("Packet size %d bytes exceeds MTU", size),
			SourceIP:    srcIP,
			SourcePort:  0,
			DestIP:      dstIP,
			DestPort:    0,
			Protocol:    "IP",
			Details:     "Possible fragmentation or tunneling",
		}
	}

	return nil
}

// calculateEntropy computes Shannon entropy of a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, c := range strings.ToLower(s) {
		freq[c]++
	}

	entropy := 0.0
	length := float64(len(s))

	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// FlagCertificateIssue flags a certificate security issue as an anomaly
func (d *Detector) FlagCertificateIssue(serverIP string, serverPort int, certSubject string, issueType string, severity Severity, details string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	anomaly := Anomaly{
		FrameNumber: 0, // Certificate issues don't tie to single frame
		Timestamp:   "",
		Type:        issueType,
		Severity:    severity,
		Description: fmt.Sprintf("Certificate issue detected for %s", certSubject),
		SourceIP:    "",
		SourcePort:  0,
		DestIP:      serverIP,
		DestPort:    serverPort,
		Protocol:    "TLS",
		Details:     details,
	}

	d.Anomalies = append(d.Anomalies, anomaly)
}
