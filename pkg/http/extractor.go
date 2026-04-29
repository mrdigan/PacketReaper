package http

import (
	"strings"
	"sync"

	"PacketReaper/pkg/packetutils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Transaction represents an HTTP request/response transaction
type Transaction struct {
	Timestamp string `json:"timestamp"`
	FrameNum  int    `json:"frame_num"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DstIP     string `json:"dst_ip"`
	DstPort   int    `json:"dst_port"`
	Method    string `json:"method"`
	URL       string `json:"url"` // Full URL
	Host      string `json:"host"`
	UserAgent string `json:"user_agent"`
	Referer   string `json:"referer"`
	Cookie    string `json:"cookie"` // Truncated/summarized
}

// Extractor scans packets for HTTP transactions
type Extractor struct {
	mu           sync.Mutex
	Transactions []Transaction
}

func NewExtractor() *Extractor {
	return &Extractor{
		Transactions: []Transaction{},
	}
}

// ScanPacket analyzes a packet for HTTP attributes
func (e *Extractor) ScanPacket(packet gopacket.Packet, frameNum int) {
	ep := packetutils.Extract(packet)
	if !ep.HasIP || ep.Protocol != "TCP" || len(ep.Payload) == 0 {
		return
	}

	payload := string(ep.Payload)

	// Quick check for HTTP methods to identify requests
	if !strings.HasPrefix(payload, "GET ") &&
		!strings.HasPrefix(payload, "POST ") &&
		!strings.HasPrefix(payload, "PUT ") &&
		!strings.HasPrefix(payload, "HEAD ") &&
		!strings.HasPrefix(payload, "DELETE ") {
		return
	}

	// Grab TCP layer just for port numbers (needed for display)
	var srcPort, dstPort int
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = int(tcp.SrcPort)
		dstPort = int(tcp.DstPort)
	}

	e.extractTransaction(payload, packet, frameNum, ep.SrcIP, ep.DstIP, srcPort, dstPort)
}

func (e *Extractor) extractTransaction(payload string, packet gopacket.Packet, frameNum int, srcIP, dstIP string, srcPort, dstPort int) {
	lines := strings.Split(payload, "\r\n")
	if len(lines) == 0 {
		return
	}

	requestLine := lines[0]
	parts := strings.Fields(requestLine)
	if len(parts) < 3 {
		return
	}

	method := parts[0]
	rawURI := parts[1]

	tx := Transaction{
		Timestamp: packet.Metadata().Timestamp.Format("15:04:05.000"),
		FrameNum:  frameNum,
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		DstIP:     dstIP,
		DstPort:   dstPort,
		Method:    method,
	}

	// Parse Headers
	host := ""
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			break
		}

		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			key := strings.ToLower(strings.TrimSpace(parts[0]))
			val := strings.TrimSpace(parts[1])

			switch key {
			case "host":
				host = val
				tx.Host = val
			case "user-agent":
				tx.UserAgent = val
			case "referer":
				tx.Referer = val
			case "cookie":
				if len(val) > 50 {
					tx.Cookie = val[:47] + "..."
				} else {
					tx.Cookie = val
				}
			}
		}
	}

	// Construct Full URL
	if strings.HasPrefix(rawURI, "http://") || strings.HasPrefix(rawURI, "https://") {
		tx.URL = rawURI
	} else if host != "" {
		tx.URL = "http://" + host + rawURI
	} else {
		tx.URL = rawURI
	}

	e.mu.Lock()
	e.Transactions = append(e.Transactions, tx)
	e.mu.Unlock()
}
