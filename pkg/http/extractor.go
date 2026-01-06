package http

import (
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Transaction represents an HTTP request/response transaction
type Transaction struct {
	Timestamp   string `json:"timestamp"`
	FrameNum    int    `json:"frame_num"`
	SrcIP       string `json:"src_ip"`
	SrcPort     int    `json:"src_port"`
	DstIP       string `json:"dst_ip"`
	DstPort     int    `json:"dst_port"`
	Method      string `json:"method"`
	URL         string `json:"url"` // Full URL
	Host        string `json:"host"`
	UserAgent   string `json:"user_agent"`
	Referer     string `json:"referer"`
	Cookie      string `json:"cookie"` // Truncated/summarized
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
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if ipLayer == nil || tcpLayer == nil {
		return
	}

	ip, _ := ipLayer.(*layers.IPv4)
	tcp, _ := tcpLayer.(*layers.TCP)

	if len(tcp.Payload) == 0 {
		return
	}

	payload := string(tcp.Payload)
	
	// Quick check for HTTP methods to identify requests
	// We primarily care about requests for the "Browsing History" view
	if !strings.HasPrefix(payload, "GET ") && 
	   !strings.HasPrefix(payload, "POST ") && 
	   !strings.HasPrefix(payload, "PUT ") && 
	   !strings.HasPrefix(payload, "HEAD ") &&
	   !strings.HasPrefix(payload, "DELETE ") {
		return
	}

	e.extractTransaction(payload, packet, frameNum, ip, tcp)
}

func (e *Extractor) extractTransaction(payload string, packet gopacket.Packet, frameNum int, ip *layers.IPv4, tcp *layers.TCP) {
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
		SrcIP:     ip.SrcIP.String(),
		SrcPort:   int(tcp.SrcPort),
		DstIP:     ip.DstIP.String(),
		DstPort:   int(tcp.DstPort),
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
