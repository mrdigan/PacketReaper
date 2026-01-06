package voip

import (
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Call represents a SIP call session
type Call struct {
	ID          string `json:"id"` // Call-ID header
	Timestamp   string `json:"timestamp"`
	From        string `json:"from"`
	To          string `json:"to"`
	UserAgent   string `json:"user_agent"`
	State       string `json:"state"` // INVITE, RINGING, ACTIVE, CLOSED, CANCELLED
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	DurationSec int    `json:"duration_sec"`

	// Internal tracking
	startTime time.Time
	endTime   time.Time
}

// Extractor scans packets for VoIP (SIP) signaling
type Extractor struct {
	mu    sync.Mutex
	Calls map[string]*Call // Keyed by Call-ID
}

func NewExtractor() *Extractor {
	return &Extractor{
		Calls: make(map[string]*Call),
	}
}

// GetCalls returns the list of calls
func (e *Extractor) GetCalls() []Call {
	e.mu.Lock()
	defer e.mu.Unlock()

	calls := make([]Call, 0, len(e.Calls))
	for _, call := range e.Calls {
		// Calculate final duration if still active/unknown
		if call.DurationSec == 0 && !call.endTime.IsZero() {
			call.DurationSec = int(call.endTime.Sub(call.startTime).Seconds())
		}
		calls = append(calls, *call)
	}
	return calls
}

// ScanPacket analyzes a packet for SIP signaling
func (e *Extractor) ScanPacket(packet gopacket.Packet, frameNum int) {
	// SIP can be UDP or TCP
	isUDP := packet.Layer(layers.LayerTypeUDP) != nil
	isTCP := packet.Layer(layers.LayerTypeTCP) != nil

	var payload []byte
	if isTCP {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			payload = tcpLayer.(*layers.TCP).Payload
		}
	} else if isUDP {
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			payload = udpLayer.(*layers.UDP).Payload
		}
	}

	if len(payload) == 0 {
		return
	}

	content := string(payload)
	// Quick check for SIP signature
	if !strings.Contains(content, "SIP/2.0") {
		return
	}

	e.processSIP(content, packet)
}

func (e *Extractor) processSIP(content string, packet gopacket.Packet) {
	e.mu.Lock()
	defer e.mu.Unlock()

	lines := strings.Split(content, "\r\n")
	if len(lines) == 0 {
		return
	}

	// Extract headers
	headers := make(map[string]string)
	for _, line := range lines[1:] {
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			headers[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
		}
	}

	callID := headers["call-id"]
	if callID == "" {
		return
	}

	// Update or Create Call
	call, exists := e.Calls[callID]
	if !exists {
		// Only create on relevant methods usually, but capturing all associated with ID is safer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		srcIP := ""
		dstIP := ""
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			srcIP = ip.SrcIP.String()
			dstIP = ip.DstIP.String()
		}

		call = &Call{
			ID:        callID,
			Timestamp: packet.Metadata().Timestamp.Format("15:04:05"),
			From:      cleanSIPURI(headers["from"]),
			To:        cleanSIPURI(headers["to"]),
			UserAgent: headers["user-agent"],
			State:     "SETUP",
			SrcIP:     srcIP,
			DstIP:     dstIP,
			startTime: packet.Metadata().Timestamp,
		}
		e.Calls[callID] = call
	}

	// Update State based on Method/Response
	firstLine := lines[0]
	if strings.Contains(firstLine, "INVITE") {
		call.State = "INVITE"
	} else if strings.Contains(firstLine, "RINGING") {
		call.State = "RINGING"
	} else if strings.Contains(firstLine, "OK") { // 200 OK often means connected
		if call.State == "INVITE" || call.State == "RINGING" {
			call.State = "ACTIVE"
		}
	} else if strings.Contains(firstLine, "BYE") {
		call.State = "CLOSED"
		call.endTime = packet.Metadata().Timestamp
		call.DurationSec = int(call.endTime.Sub(call.startTime).Seconds())
	} else if strings.Contains(firstLine, "CANCEL") {
		call.State = "CANCELLED"
		call.endTime = packet.Metadata().Timestamp
	}
}

func cleanSIPURI(uri string) string {
	// Format: "Name" <sip:user@host>;tag=...
	// We want: user@host
	if strings.Contains(uri, "<") {
		start := strings.Index(uri, "<")
		end := strings.Index(uri, ">")
		if start != -1 && end != -1 && end > start {
			uri = uri[start+1 : end]
		}
	}
	uri = strings.TrimPrefix(uri, "sip:")
	if strings.Contains(uri, ";") {
		uri = strings.Split(uri, ";")[0]
	}
	return uri
}
