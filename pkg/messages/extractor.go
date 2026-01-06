package messages

import (
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Message represents an email message extracted from network traffic
type Message struct {
	FrameNumber int          `json:"frame_number"`
	Timestamp   string       `json:"timestamp"`
	Protocol    string       `json:"protocol"` // "SMTP", "POP3", "IMAP"
	SourceIP    string       `json:"source_ip"`
	SourcePort  int          `json:"source_port"`
	DestIP      string       `json:"dest_ip"`
	DestPort    int          `json:"dest_port"`
	From        string       `json:"from"`
	To          string       `json:"to"`
	Subject     string       `json:"subject"`
	Date        string       `json:"date"`
	MessageID   string       `json:"message_id"`
	Body        string       `json:"body"`      // Decoded body
	RawBody     string       `json:"raw_body"`  // Encoded body
	Encoding    string       `json:"encoding"`  // "base64", "quoted-printable", "7bit", "8bit"
	Size        int          `json:"size"`      // Body size in bytes
	Attachments []Attachment `json:"attachments"`
}

// Attachment represents an email attachment
type Attachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int    `json:"size"`
}

// Extractor scans packets for email messages
type Extractor struct {
	mu            sync.Mutex
	Messages      []Message
	assemblyBuffer map[string]*messageBuilder // Key: srcIP:srcPort->dstIP:dstPort
}

// messageBuilder accumulates message data across multiple packets
type messageBuilder struct {
	data      strings.Builder
	protocol  string
	srcIP     string
	srcPort   int
	dstIP     string
	dstPort   int
	frameNum  int
	timestamp string
}

func NewExtractor() *Extractor {
	return &Extractor{
		Messages:      []Message{},
		assemblyBuffer: make(map[string]*messageBuilder),
	}
}

// ScanPacket analyzes a packet for email protocol traffic
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
	srcIP := ip.SrcIP.String()
	dstIP := ip.DstIP.String()
	srcPort := int(tcp.SrcPort)
	dstPort := int(tcp.DstPort)
	timestamp := packet.Metadata().Timestamp.Format("15:04:05")

	// Detect protocol by port
	protocol := ""
	if dstPort == 25 || dstPort == 587 || dstPort == 465 || srcPort == 25 || srcPort == 587 || srcPort == 465 {
		protocol = "SMTP"
	} else if dstPort == 110 || dstPort == 995 || srcPort == 110 || srcPort == 995 {
		protocol = "POP3"
	} else if dstPort == 143 || dstPort == 993 || srcPort == 143 || srcPort == 993 {
		protocol = "IMAP"
	}

	if protocol == "" {
		return
	}

	// Check for email content patterns
	if protocol == "SMTP" && (strings.Contains(payload, "From:") || strings.Contains(payload, "Subject:") || strings.Contains(payload, "DATA")) {
		e.parseSMTP(payload, frameNum, timestamp, srcIP, srcPort, dstIP, dstPort)
	} else if protocol == "POP3" && strings.Contains(payload, "+OK") {
		e.parsePOP3(payload, frameNum, timestamp, srcIP, srcPort, dstIP, dstPort)
	} else if protocol == "IMAP" && strings.Contains(payload, "FETCH") {
		e.parseIMAP(payload, frameNum, timestamp, srcIP, srcPort, dstIP, dstPort)
	}
}

// parseSMTP extracts SMTP messages
func (e *Extractor) parseSMTP(payload string, frameNum int, timestamp, srcIP string, srcPort int, dstIP string, dstPort int) {
	// Look for email headers
	if !strings.Contains(payload, "From:") {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	msg := Message{
		FrameNumber: frameNum,
		Timestamp:   timestamp,
		Protocol:    "SMTP",
		SourceIP:    srcIP,
		SourcePort:  srcPort,
		DestIP:      dstIP,
		DestPort:    dstPort,
		Encoding:    "7bit",
	}

	lines := strings.Split(payload, "\r\n")
	inBody := false
	bodyLines := []string{}
	contentType := ""
	encoding := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Headers
		if !inBody {
			if strings.HasPrefix(line, "From:") {
				msg.From = strings.TrimSpace(strings.TrimPrefix(line, "From:"))
			} else if strings.HasPrefix(line, "To:") {
				msg.To = strings.TrimSpace(strings.TrimPrefix(line, "To:"))
			} else if strings.HasPrefix(line, "Subject:") {
				msg.Subject = strings.TrimSpace(strings.TrimPrefix(line, "Subject:"))
			} else if strings.HasPrefix(line, "Date:") {
				msg.Date = strings.TrimSpace(strings.TrimPrefix(line, "Date:"))
			} else if strings.HasPrefix(line, "Message-ID:") || strings.HasPrefix(line, "Message-Id:") {
				msg.MessageID = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "Message-ID:"), "Message-Id:"))
			} else if strings.HasPrefix(line, "Content-Type:") {
				contentType = strings.TrimSpace(strings.TrimPrefix(line, "Content-Type:"))
			} else if strings.HasPrefix(line, "Content-Transfer-Encoding:") {
				encoding = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "Content-Transfer-Encoding:")))
				msg.Encoding = encoding
			} else if line == "" {
				// Empty line signals end of headers
				inBody = true
			}
		} else {
			// Body
			bodyLines = append(bodyLines, line)
		}
	}

	rawBody := strings.Join(bodyLines, "\n")
	msg.RawBody = rawBody
	msg.Size = len(rawBody)

	// Decode body
	decodedBody := rawBody
	if encoding == "base64" {
		if decoded, err := DecodeBase64(rawBody); err == nil {
			decodedBody = decoded
		}
	} else if encoding == "quoted-printable" {
		if decoded, err := DecodeQuotedPrintable(rawBody); err == nil {
			decodedBody = decoded
		}
	}

	// Parse MIME for attachments
	if strings.Contains(contentType, "multipart/") {
		mainBody, attachments, _ := ParseMIME(contentType, decodedBody)
		msg.Body = mainBody
		msg.Attachments = attachments
	} else {
		msg.Body = decodedBody
	}

	// Only add if we have meaningful data
	if msg.From != "" || msg.Subject != "" {
		e.Messages = append(e.Messages, msg)
	}
}

// parsePOP3 extracts POP3 messages (retrieval)
func (e *Extractor) parsePOP3(payload string, frameNum int, timestamp, srcIP string, srcPort int, dstIP string, dstPort int) {
	// POP3 RETR response format is similar to SMTP
	// Reuse SMTP parser logic
	if strings.Contains(payload, "From:") {
		e.parseSMTP(payload, frameNum, timestamp, srcIP, srcPort, dstIP, dstPort)
		if len(e.Messages) > 0 {
			e.Messages[len(e.Messages)-1].Protocol = "POP3"
		}
	}
}

// parseIMAP extracts IMAP messages (retrieval)
func (e *Extractor) parseIMAP(payload string, frameNum int, timestamp, srcIP string, srcPort int, dstIP string, dstPort int) {
	// IMAP FETCH response format is similar to SMTP
	// Reuse SMTP parser logic
	if strings.Contains(payload, "From:") {
		e.parseSMTP(payload, frameNum, timestamp, srcIP, srcPort, dstIP, dstPort)
		if len(e.Messages) > 0 {
			e.Messages[len(e.Messages)-1].Protocol = "IMAP"
		}
	}
}
