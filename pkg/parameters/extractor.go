package parameters

import (
	"net/url"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Parameter represents an extracted protocol parameter
type Parameter struct {
	Timestamp string `json:"timestamp"`
	FrameNum  int    `json:"frame_num"`
	Protocol  string `json:"protocol"`  // "HTTP", "SMTP", "FTP"
	Type      string `json:"type"`      // "Header", "Cookie", "Query", "POST", "Command"
	Key       string `json:"key"`       // e.g., "User-Agent", "session_id", "MAIL FROM"
	Value     string `json:"value"`     // Actual parameter value
	URL       string `json:"url"`       // Request URL (HTTP only)
	Method    string `json:"method"`    // GET, POST, etc. (HTTP only)
	SourceIP  string `json:"source_ip"`
	DestIP    string `json:"dest_ip"`
}

// Extractor scans packets for protocol parameters
type Extractor struct {
	mu         sync.Mutex
	Parameters []Parameter
}

func NewExtractor() *Extractor {
	return &Extractor{
		Parameters: []Parameter{},
	}
}

// ScanPacket analyzes a packet for extractable parameters
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
	timestamp := packet.Metadata().Timestamp.Format("15:04:05")

	// Detect protocol based on port and payload signatures
	dstPort := int(tcp.DstPort)
	srcPort := int(tcp.SrcPort)

	// HTTP Detection (port 80 or HTTP signatures)
	if dstPort == 80 || srcPort == 80 || strings.HasPrefix(payload, "GET ") || 
	   strings.HasPrefix(payload, "POST ") || strings.HasPrefix(payload, "HTTP/") {
		e.extractHTTP(payload, frameNum, timestamp, srcIP, dstIP)
	}

	// SMTP Detection (port 25, 587, or SMTP commands)
	if dstPort == 25 || dstPort == 587 || srcPort == 25 || srcPort == 587 ||
	   strings.HasPrefix(payload, "MAIL FROM") || strings.HasPrefix(payload, "RCPT TO") ||
	   strings.HasPrefix(payload, "DATA") || strings.HasPrefix(payload, "EHLO") {
		e.extractSMTP(payload, frameNum, timestamp, srcIP, dstIP)
	}

	// FTP Detection (port 21 or FTP commands)
	if dstPort == 21 || srcPort == 21 || strings.HasPrefix(payload, "USER ") ||
	   strings.HasPrefix(payload, "PASS ") || strings.HasPrefix(payload, "STOR ") ||
	   strings.HasPrefix(payload, "RETR ") {
		e.extractFTP(payload, frameNum, timestamp, srcIP, dstIP)
	}
}

// extractHTTP parses HTTP requests and responses
func (e *Extractor) extractHTTP(payload string, frameNum int, timestamp, srcIP, dstIP string) {
	lines := strings.Split(payload, "\r\n")
	if len(lines) == 0 {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Parse request line (GET /path?query HTTP/1.1)
	requestLine := lines[0]
	var method, fullURL string

	if strings.HasPrefix(requestLine, "GET ") || strings.HasPrefix(requestLine, "POST ") ||
	   strings.HasPrefix(requestLine, "PUT ") || strings.HasPrefix(requestLine, "DELETE ") {
		parts := strings.Fields(requestLine)
		if len(parts) >= 2 {
			method = parts[0]
			fullURL = parts[1]

			// Extract query string parameters
			if strings.Contains(fullURL, "?") {
				urlParts := strings.SplitN(fullURL, "?", 2)
				if len(urlParts) == 2 {
					queryString := urlParts[1]
					params, _ := url.ParseQuery(queryString)
					for key, values := range params {
						for _, val := range values {
							e.Parameters = append(e.Parameters, Parameter{
								Timestamp: timestamp,
								FrameNum:  frameNum,
								Protocol:  "HTTP",
								Type:      "Query",
								Key:       key,
								Value:     val,
								URL:       fullURL,
								Method:    method,
								SourceIP:  srcIP,
								DestIP:    dstIP,
							})
						}
					}
				}
			}
		}
	}

	// Parse headers
	interestingHeaders := map[string]bool{
		"host": true, "user-agent": true, "cookie": true, "authorization": true,
		"referer": true, "content-type": true, "accept": true, "x-forwarded-for": true,
	}

	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			// End of headers, check for POST body
			if method == "POST" && i+1 < len(lines) {
				body := strings.Join(lines[i+1:], "\r\n")
				if len(body) > 0 {
					// Truncate to 1KB
					if len(body) > 1024 {
						body = body[:1024] + "... [truncated]"
					}
					e.Parameters = append(e.Parameters, Parameter{
						Timestamp: timestamp,
						FrameNum:  frameNum,
						Protocol:  "HTTP",
						Type:      "POST",
						Key:       "body",
						Value:     body,
						URL:       fullURL,
						Method:    method,
						SourceIP:  srcIP,
						DestIP:    dstIP,
					})
				}
			}
			break
		}

		// Parse header line
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				headerKey := strings.ToLower(strings.TrimSpace(parts[0]))
				headerValue := strings.TrimSpace(parts[1])

				// Check if this is an interesting header
				if interestingHeaders[headerKey] {
					// Special handling for cookies
					if headerKey == "cookie" {
						cookies := strings.Split(headerValue, ";")
						for _, cookie := range cookies {
							cookie = strings.TrimSpace(cookie)
							if strings.Contains(cookie, "=") {
								cookieParts := strings.SplitN(cookie, "=", 2)
								e.Parameters = append(e.Parameters, Parameter{
									Timestamp: timestamp,
									FrameNum:  frameNum,
									Protocol:  "HTTP",
									Type:      "Cookie",
									Key:       cookieParts[0],
									Value:     cookieParts[1],
									URL:       fullURL,
									Method:    method,
									SourceIP:  srcIP,
									DestIP:    dstIP,
								})
							}
						}
					} else {
						e.Parameters = append(e.Parameters, Parameter{
							Timestamp: timestamp,
							FrameNum:  frameNum,
							Protocol:  "HTTP",
							Type:      "Header",
							Key:       headerKey,
							Value:     headerValue,
							URL:       fullURL,
							Method:    method,
							SourceIP:  srcIP,
							DestIP:    dstIP,
						})
					}
				}
			}
		}
	}
}

// extractSMTP parses SMTP commands and headers
func (e *Extractor) extractSMTP(payload string, frameNum int, timestamp, srcIP, dstIP string) {
	lines := strings.Split(payload, "\r\n")

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// SMTP Commands
		if strings.HasPrefix(line, "MAIL FROM:") {
			email := strings.TrimPrefix(line, "MAIL FROM:")
			email = strings.Trim(email, " <>")
			e.Parameters = append(e.Parameters, Parameter{
				Timestamp: timestamp,
				FrameNum:  frameNum,
				Protocol:  "SMTP",
				Type:      "Command",
				Key:       "MAIL FROM",
				Value:     email,
				SourceIP:  srcIP,
				DestIP:    dstIP,
			})
		} else if strings.HasPrefix(line, "RCPT TO:") {
			email := strings.TrimPrefix(line, "RCPT TO:")
			email = strings.Trim(email, " <>")
			e.Parameters = append(e.Parameters, Parameter{
				Timestamp: timestamp,
				FrameNum:  frameNum,
				Protocol:  "SMTP",
				Type:      "Command",
				Key:       "RCPT TO",
				Value:     email,
				SourceIP:  srcIP,
				DestIP:    dstIP,
			})
		} else if strings.HasPrefix(line, "From:") || strings.HasPrefix(line, "To:") ||
			strings.HasPrefix(line, "Subject:") || strings.HasPrefix(line, "Date:") {
			// Email headers
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				e.Parameters = append(e.Parameters, Parameter{
					Timestamp: timestamp,
					FrameNum:  frameNum,
					Protocol:  "SMTP",
					Type:      "Header",
					Key:       parts[0],
					Value:     strings.TrimSpace(parts[1]),
					SourceIP:  srcIP,
					DestIP:    dstIP,
				})
			}
		}
	}
}

// extractFTP parses FTP commands
func (e *Extractor) extractFTP(payload string, frameNum int, timestamp, srcIP, dstIP string) {
	lines := strings.Split(payload, "\r\n")

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// FTP Commands
		if strings.HasPrefix(line, "USER ") {
			username := strings.TrimPrefix(line, "USER ")
			e.Parameters = append(e.Parameters, Parameter{
				Timestamp: timestamp,
				FrameNum:  frameNum,
				Protocol:  "FTP",
				Type:      "Command",
				Key:       "USER",
				Value:     username,
				SourceIP:  srcIP,
				DestIP:    dstIP,
			})
		} else if strings.HasPrefix(line, "PASS ") {
			password := strings.TrimPrefix(line, "PASS ")
			e.Parameters = append(e.Parameters, Parameter{
				Timestamp: timestamp,
				FrameNum:  frameNum,
				Protocol:  "FTP",
				Type:      "Command",
				Key:       "PASS",
				Value:     password,
				SourceIP:  srcIP,
				DestIP:    dstIP,
			})
		} else if strings.HasPrefix(line, "STOR ") || strings.HasPrefix(line, "RETR ") ||
			strings.HasPrefix(line, "DELE ") || strings.HasPrefix(line, "MKD ") {
			// File operation commands
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				e.Parameters = append(e.Parameters, Parameter{
					Timestamp: timestamp,
					FrameNum:  frameNum,
					Protocol:  "FTP",
					Type:      "Command",
					Key:       parts[0],
					Value:     strings.Join(parts[1:], " "),
					SourceIP:  srcIP,
					DestIP:    dstIP,
				})
			}
		}
	}
}
