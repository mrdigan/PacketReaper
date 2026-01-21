package assembly

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// FileDetail holds info about extracted files
type FileDetail struct {
	Filename   string `json:"filename"`
	Size       int64  `json:"size"`
	Path       string `json:"path"`
	Extension  string `json:"extension"`
	MD5        string `json:"md5"`
	SHA256     string `json:"sha256"`
	SourceIP   string `json:"source_ip"`
	DestIP     string `json:"dest_ip"`
	SourcePort int    `json:"source_port"`
	DestPort   int    `json:"dest_port"`
}

// StreamAssembler handles 5-tuple streams
type StreamAssembler struct {
	mu           sync.Mutex
	Streams      map[streamKey]*Stream
	OutputDir    string
	FilesWritten []FileDetail
	SafeMode     bool // If true, do not write files to disk
	OnStreamData func(streamID string, data []byte)
	DataProvider func(streamID string) ([]byte, error)
}

// streamKey avoids string allocations for map lookups
type streamKey struct {
	srcIP   [4]byte
	dstIP   [4]byte
	srcPort uint16
	dstPort uint16
}

// Stream represents a TCP stream (simplified)
type Stream struct {
	ID          string // Kept as string for display/logging
	SrcIP       string
	DstIP       string
	PacketCount int
	Data        []byte
}

func NewStreamAssembler(outputDir string, safeMode bool) *StreamAssembler {
	_ = os.MkdirAll(outputDir, 0755)
	return &StreamAssembler{
		Streams:      make(map[streamKey]*Stream),
		OutputDir:    outputDir,
		FilesWritten: []FileDetail{},
		SafeMode:     safeMode,
	}
}

// AssemblePacket processes a packet and groups it by flow
func (sa *StreamAssembler) AssemblePacket(packet gopacket.Packet) {
	// Parse IP to get 5-tuple
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)

	var srcPort, dstPort uint16
	var payload []byte

	// Check for TCP or UDP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		payload = tcp.Payload
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		payload = udp.Payload
	} else {
		return // Not TCP or UDP
	}

	// Create struct key (no allocation)
	var key streamKey
	copy(key.srcIP[:], ip.SrcIP.To4())
	copy(key.dstIP[:], ip.DstIP.To4())
	key.srcPort = srcPort
	key.dstPort = dstPort

	sa.mu.Lock()
	defer sa.mu.Unlock()

	stream, exists := sa.Streams[key]
	if !exists {
		// Only allocate string ID when creating new stream
		strKey := fmt.Sprintf("%s_%d-%s_%d", ip.SrcIP, srcPort, ip.DstIP, dstPort)
		stream = &Stream{
			ID:    strKey,
			SrcIP: ip.SrcIP.String(),
			DstIP: ip.DstIP.String(),
		}
		sa.Streams[key] = stream
	}

	stream.PacketCount++

	if len(payload) > 0 {
		if sa.OnStreamData != nil {
			// Stream Mode:
			// 1. Keep first 4KB for identification
			if len(stream.Data) < 4096 {
				remaining := 4096 - len(stream.Data)
				if len(payload) > remaining {
					stream.Data = append(stream.Data, payload[:remaining]...)
				} else {
					stream.Data = append(stream.Data, payload...)
				}
			}
			// 2. Stream everything to disk
			sa.OnStreamData(stream.ID, payload)
		} else {
			// Memory Mode:
			// Just append everything. stream.Data will naturally contain the "first 4KB"
			// because it contains everything.
			stream.Data = append(stream.Data, payload...)
		}
	}
}

// FlushAll writes all assembled streams to disk if they look interesting
func (sa *StreamAssembler) FlushAll() int {
	sa.mu.Lock()
	defer sa.mu.Unlock()

	count := 0
	for _, stream := range sa.Streams {
		if len(stream.Data) == 0 {
			continue
		}

		if sa.identifyAndWrite(stream) {
			count++
		}
	}
	return count
}

// GetAllStreams returns all assembled streams
func (sa *StreamAssembler) GetAllStreams() []*Stream {
	sa.mu.Lock()
	defer sa.mu.Unlock()

	streams := make([]*Stream, 0, len(sa.Streams))
	for _, s := range sa.Streams {
		streams = append(streams, s)
	}
	return streams
}

func (sa *StreamAssembler) identifyAndWrite(stream *Stream) bool {
	dataStr := string(stream.Data) // buffer for detection
	filename := ""
	extension := ""
	var fileData []byte
	sourceRef := ""

	// Check for HTTP Response
	// We check the buffer first to see if it looks like HTTP
	if strings.HasPrefix(dataStr, "HTTP/") {
		// It identifies as HTTP.
		// Now we need the FULL data to parse headers properly and extract the body.
		// If we only use stream.Data, we might be truncated at 4KB.

		var fullStreamData []byte
		if sa.DataProvider != nil {
			d, err := sa.DataProvider(stream.ID)
			if err == nil && len(d) > 0 {
				fullStreamData = d
			} else {
				fullStreamData = stream.Data
			}
		} else {
			fullStreamData = stream.Data
		}

		if len(fullStreamData) == 0 {
			return false
		}

		// Find split point in full data
		// Convert head to string for searching
		searchAndDestroyLimit := 8192
		if len(fullStreamData) < searchAndDestroyLimit {
			searchAndDestroyLimit = len(fullStreamData)
		}
		headStr := string(fullStreamData[:searchAndDestroyLimit])

		splitIdx := strings.Index(headStr, "\r\n\r\n")

		if splitIdx != -1 {
			headers := headStr[:splitIdx]

			// Body starts after \r\n\r\n (4 bytes)
			bodyStart := splitIdx + 4

			if bodyStart < len(fullStreamData) {
				fileData = fullStreamData[bodyStart:]
			} else {
				fileData = []byte{} // Empty body
			}

			// 1. Try Content-Disposition
			// Content-Disposition: attachment; filename="filename.jpg"
			if strings.Contains(strings.ToLower(headers), "content-disposition") {
				lines := strings.Split(headers, "\r\n")
				for _, line := range lines {
					if strings.HasPrefix(strings.ToLower(line), "content-disposition:") {
						if idx := strings.Index(strings.ToLower(line), "filename="); idx != -1 {
							// simple extract
							val := line[idx+9:]
							val = strings.Trim(val, "\" ;")
							if val != "" {
								filename = val
							}
						}
					}
				}
			}

			// 2. Correlate with Request to get URL/Filename
			// ID: SrcIP_SrcPort-DstIP_DstPort (Server -> Client)
			// Request ID: DstIP_DstPort-SrcIP_SrcPort (Client -> Server)

			idParts := strings.Split(stream.ID, "-")
			if len(idParts) == 2 {
				revKeyStr := idParts[1] + "-" + idParts[0]

				var reqStream *Stream
				for _, s := range sa.Streams {
					if s.ID == revKeyStr {
						reqStream = s
						break
					}
				}

				if reqStream != nil {
					// Parse request for URL
					reqData := string(reqStream.Data)
					lines := strings.Split(reqData, "\r\n")
					if len(lines) > 0 {
						reqLine := lines[0] // GET ...
						parts := strings.Fields(reqLine)
						if len(parts) >= 2 {
							url := parts[1]

							// Extract Host header
							host := ""
							for _, l := range lines {
								if strings.HasPrefix(strings.ToLower(l), "host:") {
									host = strings.TrimSpace(strings.SplitN(l, ":", 2)[1])
									break
								}
							}

							if host != "" {
								sourceRef = fmt.Sprintf("%s%s", host, url)
							} else {
								sourceRef = url
							}

							// If we haven't found a filename from headers, assume it from URL
							if filename == "" {
								// Extract last part of path
								if idx := strings.LastIndex(url, "/"); idx != -1 {
									potential := url[idx+1:]
									// strip query params
									if qIdx := strings.Index(potential, "?"); qIdx != -1 {
										potential = potential[:qIdx]
									}
									if potential != "" && strings.Contains(potential, ".") {
										filename = potential
									}
								}
							}
						}
					}
				}
			}

			// Fallback extension
			if filename == "" {
				if strings.Contains(headers, "Content-Type: text/html") {
					extension = ".html"
				} else if strings.Contains(headers, "Content-Type: image/jpeg") {
					extension = ".jpg"
				} else {
					extension = ".http_resp"
				}
				filename = stream.ID + extension
			}
		} else {
			// Weird split or no split, just take whole
			fileData = fullStreamData
			filename = stream.ID + ".http_resp"
		}

	} else if strings.HasPrefix(dataStr, "GET ") || strings.HasPrefix(dataStr, "POST ") {
		// Skip requests
		return false
	}

	// Magic bytes check (fallback if not HTTP or if we want to confirm)
	if len(fileData) == 0 && !strings.HasPrefix(dataStr, "HTTP/") {
		// Use full data for logic check too
		var fullStreamData []byte
		if sa.DataProvider != nil {
			d, err := sa.DataProvider(stream.ID)
			if err == nil && len(d) > 0 {
				fullStreamData = d
			} else {
				fullStreamData = stream.Data
			}
		} else {
			fullStreamData = stream.Data
		}

		fileData = fullStreamData
		if len(fullStreamData) > 4 {
			magic := fullStreamData[:4]
			if string(magic) == "%PDF" {
				filename = stream.ID + ".pdf"
			} else if magic[0] == 0xFF && magic[1] == 0xD8 && magic[2] == 0xFF {
				filename = stream.ID + ".jpg"
				extension = ".jpg"
			} else if magic[0] == 0x89 && string(magic[1:4]) == "PNG" {
				filename = stream.ID + ".png"
				extension = ".png"
			}
		}
	}

	// If we found a likely file/protocol, extract metadata and optionally write it
	if filename != "" && len(fileData) > 0 {
		// Calculate Hashes
		md5Hash := md5.Sum(fileData)
		md5Str := hex.EncodeToString(md5Hash[:])

		sha256Hash := sha256.Sum256(fileData)
		sha256Str := hex.EncodeToString(sha256Hash[:])

		// deduplicate name if needed or ensure safe path
		safeFilename := filepath.Base(filename)

		if !strings.HasPrefix(filename, stream.ID) {
			safeFilename = fmt.Sprintf("%s_%s", stream.ID, safeFilename)
		}

		fullPath := filepath.Join(sa.OutputDir, safeFilename)
		size := int64(len(fileData))

		// If NOT SafeMode, write to disk
		if !sa.SafeMode {
			err := os.WriteFile(fullPath, fileData, 0644)
			if err != nil {
				return false // Failed to write
			}
		} else {
			fullPath = "[Only in Memory] " + safeFilename // Marker for UI
		}

		displaySource := stream.SrcIP
		if sourceRef != "" {
			displaySource = fmt.Sprintf("%s (%s)", stream.SrcIP, sourceRef)
		}

		// Parse ports from Stream ID
		// Format: SrcIP_SrcPort-DstIP_DstPort
		var sPort, dPort int
		// Replace _ with space for Sscanf (easier than splitting if we trust format)
		// Or just split.
		// ID: 1.2.3.4_123-5.6.7.8_456
		idParts := strings.Split(stream.ID, "-")
		if len(idParts) == 2 {
			p1 := strings.Split(idParts[0], "_")
			p2 := strings.Split(idParts[1], "_")
			if len(p1) == 2 && len(p2) == 2 {
				fmt.Sscanf(p1[1], "%d", &sPort)
				fmt.Sscanf(p2[1], "%d", &dPort)
			}
		}

		sa.FilesWritten = append(sa.FilesWritten, FileDetail{
			Filename:   filename, // Display name
			Size:       size,
			Path:       fullPath,
			Extension:  filepath.Ext(filename),
			MD5:        md5Str,
			SHA256:     sha256Str,
			SourceIP:   displaySource,
			DestIP:     stream.DstIP,
			SourcePort: sPort,
			DestPort:   dPort,
		})
		return true
	}

	return false
}
