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
	Filename  string `json:"filename"`
	Size      int64  `json:"size"`
	Path      string `json:"path"`
	Extension string `json:"extension"`
	MD5       string `json:"md5"`
	SHA256    string `json:"sha256"`
	SourceIP  string `json:"source_ip"`
	DestIP    string `json:"dest_ip"`
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
	// Simple identifier: HTTP
	// Look for HTTP signatures in the beginning
	dataStr := string(stream.Data)
	filename := ""

	// Check for HTTP Response
	if strings.HasPrefix(dataStr, "HTTP/") {
		// Try to find Content-Type or similar to guess extension,
		// or just use magic bytes if possible.
		// For now, let's just dump it as .html if it looks like HTML or .bin
		if strings.Contains(dataStr, "<html") {
			filename = stream.ID + ".html"
		} else {
			filename = stream.ID + ".http_resp"
		}
	} else if strings.HasPrefix(dataStr, "GET ") || strings.HasPrefix(dataStr, "POST ") {
		filename = stream.ID + ".http_req"
	}

	// Magic bytes check (very basic)
	if len(stream.Data) > 4 {
		magic := stream.Data[:4]
		if string(magic) == "%PDF" {
			filename = stream.ID + ".pdf"
		} else if magic[0] == 0xFF && magic[1] == 0xD8 && magic[2] == 0xFF {
			filename = stream.ID + ".jpg"
		} else if magic[0] == 0x89 && string(magic[1:4]) == "PNG" {
			filename = stream.ID + ".png"
		}
	}

	// If we found a likely file/protocol, extract metadata and optionally write it
	if filename != "" {
		// Get FULL data for writing/hashing
		var dataToWrite []byte
		if sa.DataProvider != nil {
			fullData, err := sa.DataProvider(stream.ID)
			if err == nil && len(fullData) > 0 {
				dataToWrite = fullData
			} else {
				dataToWrite = stream.Data
			}
		} else {
			dataToWrite = stream.Data
		}

		// Calculate Hashes
		md5Hash := md5.Sum(dataToWrite)
		md5Str := hex.EncodeToString(md5Hash[:])

		sha256Hash := sha256.Sum256(dataToWrite)
		sha256Str := hex.EncodeToString(sha256Hash[:])

		fullPath := filepath.Join(sa.OutputDir, filename)
		size := int64(len(dataToWrite))

		// If NOT SafeMode, write to disk
		if !sa.SafeMode {
			err := os.WriteFile(fullPath, dataToWrite, 0644)
			if err != nil {
				return false // Failed to write
			}
		} else {
			fullPath = "[Only in Memory] " + filename // Marker for UI
		}

		sa.FilesWritten = append(sa.FilesWritten, FileDetail{
			Filename:  filename,
			Size:      size,
			Path:      fullPath,
			Extension: filepath.Ext(filename),
			MD5:       md5Str,
			SHA256:    sha256Str,
			SourceIP:  stream.SrcIP,
			DestIP:    stream.DstIP,
		})
		return true
	}

	return false
}
