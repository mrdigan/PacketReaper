package main

import (
	"PacketReaper/pkg/analysis"
	"PacketReaper/pkg/anomalies"
	"PacketReaper/pkg/assembly"
	"PacketReaper/pkg/certificates"
	"PacketReaper/pkg/credentials"
	"PacketReaper/pkg/decryption"
	"PacketReaper/pkg/dns"
	"PacketReaper/pkg/geoip"
	"PacketReaper/pkg/http"
	"PacketReaper/pkg/keywords"
	"PacketReaper/pkg/messages"
	"PacketReaper/pkg/parameters"
	"PacketReaper/pkg/pcap"
	"PacketReaper/pkg/voip"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx       context.Context
	decryptor *decryption.Decryptor

	// Stream Storage
	streamDir   string
	streamFiles map[string]string // streamID -> filepath
	streamMu    sync.RWMutex
}

// StreamData holds bidirectional stream content
type StreamData struct {
	Inbound  string `json:"inbound"`
	Outbound string `json:"outbound"`
}

// formatDuration converts a time.Duration to a human-readable string
// Examples: "5m 23s", "2h 15m", "3d 4h"
func formatDuration(d time.Duration) string {
	if d == 0 {
		return "0s"
	}

	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	var parts []string

	if days > 0 {
		if days >= 365 {
			years := days / 365
			remainingDays := days % 365
			if remainingDays > 0 {
				parts = append(parts, fmt.Sprintf("%dy %dd", years, remainingDays))
			} else {
				parts = append(parts, fmt.Sprintf("%dy", years))
			}
		} else {
			parts = append(parts, fmt.Sprintf("%dd", days))
		}
	}

	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}

	if minutes > 0 && days == 0 { // Only show minutes if less than a day
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}

	if len(parts) == 0 {
		seconds := int(d.Seconds()) % 60
		parts = append(parts, fmt.Sprintf("%ds", seconds))
	}

	return strings.Join(parts, " ")
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{
		decryptor: decryption.NewDecryptor(),
	}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	// Open log file for the entire application lifecycle
	logFile, logErr := os.OpenFile("PacketReaper_debug.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if logErr == nil {
		log.SetOutput(logFile)
		log.Printf("=== PacketReaper Started ===")
	} else {
		log.Printf("Warning: Could not open log file: %v", logErr)
	}
}

// PcapResult holds the processing result
type PcapResult struct {
	Message          string                      `json:"message"`
	Files            []assembly.FileDetail       `json:"files"`
	Hosts            []*analysis.Host            `json:"hosts"`
	Credentials      []credentials.Credential    `json:"credentials"`
	KeywordMatches   []keywords.Match            `json:"keyword_matches"`
	DnsRecords       []dns.Record                `json:"dns_records"`
	Images           []ImageInfo                 `json:"images"`
	Metadata         PcapMetadata                `json:"metadata"`
	Timeline         []analysis.TimeBucket       `json:"timeline"`
	ProtocolStats    map[string]int              `json:"protocol_stats"`
	ServiceStats     map[int]int                 `json:"service_stats"`
	Sessions         []*analysis.Session         `json:"sessions"`
	Parameters       []parameters.Parameter      `json:"parameters"`
	Messages         []messages.Message          `json:"messages"`
	Anomalies        []anomalies.Anomaly         `json:"anomalies"`
	Certificates     []*certificates.Certificate `json:"certificates"`
	HttpTransactions []http.Transaction          `json:"http_transactions"`
	VoipCalls        []voip.Call                 `json:"voip_calls"`
}

type PcapMetadata struct {
	Filename        string `json:"filename"`
	Size            int64  `json:"size"`
	MD5             string `json:"md5"`
	FirstPacketTime string `json:"first_packet_time"`
	LastPacketTime  string `json:"last_packet_time"`
	Duration        string `json:"duration"`
	TotalPackets    int    `json:"total_packets"`
}

type ImageInfo struct {
	Filename string `json:"filename"`
	Data     string `json:"data"` // Base64
	SourceIP string `json:"source_ip"`
}

// ProcessPcapFile is exposed to the frontend
func (a *App) ProcessPcapFile(filename string, keywordsList []string) PcapResult {
	// Debug log is already initialized in startup()
	log.Printf("========================================")
	log.Printf("ProcessPcapFile STARTED")
	log.Printf("Filename: %s", filename)
	log.Printf("Keywords: %v", keywordsList)
	log.Printf("========================================")
	// 1. Calculate File Metadata
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return PcapResult{Message: fmt.Sprintf("Error stating file: %v", err)}
	}
	fileSize := fileInfo.Size()

	f, err := os.Open(filename)
	if err != nil {
		return PcapResult{Message: fmt.Sprintf("Error opening file for hashing: %v", err)}
	}
	hasher := md5.New()
	if _, err := io.Copy(hasher, f); err != nil {
		f.Close()
		return PcapResult{Message: fmt.Sprintf("Error hashing file: %v", err)}
	}
	md5Hash := hex.EncodeToString(hasher.Sum(nil))
	f.Close()
	log.Printf("File stat: size=%d bytes, MD5=%s", fileSize, md5Hash)

	// 2. Start Interpretation
	runtime.LogInfo(a.ctx, fmt.Sprintf("Processing PCAP: %s", filename))
	log.Printf("Starting PCAP interpretation...")

	// Reset Decryptor sessions (but keep key)
	if a.decryptor != nil {
		a.decryptor.Reset()
	}

	// Open PCAP file
	log.Printf("Attempting to open sniffer for file: %s", filename)
	sniffer, err := pcap.OpenFile(filename)
	if err != nil {
		log.Printf("Failed to open PCAP: %v", err)
		runtime.LogError(a.ctx, fmt.Sprintf("Failed to open PCAP: %v", err))
		return PcapResult{
			Message: fmt.Sprintf("Error opening file: %v", err),
		}
	}
	log.Printf("Sniffer create returned (err=%v)", err)
	defer sniffer.Close()
	runtime.LogInfo(a.ctx, "PCAP opened successfully. Initializing analysis...")
	log.Printf("Sniffer opened successfully")

	outputDir := filepath.Join(filepath.Dir(filename), "AssembledFiles")
	log.Printf("Output directory: %s", outputDir)

	// Initialize GeoIP service
	geoIPService, geoErr := geoip.NewGeoIPService()
	if geoErr != nil {
		log.Printf("GeoIP service disabled: %v", geoErr)
		geoIPService = nil
	} else {
		defer geoIPService.Close()
		log.Printf("GeoIP service initialized successfully")
	}

	// Stream Storage Setup
	// Cleanup previous stream data
	if a.streamDir != "" {
		os.RemoveAll(a.streamDir)
	}
	// Create new temp dir
	tmpDir, err := ioutil.TempDir("", "PacketReaper_streams")
	if err != nil {
		log.Printf("Failed to create temp dir for streams: %v", err)
	} else {
		a.streamDir = tmpDir
	}
	a.streamFiles = make(map[string]string)

	assembler := assembly.NewStreamAssembler(outputDir, true) // SafeMode: true = no disk writes

	// Setup Stream Callback
	assembler.OnStreamData = func(streamID string, data []byte) {
		if a.streamDir == "" {
			return
		}

		a.streamMu.Lock()
		defer a.streamMu.Unlock()

		// Determine file path
		filePath, exists := a.streamFiles[streamID]
		if !exists {
			filePath = filepath.Join(a.streamDir, streamID+".bin")
			a.streamFiles[streamID] = filePath
		}

		// Append to file
		f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			f.Write(data)
			f.Close()
		}
	}

	analyzer := analysis.NewAnalyzer(geoIPService, a.decryptor)
	credExtractor := credentials.NewExtractor()
	keywordSearcher := keywords.NewSearcher(keywordsList)
	dnsParser := dns.NewParser()
	paramExtractor := parameters.NewExtractor()
	msgExtractor := messages.NewExtractor()
	anomalyDetector := anomalies.NewDetector()
	httpExtractor := http.NewExtractor()
	voipExtractor := voip.NewExtractor()
	certExtractor := certificates.NewExtractor()

	// Estimate total packet count (rough heuristic: fileSize / 150 bytes per packet)
	estimatedPackets := int(fileSize / 150)
	if estimatedPackets < 100 {
		estimatedPackets = 100 // Minimum estimate
	}

	// Emit initial progress to show total estimated packets immediately
	runtime.EventsEmit(a.ctx, "pcap-progress", map[string]interface{}{
		"current":   0,
		"estimated": estimatedPackets,
		"percent":   0,
	})

	var errorMsg string
	packetCount := 0
	log.Printf("Starting packet sniff loop (estimated: %d packets)...", estimatedPackets)
	err = sniffer.Sniff(func(packet gopacket.Packet) {
		packetCount++

		// Optimization: Check layers once to skip unrelated extractors
		isIP := packet.Layer(layers.LayerTypeIPv4) != nil || packet.Layer(layers.LayerTypeIPv6) != nil

		isTCP := packet.Layer(layers.LayerTypeTCP) != nil
		isUDP := packet.Layer(layers.LayerTypeUDP) != nil

		assembler.AssemblePacket(packet)
		analyzer.AnalyzePacket(packet)
		anomalyDetector.ScanPacket(packet, packetCount)
		certExtractor.ExtractCertificates(packet) // Extract TLS certificates

		if isIP {
			if isTCP {
				credExtractor.ScanPacket(packet)
				msgExtractor.ScanPacket(packet, packetCount)
			}

			if isTCP || isUDP {
				keywordSearcher.ScanPacket(packet, packetCount)
				paramExtractor.ScanPacket(packet, packetCount)
				httpExtractor.ScanPacket(packet, packetCount)
			}

			if isUDP {
				dnsParser.ParsePacket(packet)
			}

			// VoIP check (SIP can be UDP or TCP)
			if isUDP || isTCP {
				voipExtractor.ScanPacket(packet, packetCount)
			}
		}

		// Emit progress every 2000 packets (reduced from 500 for better performance)
		if packetCount%2000 == 0 {
			progress := int((float64(packetCount) / float64(estimatedPackets)) * 100)
			if progress > 100 {
				progress = 100
			}
			runtime.EventsEmit(a.ctx, "pcap-progress", map[string]interface{}{
				"current":   packetCount,
				"estimated": estimatedPackets,
				"percent":   progress,
			})
		}
	})

	log.Printf("Sniff loop completed. Packets processed: %d", packetCount)

	if err != nil {
		log.Printf("Sniffer Error: %v", err)
		fmt.Printf("Sniffer Error: %v\n", err)
		runtime.EventsEmit(a.ctx, "toast", map[string]string{
			"type":    "error",
			"message": fmt.Sprintf("Stopped early: %v", err),
		})
		// Append error to result message for persistent visibility
		// Append error to result message for persistent visibility
		errorMsg = fmt.Sprintf(" [Partial Load Error: %v]", err)
	}

	// 4. Finalize & Extract Files
	// If streaming, assembler only has the start of the data.
	// We provide a data provider to fetch full content from our temp files.
	assembler.DataProvider = func(streamID string) ([]byte, error) {
		path, ok := a.streamFiles[streamID]
		if !ok {
			return nil, fmt.Errorf("stream file not found")
		}
		// Read full file
		// Note: This loads full file into RAM for writing. For huge files this might be an issue again,
		// but since we are extracting images/docs which are usually reasonable size, it's acceptable for now.
		return os.ReadFile(path)
	}

	_ = assembler.FlushAll()

	// 3. Post-Process: Extract certificates from assembled streams
	// This captures certificates that were split across multiple packets (fragmentation)
	log.Printf("Scanning assembled streams for certificates...")
	streams := assembler.GetAllStreams()
	for _, stream := range streams {
		var srcP, dstP int
		var sIP, dIP string
		// Try to parse from ID which is reliable
		fmt.Sscanf(stream.ID, "%s_%d-%s_%d", &sIP, &srcP, &dIP, &dstP)

		// If we have a file on disk for this stream, use it!
		// The 4KB buffer in stream.Data might be enough for ClientHello, but ServerHello+Certificate often exceeds 4KB.
		// So we prefer reading the temp file.

		// Map stream ID to temp file
		// Stream IDs in assembler: "IP_Port-IP_Port" (underscores) or as formatted in Sscanf above?
		// Wait, assembler uses: fmt.Sprintf("%s_%d-%s_%d", ip.SrcIP, srcPort, ip.DstIP, dstPort) -> 1.2.3.4_80-5.6.7.8_443
		// App.go StreamFiles uses: "1.2.3.4_80-5.6.7.8_443" (same format, via toAssemblerFormat logic)

		// Note: assembler.go stores ID as "SrcIP_SrcPort-DstIP_DstPort"
		streamID := stream.ID
		tempFile, exists := a.streamFiles[streamID]

		if exists {
			// Read the full stream from disk (streaming extraction would be better but this works for now)
			// Limit to 1MB to prevent hanging on huge streams just for certs
			f, err := os.Open(tempFile)
			if err == nil {
				// Read headers/handshake relevant parts (usually first 16KB is plenty for Certs)
				buf := make([]byte, 16384)
				n, _ := f.Read(buf)
				f.Close()
				if n > 0 {
					certExtractor.ExtractFromStream(buf[:n], stream.SrcIP, stream.DstIP, dstP)
				}
			}
		} else {
			// Fallback to memory buffer (which is now capped at 4KB)
			if len(stream.Data) > 0 {
				certExtractor.ExtractFromStream(stream.Data, stream.SrcIP, stream.DstIP, dstP)
			}
		}
	}

	// Flag certificate security issues as anomalies
	for _, cert := range certExtractor.Certificates {
		if cert.IsExpired {
			anomalyDetector.FlagCertificateIssue(
				cert.ServerIP,
				cert.ServerPort,
				cert.Subject,
				"Expired Certificate",
				anomalies.SeverityHigh,
				fmt.Sprintf("Certificate expired on %s (issued by %s)", cert.NotAfter, cert.Issuer),
			)
		} else if cert.IsSelfSigned {
			anomalyDetector.FlagCertificateIssue(
				cert.ServerIP,
				cert.ServerPort,
				cert.Subject,
				"Self-Signed Certificate",
				anomalies.SeverityMedium,
				fmt.Sprintf("Self-signed certificate detected (valid until %s)", cert.NotAfter),
			)
		}
	}

	// Post-process images
	var images []ImageInfo
	for _, fileInfo := range assembler.FilesWritten {
		file := fileInfo.Filename
		ext := strings.ToLower(filepath.Ext(file))
		if ext == ".jpg" || ext == ".jpeg" || ext == ".png" || ext == ".gif" {
			fullPath := filepath.Join(outputDir, file)
			data, err := ioutil.ReadFile(fullPath)
			if err == nil {
				b64 := base64.StdEncoding.EncodeToString(data)
				images = append(images, ImageInfo{
					Filename: file,
					Data:     b64,
					SourceIP: fileInfo.SourceIP,
				})
			}
		}
	}

	metadata := PcapMetadata{
		Filename:        filepath.Base(filename),
		Size:            fileSize,
		MD5:             md5Hash,
		FirstPacketTime: analyzer.FirstPacketTime.Format("2006-01-02 15:04:05"),
		LastPacketTime:  analyzer.LastPacketTime.Format("2006-01-02 15:04:05"),
		Duration:        formatDuration(analyzer.LastPacketTime.Sub(analyzer.FirstPacketTime)),
		TotalPackets:    packetCount,
	}

	// Emit final 100% progress
	runtime.EventsEmit(a.ctx, "pcap-progress", map[string]interface{}{
		"current":   packetCount,
		"estimated": packetCount, // Final count is the truth
		"percent":   100,
		"label":     "Finalizing...",
	})

	msg := fmt.Sprintf("Processed %d packets. Found %d hosts, %d credentials, %d keyword matches, %d DNS records, %d images.", packetCount, len(analyzer.Hosts), len(credExtractor.Credentials), len(keywordSearcher.Matches), len(dnsParser.Records), len(images)) + errorMsg
	log.Printf("Final message: %s", msg)
	log.Printf("ProcessPcapFile COMPLETED")
	log.Printf("========================================")

	return PcapResult{
		Message:          msg,
		Files:            assembler.FilesWritten,
		Hosts:            analyzer.GetSortedHosts(),
		Credentials:      credExtractor.Credentials,
		KeywordMatches:   keywordSearcher.Matches,
		DnsRecords:       dnsParser.Records,
		Images:           images,
		Metadata:         metadata,
		Timeline:         analyzer.GetTimeline(),
		ProtocolStats:    analyzer.GetProtocolStats(),
		ServiceStats:     analyzer.GetPortStats(),
		Sessions:         analyzer.GetSessions(),
		Parameters:       paramExtractor.Parameters,
		Messages:         msgExtractor.Messages,
		Anomalies:        anomalyDetector.Anomalies,
		Certificates:     certExtractor.Certificates,
		HttpTransactions: httpExtractor.Transactions,
		VoipCalls:        voipExtractor.GetCalls(),
	}
}

// SelectPcapFile opens a file dialog to select a PCAP file
func (a *App) SelectPcapFile() string {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select PCAP File",
		Filters: []runtime.FileFilter{
			{DisplayName: "Packet Captures", Pattern: "*.pcap;*.pcapng;*.cap"},
		},
	})
	if err != nil {
		return ""
	}
	return path
}

// LoadPrivateKey opens a file dialog to select a Private Key
func (a *App) LoadPrivateKey() (string, error) {
	log.Printf("[App] LoadPrivateKey called")
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select Private Key or NSS KeyLog",
		Filters: []runtime.FileFilter{
			{DisplayName: "Key Files", Pattern: "*.key;*.pem;*.crt;*.txt;*.log"},
		},
	})
	if err != nil || path == "" {
		log.Printf("[App] File dialog cancelled or error: %v", err)
		return "", err
	}

	log.Printf("[App] Loading key from: %s", path)
	// Load it into the decryptor
	err = a.decryptor.LoadPrivateKey(path)
	if err != nil {
		log.Printf("[App] LoadPrivateKey failed: %v", err)
		return "", err
	}

	log.Printf("[App] Key loaded successfully")
	return "Key Loaded Successfully", nil
}

// GetStreamContent retrieves the conversation for a session
// sessionKey format from Analyzer: "IP:Port-IP:Port-Proto" e.g. "192.168.1.5:49812-10.0.0.1:80-TCP"
func (a *App) GetStreamContent(sessionKey string) StreamData {
	a.streamMu.RLock()
	defer a.streamMu.RUnlock()

	result := StreamData{Inbound: "", Outbound: ""}

	// 1. Parse Session Key
	parts := strings.Split(sessionKey, "-")
	if len(parts) < 3 {
		return result
	}
	// source: IP:Port, dest: IP:Port
	srcPart := parts[0] // 192.168.1.5:49812
	dstPart := parts[1] // 10.0.0.1:80

	// Helper to convert IP:Port to Assembler ID format IP_Port
	toAssemblerFormat := func(ipPort string) string {
		return strings.Replace(ipPort, ":", "_", 1)
	}

	// The StreamAssembler stores streams as "Src_Port-Dst_Port"
	// We need to look up both directions: A->B and B->A

	// Forward: Src->Dst
	id1 := fmt.Sprintf("%s-%s", toAssemblerFormat(srcPart), toAssemblerFormat(dstPart))
	// Reverse: Dst->Src
	id2 := fmt.Sprintf("%s-%s", toAssemblerFormat(dstPart), toAssemblerFormat(srcPart))

	readStreamFile := func(id string) string {
		path, ok := a.streamFiles[id]
		if !ok {
			return ""
		}

		f, err := os.Open(path)
		if err != nil {
			return fmt.Sprintf("[Error reading stream: %v]", err)
		}
		defer f.Close()

		// Limit readahead to prevent UI freeze (e.g. 50KB)
		limit := int64(50 * 1024)
		buf := make([]byte, limit)
		n, _ := f.Read(buf)

		// Sanitize output (replace non-printables with dot)
		// Similar to Wireshark's ASCII view
		cleanBuf := make([]byte, n)
		for i := 0; i < n; i++ {
			b := buf[i]
			if (b < 32 && b != '\n' && b != '\r' && b != '\t') || b > 126 {
				cleanBuf[i] = '.'
			} else {
				cleanBuf[i] = b
			}
		}

		content := string(cleanBuf)
		if n == int(limit) {
			content += "\n...[Stream Truncated]..."
		}
		return content
	}

	result.Outbound = readStreamFile(id1) // Src -> Dst
	result.Inbound = readStreamFile(id2)  // Dst -> Src

	return result
}
