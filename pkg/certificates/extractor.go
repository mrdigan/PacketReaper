package certificates

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Certificate represents an extracted X.509 certificate
type Certificate struct {
	// Identification
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	SerialNumber string `json:"serial_number"`

	// Validity
	NotBefore       string `json:"not_before"`
	NotAfter        string `json:"not_after"`
	IsExpired       bool   `json:"is_expired"`
	DaysUntilExpiry int    `json:"days_until_expiry"`

	// Security Flags
	IsSelfSigned bool `json:"is_self_signed"`

	// Fingerprints
	SHA256 string `json:"sha256"`

	// Network Context
	ServerIP   string `json:"server_ip"`
	ServerPort int    `json:"server_port"`
	ClientIP   string `json:"client_ip"`

	// Metadata
	Timestamp string `json:"timestamp"`
	Algorithm string `json:"signature_algorithm"`
}

// Extractor extracts certificates from TLS traffic
type Extractor struct {
	Certificates []*Certificate
	mu           sync.Mutex
	seen         map[string]bool // Dedupe by SHA256
}

// NewExtractor creates a new certificate extractor
func NewExtractor() *Extractor {
	return &Extractor{
		Certificates: make([]*Certificate, 0),
		seen:         make(map[string]bool),
	}
}

// ExtractCertificates extracts certificates from a packet
func (e *Extractor) ExtractCertificates(packet gopacket.Packet) {
	// Get TLS layer - just check if it exists
	tlsLayer := packet.Layer(layers.LayerTypeTLS)
	if tlsLayer == nil {
		return
	}

	// Get network layer for context
	var srcIP, dstIP string
	var dstPort int

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip := ipLayer.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		dstPort = int(tcp.DstPort)
	}

	timestamp := packet.Metadata().Timestamp.Format("2006-01-02 15:04:05")

	// The issue: tls.LayerPayload() returns encrypted application data
	// Certificates appear in plaintext in TLS handshake messages
	// Solution: Scan the entire packet payload for certificate patterns
	
	// Get the raw application layer payload (all TCP data)
	var appPayload []byte
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		appPayload = appLayer.Payload()
	}
	
	if len(appPayload) == 0 {
		return
	}
	
	// Scan for X.509 certificates in the raw TLS stream
	// Certificates in TLS appear as:
	// - TLS Record: Content Type (0x16 = Handshake)
	// - TLS Handshake: Type (0x0b = Certificate)
	// - Certificate data: DER-encoded X.509 (starts with 0x30 0x82)
	certs := e.scanForCertificates(appPayload)
	
	for _, cert := range certs {
		certInfo := &Certificate{
			Subject:         getCommonName(cert.Subject.CommonName, cert.DNSNames),
			Issuer:          cert.Issuer.CommonName,
			SerialNumber:    fmt.Sprintf("%X", cert.SerialNumber),
			NotBefore:       cert.NotBefore.Format("2006-01-02 15:04:05"),
			NotAfter:        cert.NotAfter.Format("2006-01-02 15:04:05"),
			IsExpired:       time.Now().After(cert.NotAfter),
			DaysUntilExpiry: int(time.Until(cert.NotAfter).Hours() / 24),
			IsSelfSigned:    cert.Subject.String() == cert.Issuer.String(),
			SHA256:          calculateSHA256(cert.Raw),
			ServerIP:        dstIP,
			ServerPort:      dstPort,
			ClientIP:        srcIP,
			Timestamp:       timestamp,
			Algorithm:       cert.SignatureAlgorithm.String(),
		}

		e.addCertificate(certInfo)
	}
}

// ExtractFromStream processes a reassembled TCP stream for certificates
func (e *Extractor) ExtractFromStream(streamData []byte, srcIP, dstIP string, dstPort int) {
	if len(streamData) == 0 {
		return
	}

	// TLS Record parsing
	// A stream contains multiple TLS records.
	// Record format:
	// Type (1 byte) | Version (2 bytes) | Length (2 bytes) | Fragment (Length bytes)
	
	offset := 0
	for offset+5 <= len(streamData) {
		recordType := streamData[offset]
		// versionMajor := streamData[offset+1]
		// versionMinor := streamData[offset+2]
		
		// Read Length (Big Endian)
		length := int(streamData[offset+3])<<8 | int(streamData[offset+4])
		
		// Move to fragment
		offset += 5
		
		if offset+length > len(streamData) {
			// Incomplete record or stream end
			break
		}
		
		// We only care about Handshake records (Type 0x16)
		if recordType == 0x16 {
			fragment := streamData[offset : offset+length]
			e.parseHandshakeFragment(fragment, srcIP, dstIP, dstPort)
		} else {
             // If we lose sync or it's not a record, we might want to scan, 
             // but for now let's assume valid stream.
             // If we hit SSLv2 (MSB set in length), this simple parser breaks.
             // SSLv2 ClientHello starts with Type 0x80 (usually).
             // Let's stick to TLS/SSLv3 for now.
        }
		
		offset += length
	}
}

func (e *Extractor) parseHandshakeFragment(data []byte, srcIP, dstIP string, dstPort int) {
	// Handshake Protocol
	// Type (1 byte) | Length (3 bytes) | Body
	
	offset := 0
	for offset+4 <= len(data) {
		msgType := data[offset]
		msgLen := int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
		
		offset += 4
		if offset+msgLen > len(data) {
			break
		}
		
		// Certificate Message (Type 0x0b)
		if msgType == 0x0b {
			certMsg := data[offset : offset+msgLen]
			e.parseCertificateMessage(certMsg, srcIP, dstIP, dstPort)
		}
		
		offset += msgLen
	}
}

func (e *Extractor) parseCertificateMessage(data []byte, srcIP, dstIP string, dstPort int) {
	// Certificate Message Format:
	// Certs Length (3 bytes) | Certificates...
	
	if len(data) < 3 {
		return
	}
	
	// totalCertLen := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
	offset := 3
	
	for offset+3 <= len(data) {
		// Each certificate is: Length (3 bytes) | ASN.1 Cert Data
		certLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
		offset += 3
		
		if offset+certLen > len(data) {
			break
		}
		
		certData := data[offset : offset+certLen]
		
		// Parse this individual certificate
		parsedCerts := e.parseCertificates(certData)
		for _, cert := range parsedCerts {
			certInfo := &Certificate{
				Subject:         getCommonName(cert.Subject.CommonName, cert.DNSNames),
				Issuer:          cert.Issuer.CommonName,
				SerialNumber:    fmt.Sprintf("%X", cert.SerialNumber),
				NotBefore:       cert.NotBefore.Format("2006-01-02 15:04:05"),
				NotAfter:        cert.NotAfter.Format("2006-01-02 15:04:05"),
				IsExpired:       time.Now().After(cert.NotAfter),
				DaysUntilExpiry: int(time.Until(cert.NotAfter).Hours() / 24),
				IsSelfSigned:    cert.Subject.String() == cert.Issuer.String(),
				SHA256:          calculateSHA256(cert.Raw),
				ServerIP:        dstIP,
				ServerPort:      dstPort,
				ClientIP:        srcIP,
				Timestamp:       time.Now().Format("2006-01-02 15:04:05"),
				Algorithm:       cert.SignatureAlgorithm.String(),
			}
			e.addCertificate(certInfo)
		}
		
		offset += certLen
	}
}

// scanForCertificates searches for X.509 certificates in raw data
func (e *Extractor) scanForCertificates(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	
	// Scan for DER-encoded certificate patterns
	// X.509 certificates start with: 0x30 (SEQUENCE)
	// Followed by length. 
	// Short form: 0x00-0x7F (0-127 bytes)
	// Long form: 0x81-0x83 (128 bytes to ~16MB)
	
	minCertSize := 100 // Heuristic: valid certs are rarely smaller than this
	
	for i := 0; i < len(data)-minCertSize; i++ {
		// Look for DER SEQUENCE tag (0x30)
		if data[i] != 0x30 {
			continue
		}
		
		// Check length byte
		lenByte := data[i+1]
		
		// We are looking for the START of a certificate.
		// Common cases:
		// 0x82: Length is in next 2 bytes (common for > 255 bytes)
		// 0x81: Length is in next 1 byte (common for 128-255 bytes)
		// 0x83: Length is in next 3 bytes (common for huge certs/chains)
		
		isValidStart := false
		if lenByte == 0x81 || lenByte == 0x82 || lenByte == 0x83 {
			isValidStart = true
		} else if lenByte < 0x80 && int(lenByte) > 0 { 
			// Short form, unlikely for full cert but possible for parts
			// We skip this for now to reduce false positives unless we're desperate
			isValidStart = false 
		}

		if isValidStart {
			// Try to parse from this position
			// We pass a slice starting at i
			remaining := data[i:]
			
			// Quick optimization: Check if buffer has enough bytes for the declared length
			// (This requires parsing the length, which ParseCertificate does anyway, 
			// but we can save the function call overhead if we wanted. 
			// specific x509 parsing is heavy, so we rely on checks)

			parsedCerts := e.parseCertificates(remaining)
			if len(parsedCerts) > 0 {
				certs = append(certs, parsedCerts...)
				// Skip ahead. A cert is at least minCertSize.
				// Ideally we skip by the actual size of the cert we found,
				// but we don't easily have that from parsedCerts[0].Raw (we do!)
				
				bytesConsumed := 0
				for _, c := range parsedCerts {
					bytesConsumed += len(c.Raw)
				}
				
				if bytesConsumed > 0 {
					i += bytesConsumed - 1 // -1 because loop increments
				} else {
					i += minCertSize
				}
			}
		}
	}
	
	return certs
}

// parseCertificates parses DER-encoded certificates
func (e *Extractor) parseCertificates(certData []byte) []*x509.Certificate {
	certs, err := x509.ParseCertificates(certData)
	if err != nil {
		// Try parsing as a single certificate
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil
		}
		return []*x509.Certificate{cert}
	}
	return certs
}

// addCertificate adds a certificate if not already seen
func (e *Extractor) addCertificate(cert *Certificate) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Deduplicate by SHA256
	if e.seen[cert.SHA256] {
		return
	}

	e.seen[cert.SHA256] = true
	e.Certificates = append(e.Certificates, cert)
}

// calculateSHA256 calculates SHA256 fingerprint
func calculateSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// getCommonName returns the best display name for a certificate
func getCommonName(cn string, dnsNames []string) string {
	if cn != "" {
		return cn
	}
	if len(dnsNames) > 0 {
		return dnsNames[0]
	}
	return "Unknown"
}
