package credentials

import (
	"encoding/base64"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Credential represents a discovered username/password pair
type Credential struct {
	Protocol string `json:"protocol"`
	ClientIP string `json:"client_ip"`
	ServerIP string `json:"server_ip"`
	Username string `json:"username"`
	Password string `json:"password"`
	Captured bool   `json:"captured"` // captured in this file
}

// Extractor handles credential extraction
type Extractor struct {
	Credentials []Credential
}

func NewExtractor() *Extractor {
	return &Extractor{
		Credentials: []Credential{},
	}
}

// ScanPacket checks for credentials in the packet payload
func (e *Extractor) ScanPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if ipLayer == nil || tcpLayer == nil {
		return
	}

	ip, _ := ipLayer.(*layers.IPv4)
	tcp, _ := tcpLayer.(*layers.TCP)
	payload := string(tcp.Payload)

	if len(payload) == 0 {
		return
	}

	srcIP := ip.SrcIP.String()
	dstIP := ip.DstIP.String()

	// 1. HTTP Basic Auth
	if strings.Contains(payload, "Authorization: Basic ") {
		e.parseHttpBasic(payload, srcIP, dstIP)
	}

	// 2. FTP (Plaintext)
	// FTP often sends USER and PASS in separate packets.
	// This simple per-packet scan works if USER/PASS are in the payload.
	// A more robust approach would track state, but this catches simple logins.
	if strings.HasPrefix(payload, "USER ") {
		user := strings.TrimSpace(strings.TrimPrefix(payload, "USER "))
		e.addCredential("FTP", srcIP, dstIP, user, "<pending>")
	} else if strings.HasPrefix(payload, "PASS ") {
		pass := strings.TrimSpace(strings.TrimPrefix(payload, "PASS "))
		e.updateLastFtpPassword(srcIP, dstIP, pass)
	}
}

func (e *Extractor) parseHttpBasic(payload, srcIP, dstIP string) {
	lines := strings.Split(payload, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Authorization: Basic ") {
			authBase64 := strings.TrimPrefix(line, "Authorization: Basic ")
			decoded, err := base64.StdEncoding.DecodeString(authBase64)
			if err == nil {
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) == 2 {
					e.addCredential("HTTP", srcIP, dstIP, parts[0], parts[1])
				}
			}
		}
	}
}

func (e *Extractor) addCredential(proto, client, server, user, pass string) {
	// Check for duplicates
	for _, c := range e.Credentials {
		if c.Protocol == proto && c.ClientIP == client && c.ServerIP == server && c.Username == user && c.Password == pass {
			return
		}
	}
	e.Credentials = append(e.Credentials, Credential{
		Protocol: proto,
		ClientIP: client,
		ServerIP: server,
		Username: user,
		Password: pass,
		Captured: true,
	})
}

func (e *Extractor) updateLastFtpPassword(client, server, pass string) {
	// Find the most recent FTP cred for this pair that matches "pending"
	for i := len(e.Credentials) - 1; i >= 0; i-- {
		c := &e.Credentials[i]
		if c.Protocol == "FTP" && c.ClientIP == client && c.ServerIP == server && c.Password == "<pending>" {
			c.Password = pass
			return
		}
	}
}
