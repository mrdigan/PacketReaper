package credentials

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"PacketReaper/pkg/packetutils"
	"github.com/google/gopacket"
)

// Credential represents a discovered username/password pair
type Credential struct {
	Protocol   string `json:"protocol"`
	ClientIP   string `json:"client_ip"`
	ClientPort string `json:"client_port"` // Port as string to handle "21", "80", etc.
	ServerIP   string `json:"server_ip"`
	ServerPort string `json:"server_port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Captured   bool   `json:"captured"` // captured in this file
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
	ep := packetutils.Extract(packet)
	if !ep.HasIP {
		return
	}

	var payload []byte
	var srcPort, dstPort string
	var srcPortInt, dstPortInt uint16

	if ep.Protocol == "TCP" || ep.Protocol == "UDP" {
		payload = ep.Payload
		srcPortInt = ep.SrcPort
		dstPortInt = ep.DstPort
		srcPort = fmt.Sprintf("%d", ep.SrcPort)
		dstPort = fmt.Sprintf("%d", ep.DstPort)
	}

	if len(payload) == 0 {
		return
	}

	payloadStr := string(payload)
	srcIP := ep.SrcIP
	dstIP := ep.DstIP

	isTCP := ep.Protocol == "TCP"

	// 2. FTP (Plaintext)
	if strings.HasPrefix(payloadStr, "USER ") && (dstPortInt == 21 || srcPortInt == 21) {
		user := strings.TrimSpace(strings.TrimPrefix(payloadStr, "USER "))
		e.addCredential("FTP", srcIP, srcPort, dstIP, dstPort, user, "<pending>")
	} else if strings.HasPrefix(payloadStr, "PASS ") && (dstPortInt == 21 || srcPortInt == 21) {
		pass := strings.TrimSpace(strings.TrimPrefix(payloadStr, "PASS "))
		e.updateLastPassword("FTP", srcIP, dstIP, pass)
	}

	// 1. HTTP Basic Auth
	if strings.Contains(payloadStr, "Authorization: Basic ") {
		e.parseHttpBasic(payloadStr, srcIP, srcPort, dstIP, dstPort)
	}

	// 3. Telnet (very basic)
	if srcPortInt == 23 || dstPortInt == 23 {
		// Telnet captures are often character-by-character, tricky to capture nicely in a simple packet scan.
		// We'll look for simple "login:" or "Password:" prompts if they appear in one key packet, creating a generic entry.
		// For a real Telnet parser, stream reassembly is preferred.
		// This is a placeholder for cleartext Telnet.
	}

	// 4. POP3
	if strings.HasPrefix(payloadStr, "USER ") && (dstPortInt == 110 || srcPortInt == 110) {
		user := strings.TrimSpace(strings.TrimPrefix(payloadStr, "USER "))
		e.addCredential("POP3", srcIP, srcPort, dstIP, dstPort, user, "<pending>")
	} else if strings.HasPrefix(payloadStr, "PASS ") && (dstPortInt == 110 || srcPortInt == 110) {
		pass := strings.TrimSpace(strings.TrimPrefix(payloadStr, "PASS "))
		e.updateLastPassword("POP3", srcIP, dstIP, pass)
	}

	// 5. IMAP
	// LOGIN <user> <pass>
	if dstPortInt == 143 || srcPortInt == 143 {
		lowerPayload := strings.ToLower(payloadStr)
		if strings.Contains(lowerPayload, "login ") {
			parts := strings.Fields(payloadStr)
			// expected: [TAG] LOGIN user pass
			for i, p := range parts {
				if strings.ToLower(p) == "login" && i+2 < len(parts) {
					e.addCredential("IMAP", srcIP, srcPort, dstIP, dstPort, parts[i+1], parts[i+2])
				}
			}
		}
	}

	// 6. SMTP
	// AUTH PLAIN <base64>
	// AUTH LOGIN <base64>
	if dstPortInt == 25 || srcPortInt == 25 || dstPortInt == 587 || srcPortInt == 587 {
		if strings.Contains(payloadStr, "AUTH PLAIN ") {
			b64 := strings.TrimSpace(strings.TrimPrefix(payloadStr, "AUTH PLAIN "))
			decoded, err := base64.StdEncoding.DecodeString(b64)
			if err == nil {
				// PLAIN auth format: \0user\0pass or user\0user\0pass
				parts := strings.Split(string(decoded), "\x00")
				if len(parts) >= 3 {
					e.addCredential("SMTP", srcIP, srcPort, dstIP, dstPort, parts[1], parts[2])
				} else if len(parts) >= 2 {
					e.addCredential("SMTP", srcIP, srcPort, dstIP, dstPort, parts[0], parts[1])
				}
			}
		}
	}

	// 7. Kerberos (Port 88)
	if dstPortInt == 88 || srcPortInt == 88 {
		e.extractKerberos(payload, srcIP, srcPort, dstIP, dstPort, isTCP)
	}
}

func (e *Extractor) parseHttpBasic(payload, srcIP, srcPort, dstIP, dstPort string) {
	lines := strings.Split(payload, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Authorization: Basic ") {
			authBase64 := strings.TrimPrefix(line, "Authorization: Basic ")
			decoded, err := base64.StdEncoding.DecodeString(authBase64)
			if err == nil {
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) == 2 {
					e.addCredential("HTTP", srcIP, srcPort, dstIP, dstPort, parts[0], parts[1])
				}
			}
		}
	}
}

func (e *Extractor) addCredential(proto, client, clientPort, server, serverPort, user, pass string) {
	// Check for duplicates
	for _, c := range e.Credentials {
		if c.Protocol == proto && c.ClientIP == client && c.ServerIP == server && c.Username == user && c.Password == pass {
			return
		}
	}
	e.Credentials = append(e.Credentials, Credential{
		Protocol:   proto,
		ClientIP:   client,
		ClientPort: clientPort,
		ServerIP:   server,
		ServerPort: serverPort,
		Username:   user,
		Password:   pass,
		Captured:   true,
	})
}

func (e *Extractor) updateLastPassword(proto, client, server, pass string) {
	// Find the most recent cred for this pair that matches "pending"
	for i := len(e.Credentials) - 1; i >= 0; i-- {
		c := &e.Credentials[i]
		if c.Protocol == proto && c.ClientIP == client && c.ServerIP == server && c.Password == "<pending>" {
			c.Password = pass
			return
		}
	}
}

type krbASReq struct {
	PVNO    int           `asn1:"explicit,tag:1"`
	MsgType int           `asn1:"explicit,tag:2"`
	PAData  []krbPAData   `asn1:"explicit,optional,tag:3"`
	ReqBody asn1.RawValue `asn1:"explicit,tag:4"`
}

type krbPAData struct {
	Type  int    `asn1:"explicit,tag:1"`
	Value []byte `asn1:"explicit,tag:2"`
}

type krbEncryptedData struct {
	EType  int    `asn1:"explicit,tag:0"`
	KVNO   int    `asn1:"explicit,optional,tag:1"`
	Cipher []byte `asn1:"explicit,tag:2"`
}

type krbKDCReqBody struct {
	KDCOptions asn1.BitString   `asn1:"explicit,tag:0"`
	CName      krbPrincipalName `asn1:"explicit,optional,tag:1"`
	Realm      string           `asn1:"generalstring,explicit,tag:2"`
	// Use RawElements for the rest to avoid strict ASN.1 trailing data errors
	RawElements []asn1.RawValue
}

type krbPrincipalName struct {
	NameType   int      `asn1:"explicit,tag:0"`
	NameString []string `asn1:"generalstring,explicit,tag:1"`
}

func (e *Extractor) extractKerberos(payload []byte, srcIP, srcPort, dstIP, dstPort string, isTCP bool) {
	if len(payload) == 0 {
		return
	}

	// 1. Normalize TCP Payload
	if isTCP {
		if len(payload) >= 4 {
			length := uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])
			if length <= uint32(len(payload)-4) {
				payload = payload[4 : 4+length]
			}
		}
	}

	// 2. Try ASN.1 strict parsing
	var asReq krbASReq
	_, err := asn1.UnmarshalWithParams(payload, &asReq, "application,tag:10")
	if err == nil && asReq.PVNO == 5 && asReq.MsgType == 10 {
		// Valid AS-REQ
		e.parseKerberosASN1(asReq, srcIP, srcPort, dstIP, dstPort)
		return
	}

	// 3. Fallback to heuristic parser if ASN.1 fails
	// Note: We only run fallback if it might be an AS-REQ (e.g. contains 02 01 05)
	if strings.Contains(string(payload), "\x02\x01\x05") {
		e.extractKerberosHeuristic(payload, srcIP, srcPort, dstIP, dstPort)
	}
}

func (e *Extractor) parseKerberosASN1(asReq krbASReq, srcIP, srcPort, dstIP, dstPort string) {
	var encData krbEncryptedData
	foundTimestamp := false

	// Locate PA-DATA type 2
	for _, pa := range asReq.PAData {
		if pa.Type == 2 {
			_, err := asn1.Unmarshal(pa.Value, &encData)
			if err == nil {
				foundTimestamp = true
				break
			}
		}
	}

	if !foundTimestamp {
		return
	}

	// Extract Realm and CName
	var reqBody krbKDCReqBody
	_, _ = asn1.Unmarshal(asReq.ReqBody.Bytes, &reqBody)

	realm := reqBody.Realm
	if realm == "" {
		realm = "UNKNOWN"
	}

	username := "unknown"
	if len(reqBody.CName.NameString) > 0 {
		username = strings.Join(reqBody.CName.NameString, "")
	}

	userRealm := fmt.Sprintf("%s\\%s", realm, username)

	hash := fmt.Sprintf("$krb5pa$%d$%s", encData.EType, hex.EncodeToString(encData.Cipher))
	e.addCredential("Kerberos", srcIP, srcPort, dstIP, dstPort, userRealm, hash)
}

func (e *Extractor) extractKerberosHeuristic(payload []byte, srcIP, srcPort, dstIP, dstPort string) {
	// Fallback heuristic extraction
	padataType2Idx := strings.Index(string(payload), "\x02\x01\x02")
	if padataType2Idx == -1 {
		return
	}

	cleanStrings := func(data []byte) []string {
		var extracted []string
		current := []byte{}
		for _, b := range data {
			if b >= 32 && b <= 126 {
				current = append(current, b)
			} else {
				if len(current) > 3 {
					extracted = append(extracted, string(current))
				}
				current = []byte{}
			}
		}
		return extracted
	}

	strs := cleanStrings(payload)

	var etype int
	var cipher []byte

	if idx := strings.Index(string(payload), "\x02\x01\x12"); idx != -1 { // 18 AES256
		etype = 18
		cipher = extractOctetString(payload, idx+3)
	} else if idx := strings.Index(string(payload), "\x02\x01\x17"); idx != -1 { // 23 RC4
		etype = 23
		cipher = extractOctetString(payload, idx+3)
	} else if idx := strings.Index(string(payload), "\x02\x01\x11"); idx != -1 { // 17 AES128
		etype = 17
		cipher = extractOctetString(payload, idx+3)
	}

	if etype != 0 && len(cipher) > 0 {
		userRealm := "unknown"
		if len(strs) > 0 {
			var candidates []string
			for _, s := range strs {
				if len(s) == 15 && s[len(s)-1] == 'Z' && s[0] == '2' {
					isTime := true
					for i := 0; i < 14; i++ {
						if s[i] < '0' || s[i] > '9' {
							isTime = false
							break
						}
					}
					if isTime {
						continue
					}
				}

				valid := true
				hasLetter := false
				hasLower := false
				hasUpper := false

				for _, r := range s {
					if r >= 'a' && r <= 'z' {
						hasLetter = true
						hasLower = true
					} else if r >= 'A' && r <= 'Z' {
						hasLetter = true
						hasUpper = true
					} else if r >= '0' && r <= '9' {
					} else if r == '.' || r == '-' || r == '_' || r == '$' || r == '@' {
					} else {
						valid = false
						break
					}
				}

				if !valid || !hasLetter || len(s) < 3 {
					continue
				}

				isMixed := hasLower && hasUpper
				if isMixed && !strings.Contains(s, ".") && !strings.Contains(s, "-") {
					continue
				}

				candidates = append(candidates, s)
			}

			if len(candidates) >= 2 {
				c1 := candidates[len(candidates)-2]
				c2 := candidates[len(candidates)-1]

				isRealm1 := strings.ToUpper(c1) == c1
				isRealm2 := strings.ToUpper(c2) == c2

				if isRealm1 && !isRealm2 {
					userRealm = fmt.Sprintf("%s\\%s", c1, c2)
				} else if isRealm2 && !isRealm1 {
					userRealm = fmt.Sprintf("%s\\%s", c2, c1)
				} else {
					userRealm = fmt.Sprintf("%s\\%s", c1, c2)
				}
			} else if len(candidates) == 1 {
				userRealm = candidates[0]
			}
		}

		hash := fmt.Sprintf("$krb5pa$%d$%s", etype, hex.EncodeToString(cipher))
		e.addCredential("Kerberos", srcIP, srcPort, dstIP, dstPort, userRealm, hash)
	}
}

func extractOctetString(data []byte, after int) []byte {
	start := after
	if start >= len(data) {
		return nil
	}

	limit := start + 20
	if limit > len(data) {
		limit = len(data)
	}

	for i := start; i < limit; i++ {
		if data[i] == 0x04 {
			if i+1 >= len(data) {
				return nil
			}
			length := int(data[i+1])

			contentStart := i + 2
			if length > 127 {
				lenBytes := length & 0x7F
				if i+2+lenBytes > len(data) {
					return nil
				}
				contentStart = i + 2 + lenBytes
				length = 0
			}

			if length > 0 && contentStart+length <= len(data) {
				return data[contentStart : contentStart+length]
			}
			return data[contentStart:]
		}
	}
	return nil
}
