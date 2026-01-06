package anomalies

import (
	"strings"
)

// Severity levels for anomalies
type Severity string

const (
	SeverityLow      Severity = "Low"
	SeverityMedium   Severity = "Medium"
	SeverityHigh     Severity = "High"
	SeverityCritical Severity = "Critical"
)

// Detection thresholds
const (
	DGAEntropyThreshold  = 3.5              // Shannon entropy for DGA detection
	ICMPMaxNormalSize    = 84               // bytes (typical ping)
	DNSTxtMaxNormalSize  = 255              // bytes
	HighTrafficThreshold = 10 * 1024 * 1024 // 10MB per IP
	LargePacketThreshold = 1500             // MTU size
)

// Standard port mappings
var StandardPorts = map[int]string{
	20:   "FTP-DATA",
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	143:  "IMAP",
	443:  "HTTPS",
	465:  "SMTPS",
	587:  "SMTP",
	993:  "IMAPS",
	995:  "POP3S",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	8080: "HTTP-Alt",
	8443: "HTTPS-Alt",
}

// Suspicious user-agent strings
var SuspiciousUserAgents = []string{
	"python-requests",
	"curl/",
	"Wget/",
	"Nmap Scripting Engine",
	"sqlmap",
	"Metasploit",
	"Nikto",
	"masscan",
	"ZmEu",
	"WinHTTP",
	"Go-http-client",
	"Scrapy",
}

// Known malicious/scanning patterns
var SuspiciousPatterns = []string{
	"/admin",
	"/phpmyadmin",
	"/wp-admin",
	"/.git",
	"/../",
	"/etc/passwd",
	"cmd.exe",
	"powershell",
	"<script>",
	"SELECT * FROM",
	"UNION SELECT",
}

// IsStandardPort checks if a port matches its expected service
func IsStandardPort(port int, expectedService string) bool {
	service, exists := StandardPorts[port]
	if !exists {
		return false
	}
	return strings.EqualFold(service, expectedService)
}

// IsSuspiciousUserAgent checks if a user-agent is known to be suspicious
func IsSuspiciousUserAgent(ua string) (bool, string) {
	for _, sus := range SuspiciousUserAgents {
		if strings.Contains(ua, sus) {
			return true, sus
		}
	}
	return false, ""
}

// ContainsSuspiciousPattern checks for common attack patterns
func ContainsSuspiciousPattern(payload string) (bool, string) {
	for _, pattern := range SuspiciousPatterns {
		if strings.Contains(payload, pattern) {
			return true, pattern
		}
	}
	return false, ""
}
