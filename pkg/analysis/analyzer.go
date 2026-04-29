package analysis

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"PacketReaper/pkg/decryption"
	"PacketReaper/pkg/geoip"
	"PacketReaper/pkg/ja3"
	"PacketReaper/pkg/packetutils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Host represents a network host with traffic statistics
type Host struct {
	IP              string `json:"ip"`
	MAC             string `json:"mac"`
	Hostname        string `json:"hostname"`
	OS              string `json:"os"`
	OpenPorts       []int  `json:"open_ports"`
	PacketsSent     int    `json:"packets_sent"`
	PacketsReceived int    `json:"packets_received"`
	BytesSent       int64  `json:"bytes_sent"`
	BytesRecv       int64  `json:"bytes_recv"`
	TTL             int    `json:"ttl"` // Last observed TTL
	FirstSeen       string `json:"firstSeen"`
	LastSeen        string `json:"lastSeen"`

	// GeoIP fields
	Country      string  `json:"country"`
	CountryISO   string  `json:"countryISO"`
	City         string  `json:"city"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	ASN          uint    `json:"asn"`
	Organization string  `json:"organization"`
}

// TimeBucket represents traffic volume in a time slice
type TimeBucket struct {
	Timestamp string `json:"timestamp"` // ISO8601 or similar suitable for chart
	Bytes     int64  `json:"bytes"`
	Packets   int    `json:"packets"`
}

// Session represents a bidirectional flow between two endpoints
type Session struct {
	Key              string    `json:"key"`
	SrcIP            string    `json:"src_ip"`
	SrcPort          int       `json:"src_port"`
	DstIP            string    `json:"dst_ip"`
	DstPort          int       `json:"dst_port"`
	Protocol         string    `json:"protocol"`
	StartTime        time.Time `json:"start_time"`
	EndTime          time.Time `json:"end_time"`
	Duration         string    `json:"duration"` // Human readable duration
	PacketCount      int       `json:"packet_count"`
	ByteCount        int64     `json:"byte_count"`
	PayloadSize      int64     `json:"payload_size"`
	JA3              string    `json:"ja3"`        // Full JA3 string
	JA3Digest        string    `json:"ja3_digest"` // MD5 hash
	DecryptedContent string    `json:"decrypted_content"`
}

// sessionKey for optimized map lookups — uses [16]byte to support both IPv4 and IPv6.
// IPv4 addresses are stored as IPv4-in-IPv6 via net.IP.To16().
type sessionKey struct {
	ip1      [16]byte
	ip2      [16]byte
	port1    uint16
	port2    uint16
	protocol uint8
}

// Analyzer performs network traffic analysis
type Analyzer struct {
	Hosts           map[string]*Host
	Sessions        map[sessionKey]*Session
	Timeline        map[int64]*TimeBucket // Key: Unix Timestamp (seconds)
	FirstPacketTime time.Time
	LastPacketTime  time.Time
	geoIP           *geoip.GeoIPService
	decryptor       *decryption.Decryptor
	mu              sync.Mutex
	ProtocolCounts  map[string]int // Key: TCP, UDP, ICMP
	PortCounts      map[int]int    // Key: Destination Port
}

func NewAnalyzer(geoIP *geoip.GeoIPService, decryptor *decryption.Decryptor) *Analyzer {
	return &Analyzer{
		Hosts:          make(map[string]*Host),
		Timeline:       make(map[int64]*TimeBucket),
		ProtocolCounts: make(map[string]int),
		PortCounts:     make(map[int]int),
		Sessions:       make(map[sessionKey]*Session),
		geoIP:          geoIP,
		decryptor:      decryptor,
	}
}

// AnalyzePacket processes a packet to update host information
func (a *Analyzer) AnalyzePacket(packet gopacket.Packet) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Update Timestamps (Do this for ALL packets, not just IPv4)
	meta := packet.Metadata()
	if meta != nil && !meta.Timestamp.IsZero() {
		ts := meta.Timestamp
		if a.FirstPacketTime.IsZero() || ts.Before(a.FirstPacketTime) {
			a.FirstPacketTime = ts
		}
		if ts.After(a.LastPacketTime) {
			a.LastPacketTime = ts
		}

		// Timeline Bucketing (1 Second)
		bucketTime := ts.Unix()
		bucket, exists := a.Timeline[bucketTime]
		if !exists {
			bucket = &TimeBucket{
				Timestamp: ts.Format("15:04:05"),
				Bytes:     0,
				Packets:   0,
			}
			a.Timeline[bucketTime] = bucket
		}
		bucket.Bytes += int64(meta.Length)
		bucket.Packets++
	}

	// Extract endpoint metadata — supports both IPv4 and IPv6
	ep := packetutils.Extract(packet)
	if !ep.HasIP {
		return
	}

	// Update Network Counts & Sessions
	var srcPort, dstPort int
	var protocol string
	var protoID uint8

	switch ep.Protocol {
	case "TCP":
		srcPort = int(ep.SrcPort)
		dstPort = int(ep.DstPort)
		protocol = "TCP"
		protoID = 6
		a.ProtocolCounts["TCP"]++
		// If SYN-ACK, the sender is a Server and the SrcPort is Open
		if tcpL := packet.Layer(layers.LayerTypeTCP); tcpL != nil {
			t, _ := tcpL.(*layers.TCP)
			if t.SYN && t.ACK {
				sender := a.getHost(ep.SrcIP)
				a.addOpenPort(sender, srcPort)
			}
		}
		a.PortCounts[dstPort]++
	case "UDP":
		srcPort = int(ep.SrcPort)
		dstPort = int(ep.DstPort)
		protocol = "UDP"
		protoID = 17
		a.ProtocolCounts["UDP"]++
		a.PortCounts[dstPort]++
	case "ICMP":
		protocol = "ICMP"
		protoID = 1
		a.ProtocolCounts["ICMP"]++
	case "ICMPv6":
		protocol = "ICMPv6"
		protoID = 58
		a.ProtocolCounts["ICMPv6"]++
	}

	// Update Session (Flow)
	if protocol != "" {
		// Use net.IP.To16() so both IPv4 and IPv6 fit in [16]byte for map key comparison
		ip1Raw := net.ParseIP(ep.SrcIP).To16()
		ip2Raw := net.ParseIP(ep.DstIP).To16()
		var ip1, ip2 [16]byte
		copy(ip1[:], ip1Raw)
		copy(ip2[:], ip2Raw)
		p1 := uint16(srcPort)
		p2 := uint16(dstPort)

		// Canonicalize key: always store lower IP first for bidirectional matching
		var key sessionKey
		cmp := compareIP16(ip1, ip2)
		if cmp < 0 {
			key = sessionKey{ip1, ip2, p1, p2, protoID}
		} else if cmp > 0 {
			key = sessionKey{ip2, ip1, p2, p1, protoID}
		} else {
			if p1 <= p2 {
				key = sessionKey{ip1, ip2, p1, p2, protoID}
			} else {
				key = sessionKey{ip1, ip2, p2, p1, protoID}
			}
		}

		session, exists := a.Sessions[key]
		if !exists {
			strKey := ""
			if cmp < 0 {
				strKey = fmt.Sprintf("%s:%d-%s:%d-%s", ep.SrcIP, srcPort, ep.DstIP, dstPort, protocol)
			} else if cmp > 0 {
				strKey = fmt.Sprintf("%s:%d-%s:%d-%s", ep.DstIP, dstPort, ep.SrcIP, srcPort, protocol)
			} else {
				if p1 <= p2 {
					strKey = fmt.Sprintf("%s:%d-%s:%d-%s", ep.SrcIP, srcPort, ep.DstIP, dstPort, protocol)
				} else {
					strKey = fmt.Sprintf("%s:%d-%s:%d-%s", ep.DstIP, dstPort, ep.SrcIP, srcPort, protocol)
				}
			}

			session = &Session{
				Key:         strKey,
				SrcIP:       ep.SrcIP,
				SrcPort:     srcPort,
				DstIP:       ep.DstIP,
				DstPort:     dstPort,
				Protocol:    protocol,
				StartTime:   meta.Timestamp,
				EndTime:     meta.Timestamp,
				Duration:    "0s",
				PacketCount: 0,
				ByteCount:   0,
			}
			a.Sessions[key] = session
		}

		session.PacketCount++
		session.ByteCount += int64(meta.Length)

		// Update Payload Size
		session.PayloadSize += int64(len(ep.Payload))

		if meta.Timestamp.After(session.EndTime) {
			session.EndTime = meta.Timestamp
			session.Duration = session.EndTime.Sub(session.StartTime).String()
		}

		// JA3 Calculation (Client Hello) — TCP only
		if protocol == "TCP" && len(ep.Payload) > 0 {
			tcpPayload := ep.Payload

			// TLS Decryption
			if a.decryptor != nil && (a.decryptor.PrivateKey != nil || len(a.decryptor.KeyLog) > 0) {
				a.decryptor.ExtractHandshakeData(session.Key, ep.SrcIP, tcpPayload)
				decrypted, err := a.decryptor.DecryptApplicationData(session.Key, ep.SrcIP, tcpPayload)
				if err == nil && len(decrypted) > 0 {
					if len(session.DecryptedContent) < 2048 {
						cleanData := ""
						for _, b := range decrypted {
							if b >= 32 && b <= 126 {
								cleanData += string(b)
							} else if b == 10 || b == 13 {
								cleanData += string(b)
							} else {
								cleanData += "."
							}
						}
						session.DecryptedContent += cleanData
					}
				}
			}

			if session.JA3Digest == "" {
				ja3Str, ja3Hash := ja3.ComputeJA3(tcpPayload)
				if ja3Hash != "" {
					session.JA3 = ja3Str
					session.JA3Digest = ja3Hash
				}
			}
		}
	}

	// Host Analysis (Sender/Receiver Stats)
	sender := a.getHost(ep.SrcIP)
	sender.PacketsSent++
	sender.TTL = int(ep.TTL) // Works for both IPv4 TTL and IPv6 HopLimit

	// Enhanced OS fingerprinting with TCP layer
	var tcpLayerForOS *layers.TCP
	if tcpPacket := packet.Layer(layers.LayerTypeTCP); tcpPacket != nil {
		tcpLayerForOS, _ = tcpPacket.(*layers.TCP)
	}
	sender.OS = fingerprintOS(sender.TTL, tcpLayerForOS)

	receiver := a.getHost(ep.DstIP)
	receiver.PacketsReceived++

	// MAC Addresses
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		if sender.MAC == "" {
			sender.MAC = eth.SrcMAC.String()
		}
		if receiver.MAC == "" {
			receiver.MAC = eth.DstMAC.String()
		}
	}
}

// compareIP16 compares two [16]byte IPs lexicographically.
// Returns negative if a < b, positive if a > b, 0 if equal.
func compareIP16(a, b [16]byte) int {
	for i := 0; i < 16; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func (a *Analyzer) getHost(ip string) *Host {
	if host, exists := a.Hosts[ip]; exists {
		return host
	}

	host := &Host{
		IP:        ip,
		OpenPorts: []int{},
	}

	// Perform GeoIP lookup if service available
	if a.geoIP != nil {
		if geoInfo, err := a.geoIP.Lookup(ip); err == nil && geoInfo != nil {
			host.Country = geoInfo.Country
			host.CountryISO = geoInfo.CountryISO
			host.City = geoInfo.City
			host.Latitude = geoInfo.Latitude
			host.Longitude = geoInfo.Longitude
			host.ASN = geoInfo.ASN
			host.Organization = geoInfo.Organization
		}
	}

	a.Hosts[ip] = host
	return host
}

func (a *Analyzer) addOpenPort(host *Host, port int) {
	for _, p := range host.OpenPorts {
		if p == port {
			return
		}
	}
	host.OpenPorts = append(host.OpenPorts, port)
	sort.Ints(host.OpenPorts)
}

// Enhanced OS fingerprinting using TTL, TCP Window Size, and other heuristics
func fingerprintOS(ttl int, tcpLayer *layers.TCP) string {
	windowSize := 0
	mss := 0

	if tcpLayer != nil {
		windowSize = int(tcpLayer.Window)

		// Extract MSS from TCP options
		for _, opt := range tcpLayer.Options {
			if opt.OptionType == layers.TCPOptionKind(2) { // MSS option
				if len(opt.OptionData) >= 2 {
					mss = int(opt.OptionData[0])<<8 | int(opt.OptionData[1])
				}
			}
		}
	}

	// REFINED TTL-BASED DETECTION (most reliable indicator)
	// Windows: 128, 64 (modern Windows can use 64 for local)
	// Linux/Unix: 64
	// macOS: 64
	// Cisco/Solaris: 255
	// FreeBSD: 64

	// WINDOWS DETECTION
	if ttl > 64 && ttl <= 128 {
		// Windows typically uses TTL=128
		// Confirm with window size patterns
		if windowSize == 65535 || windowSize == 8192 || windowSize == 64240 {
			if mss == 1460 {
				return "Windows 10/11"
			}
			return "Windows"
		}
		// Server 2016/2019 often uses 8192
		if windowSize == 8192 {
			return "Windows Server"
		}
		return "Windows"
	}

	// LINUX/UNIX/macOS DETECTION (TTL=64)
	if ttl > 32 && ttl <= 64 {
		// Differentiate Linux from macOS using window size
		if windowSize == 65535 {
			return "macOS/iOS"
		}
		if windowSize == 29200 {
			return "Linux (Modern)"
		}
		if windowSize == 5840 || windowSize == 5792 {
			return "Linux (2.4/2.6 kernel)"
		}
		if windowSize >= 14600 && windowSize <= 16384 {
			return "Linux"
		}
		// FreeBSD often uses smaller windows
		if windowSize <= 32768 {
			return "FreeBSD/Linux"
		}
		return "Linux/Unix"
	}

	// CISCO/SOLARIS (TTL=255)
	if ttl > 128 && ttl <= 255 {
		if windowSize == 4128 {
			return "Cisco IOS"
		}
		return "Solaris/Cisco/Network Device"
	}

	// LOW TTL (Might be VM or behind NAT)
	if ttl <= 32 {
		return "Unknown (Low TTL - NAT/VM?)"
	}

	return "Unknown"
}

// GetSortedHosts returns a list of hosts sorted by IP
func (a *Analyzer) GetSortedHosts() []*Host {
	a.mu.Lock()
	defer a.mu.Unlock()

	hosts := make([]*Host, 0, len(a.Hosts))
	for _, h := range a.Hosts {
		hosts = append(hosts, h)
	}

	// Sort by IP (simple string sort for now, ideally numeric)
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].IP < hosts[j].IP
	})

	return hosts
}

// GetTimeline returns sorted timeline buckets
func (a *Analyzer) GetTimeline() []TimeBucket {
	a.mu.Lock()
	defer a.mu.Unlock()

	var buckets []TimeBucket
	var keys []int64
	for k := range a.Timeline {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	for _, k := range keys {
		buckets = append(buckets, *a.Timeline[k])
	}
	return buckets
}

// GetProtocolStats returns stats for charts
func (a *Analyzer) GetProtocolStats() map[string]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ProtocolCounts
}

// GetPortStats returns stats for charts
func (a *Analyzer) GetPortStats() map[int]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.PortCounts
}

// GetSessions returns list of discovered sessions
func (a *Analyzer) GetSessions() []*Session {
	a.mu.Lock()
	defer a.mu.Unlock()

	sessions := make([]*Session, 0, len(a.Sessions))
	for _, s := range a.Sessions {
		sessions = append(sessions, s)
	}
	// Sort by Start Time
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].StartTime.Before(sessions[j].StartTime)
	})
	return sessions
}
