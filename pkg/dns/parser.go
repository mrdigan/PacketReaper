package dns

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Record represents a DNS query or response
type Record struct {
	Timestamp   string `json:"timestamp"`
	srcIP       string
	dstIP       string
	TransactionID uint16 `json:"transaction_id"`
	Query       string `json:"query"`
	Type        string `json:"type"` // A, AAAA, MX, etc.
	Answers     string `json:"answers"` // Formatted string of answers
	ResponseCode string `json:"response_code"`
	IsResponse  bool   `json:"is_response"`
}

// Parser handles DNS packet parsing
type Parser struct {
	Records []Record
}

func NewParser() *Parser {
	return &Parser{
		Records: []Record{},
	}
}

// ParsePacket extracts DNS data from a packet
func (p *Parser) ParsePacket(packet gopacket.Packet) {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	
	dns, _ := dnsLayer.(*layers.DNS)
	
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	var src, dst string
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		src = ip.SrcIP.String()
		dst = ip.DstIP.String()
	}

	// We only care if there are questions or answers
	if dns.QDCount == 0 && dns.ANCount == 0 {
		return
	}

	record := Record{
		Timestamp:     packet.Metadata().Timestamp.String(),
		srcIP:         src,
		dstIP:         dst,
		TransactionID: dns.ID,
		IsResponse:    dns.QR,
		ResponseCode:  dns.ResponseCode.String(),
	}

	// Questions
	var queries []string
	for _, q := range dns.Questions {
		queries = append(queries, fmt.Sprintf("%s (%s)", string(q.Name), q.Type))
	}
	record.Query = strings.Join(queries, ", ")
	if len(dns.Questions) > 0 {
		record.Type = dns.Questions[0].Type.String()
	}

	// Answers
	var answers []string
	for _, a := range dns.Answers {
		if a.IP.String() != "<nil>" {
			answers = append(answers, fmt.Sprintf("%s -> %s", string(a.Name), a.IP))
		} else if a.CNAME != nil {
			answers = append(answers, fmt.Sprintf("%s -> CNAME %s", string(a.Name), string(a.CNAME)))
		} else {
			answers = append(answers, fmt.Sprintf("%s", string(a.Name)))
		}
	}
	record.Answers = strings.Join(answers, ", ")

	p.Records = append(p.Records, record)
}
