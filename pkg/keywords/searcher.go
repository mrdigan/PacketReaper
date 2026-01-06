package keywords

import (
	"github.com/google/gopacket"
	"strings"
)

// Match represents a keyword found in a packet
type Match struct {
	Keyword   string `json:"keyword"`
	Context   string `json:"context"`
	FrameNum  int    `json:"frame_num"`
	Timestamp string `json:"timestamp"`
}

// Searcher handles searching for keywords in packets
type Searcher struct {
	Keywords []string
	Matches  []Match
}

func NewSearcher(keywords []string) *Searcher {
	return &Searcher{
		Keywords: keywords,
		Matches:  []Match{},
	}
}

// ScanPacket checks for keywords in the packet payload
func (s *Searcher) ScanPacket(packet gopacket.Packet, frameNum int) {
	if len(s.Keywords) == 0 {
		return
	}

	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return
	}
	payload := appLayer.Payload()
	if len(payload) == 0 {
		return
	}

	text := string(payload)
	// Simple case-insensitive search? Or exact?
	// NetworkMiner defaults to exact but allows case-insensitive.
	// Let's do simple Contains for now.

	for _, kw := range s.Keywords {
		if strings.Contains(text, kw) {
			s.addMatch(kw, text, frameNum, packet.Metadata().Timestamp.String())
		}
	}
}

func (s *Searcher) addMatch(keyword, text string, frameNum int, timestamp string) {
	// Extract context (e.g. 20 chars around match)
	idx := strings.Index(text, keyword)
	start := idx - 20
	if start < 0 {
		start = 0
	}
	end := idx + len(keyword) + 20
	if end > len(text) {
		end = len(text)
	}
	context := text[start:end]

	// Clean context for specific chars if needed make it readable
	context = strings.ReplaceAll(context, "\r", " ")
	context = strings.ReplaceAll(context, "\n", " ")

	s.Matches = append(s.Matches, Match{
		Keyword:   keyword,
		Context:   "..." + context + "...",
		FrameNum:  frameNum,
		Timestamp: timestamp,
	})
}
