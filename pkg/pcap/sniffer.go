package pcap

import (
	"fmt"
	"io"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// PacketHandler is a callback for processing packets
type PacketHandler func(packet gopacket.Packet)

// Sniffer handles packet capture from files or live interfaces
type Sniffer struct {
	file         *os.File
	reader       *pcapgo.NgReader // NgReader for multi-interface pcapng files
	packetSource *gopacket.PacketSource
}

// OpenFile opens a PCAP/PCAPNG file for reading using pure Go implementation
func OpenFile(filename string) (*Sniffer, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening pcap file: %w", err)
	}

	// Try to detect if it's pcapng format by checking magic bytes
	magic := make([]byte, 4)
	_, err = file.Read(magic)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("error reading file magic: %w", err)
	}
	
	// Reset file pointer to beginning
	_, err = file.Seek(0, 0)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("error seeking file: %w", err)
	}

	// Check for pcapng magic (0a0d0d0a in little-endian)
	isPcapng := (magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a)

	var packetSource *gopacket.PacketSource
	
	if isPcapng {
		// Use NgReader for pcapng files with multi-interface support
		options := pcapgo.NgReaderOptions{
			WantMixedLinkType:          true,  // Enable reading from multiple interfaces
			ErrorOnMismatchingLinkType: false, // Don't error on different link types
		}
		
		ngReader, err := pcapgo.NewNgReader(file, options)
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("error creating pcapng reader: %w", err)
		}
		
		// Store the NgReader so Sniff() can use custom decoding logic
		return &Sniffer{
			file:         file,
			reader:       ngReader,
			packetSource: nil, // Not used for multi-interface pcapng
		}, nil
	} else {
		// Use classic Reader for pcap files
		reader, err := pcapgo.NewReader(file)
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("error creating pcap reader: %w", err)
		}
		packetSource = gopacket.NewPacketSource(reader, reader.LinkType())
	}

	return &Sniffer{
		file:         file,
		reader:       nil, // We don't store the reader anymore as we use packetSource
		packetSource: packetSource,
	}, nil
}

// OpenLive is not yet implemented for pure Go
// TODO: Implement live capture using pcapgo when needed
/*
func OpenLive(device string, snaplen int32, promisc bool, timeout time.Duration) (*Sniffer, error) {
	return nil, fmt.Errorf("live capture not yet implemented")
}
*/

// Sniff starts sending packets to the handler channel
// It runs until the packet source is exhausted or the context is cancelled
func (s *Sniffer) Sniff(handler PacketHandler) error {
	// Check if we have an NgReader (for multi-interface support)
	if s.reader != nil {
		// Custom decoding for pcapng with multiple interfaces/link types
		return s.sniffNg(handler)
	}
	
	// Standard packet source for regular pcap files
	count := 0
	for {
		packet, err := s.packetSource.NextPacket()
		if err != nil {
			if err == io.EOF {
				if count == 0 {
					return fmt.Errorf("EOF encountered immediately (0 packets read). Check file format or permissions.")
				}
				return nil
			}
			return fmt.Errorf("error at packet %d: %v", count, err)
		}
		count++
		handler(packet)
	}
}

// sniffNg handles pcapng files with mixed link types
func (s *Sniffer) sniffNg(handler PacketHandler) error {
	count := 0
	for {
		data, ci, err := s.reader.ZeroCopyReadPacketData()
		if err != nil {
			if err == io.EOF {
				if count == 0 {
					return fmt.Errorf("EOF encountered immediately (0 packets read)")
				}
				return nil
			}
			return fmt.Errorf("error reading packet %d: %v", count, err)
		}
		
		// Get link type from ancillary data (set when WantMixedLinkType is true)
		linkType := s.reader.LinkType()
		if len(ci.AncillaryData) > 0 {
			// AncillaryData[0] contains the actual link type for this packet
			if lt, ok := ci.AncillaryData[0].(layers.LinkType); ok {
				linkType = lt
			}
		}
		
		// Manually decode packet with correct link type
		packet := gopacket.NewPacket(data, linkType, gopacket.DecodeOptions{
			Lazy:   false,
			NoCopy: true,
		})
		
		// Set metadata
		packet.Metadata().Timestamp = ci.Timestamp
		packet.Metadata().CaptureInfo = ci
		
		count++
		handler(packet)
	}
}

// Close closes the file handle
func (s *Sniffer) Close() {
	if s.file != nil {
		s.file.Close()
	}
}
