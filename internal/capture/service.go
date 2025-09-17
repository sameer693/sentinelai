package capture

import (
	"context"
	"fmt"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

// Service handles network packet capture and analysis
type Service struct {
	interface_ string
	logger     *logrus.Logger
	handle     *pcap.Handle
	packetChan chan gopacket.Packet
	stats      *CaptureStats
}

// CaptureStats holds packet capture statistics
type CaptureStats struct {
	PacketsCaptured uint64
	BytesCaptured   uint64
	PacketsDropped  uint64
	StartTime       time.Time
}

// FlowMetadata represents extracted metadata from network flows
type FlowMetadata struct {
	SourceIP    string
	DestIP      string
	SourcePort  uint16
	DestPort    uint16
	Protocol    string
	SNI         string
	JA3Hash     string
	JA3SHash    string
	PacketSizes []int
	Timestamps  []time.Time
	TotalBytes  uint64
	Duration    time.Duration
	FlowID      string
}

// NewService creates a new packet capture service
func NewService(iface string, logger *logrus.Logger) *Service {
	return &Service{
		interface_: iface,
		logger:     logger,
		packetChan: make(chan gopacket.Packet, 1000),
		stats: &CaptureStats{
			StartTime: time.Now(),
		},
	}
}

// Start begins packet capture on the specified interface
func (s *Service) Start(ctx context.Context) error {
	s.logger.WithField("interface", s.interface_).Info("Starting packet capture")

	// Open device for packet capture
	handle, err := pcap.OpenLive(s.interface_, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open capture device: %w", err)
	}
	s.handle = handle
	defer handle.Close()

	// Set BPF filter for relevant traffic (TCP/UDP)
	if err := handle.SetBPFFilter("tcp or udp"); err != nil {
		s.logger.WithError(err).Warn("Failed to set BPF filter, capturing all traffic")
	}

	// Create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	s.logger.Info("Packet capture started successfully")

	// Start packet processing goroutines
	go s.processPackets(ctx)

	// Capture packets
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("Stopping packet capture")
			return nil
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}

			// Update statistics
			s.stats.PacketsCaptured++
			s.stats.BytesCaptured += uint64(len(packet.Data()))

			// Send packet for processing
			select {
			case s.packetChan <- packet:
			default:
				s.stats.PacketsDropped++
				s.logger.Debug("Dropped packet due to full channel")
			}
		}
	}
}

// processPackets processes captured packets and extracts flow metadata
func (s *Service) processPackets(ctx context.Context) {
	flowTracker := NewFlowTracker()
	ticker := time.NewTicker(30 * time.Second) // Flow cleanup interval
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-s.packetChan:
			// Process packet and update flow information
			flowMetadata := flowTracker.ProcessPacket(packet)
			if flowMetadata != nil {
				s.logger.WithFields(map[string]interface{}{
					"flow_id":     flowMetadata.FlowID,
					"source_ip":   flowMetadata.SourceIP,
					"dest_ip":     flowMetadata.DestIP,
					"dest_port":   flowMetadata.DestPort,
					"protocol":    flowMetadata.Protocol,
					"sni":         flowMetadata.SNI,
					"ja3":         flowMetadata.JA3Hash,
					"total_bytes": flowMetadata.TotalBytes,
				}).Debug("Flow metadata extracted")

				// TODO: Send flow metadata to NGFW engine for analysis
				// This would be integrated with the NGFW engine
			}
		case <-ticker.C:
			// Cleanup expired flows
			flowTracker.CleanupExpiredFlows(5 * time.Minute)
		}
	}
}

// GetStats returns current capture statistics
func (s *Service) GetStats() *CaptureStats {
	return s.stats
}
