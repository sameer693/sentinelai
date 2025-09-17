package capture

import (
	"context"
	"fmt"
	"strings"
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

	// If interface is "eth0" (Linux default), try to find a suitable Windows interface
	if s.interface_ == "eth0" {
		if winInterface := s.findWindowsInterface(); winInterface != "" {
			s.logger.WithFields(logrus.Fields{
				"original_interface": s.interface_,
				"detected_interface": winInterface,
			}).Info("Detected Windows environment, using appropriate interface")
			s.interface_ = winInterface
		}
	}

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

// findWindowsInterface attempts to find a suitable network interface on Windows
func (s *Service) findWindowsInterface() string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		s.logger.WithError(err).Warn("Failed to enumerate network devices")
		return ""
	}

	s.logger.WithField("device_count", len(devices)).Debug("Found network devices")

	// Look for active network interfaces
	for _, device := range devices {
		// Skip loopback interfaces
		if strings.Contains(device.Name, "Loopback") {
			continue
		}

		// Look for interfaces with IP addresses (likely active)
		if len(device.Addresses) > 0 {
			for _, addr := range device.Addresses {
				// Check if it's not a loopback address
				if addr.IP != nil && !addr.IP.IsLoopback() {
					s.logger.WithFields(logrus.Fields{
						"device_name": device.Name,
						"description": device.Description,
						"ip_address":  addr.IP.String(),
					}).Info("Found suitable network interface")
					return device.Name
				}
			}
		}
	}

	s.logger.Warn("No suitable network interface found, trying first non-loopback device")

	// Fallback: use first non-loopback device
	for _, device := range devices {
		if !strings.Contains(device.Name, "Loopback") {
			s.logger.WithFields(logrus.Fields{
				"device_name": device.Name,
				"description": device.Description,
			}).Info("Using fallback network interface")
			return device.Name
		}
	}

	return ""
}
