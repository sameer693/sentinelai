package capture

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// TLSExtractor handles TLS metadata extraction and JA3 fingerprinting
type TLSExtractor struct{}

// TLSMetadata contains extracted TLS handshake information
type TLSMetadata struct {
	SNI                       string
	JA3                       string
	JA3S                      string
	TLSVersion                uint16
	CipherSuites              []uint16
	Extensions                []uint16
	EllipticCurves            []uint16
	EllipticCurvePointFormats []uint8
	ServerCipherSuite         uint16
	ServerExtensions          []uint16
}

// NewTLSExtractor creates a new TLS metadata extractor
func NewTLSExtractor() *TLSExtractor {
	return &TLSExtractor{}
}

// ExtractTLSMetadata extracts TLS metadata from a packet
func (e *TLSExtractor) ExtractTLSMetadata(packet gopacket.Packet) *TLSMetadata {
	// Check if packet contains TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return nil
	}

	// Check for TLS traffic (commonly on ports 443, 993, 995, etc.)
	if !e.isTLSPort(tcp.DstPort) && !e.isTLSPort(tcp.SrcPort) {
		return nil
	}

	// Get application layer payload
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return nil
	}

	payload := appLayer.Payload()
	if len(payload) < 5 {
		return nil
	}

	// Check for TLS handshake record (0x16)
	if payload[0] != 0x16 {
		return nil
	}

	return e.parseTLSHandshake(payload)
}

// isTLSPort checks if the port is commonly used for TLS
func (e *TLSExtractor) isTLSPort(port layers.TCPPort) bool {
	tlsPorts := map[layers.TCPPort]bool{
		443:  true, // HTTPS
		993:  true, // IMAPS
		995:  true, // POP3S
		465:  true, // SMTPS
		587:  true, // SMTP with STARTTLS
		636:  true, // LDAPS
		989:  true, // FTPS Data
		990:  true, // FTPS Control
		8443: true, // Alternative HTTPS
	}
	return tlsPorts[port]
}

// parseTLSHandshake parses TLS handshake data
func (e *TLSExtractor) parseTLSHandshake(payload []byte) *TLSMetadata {
	if len(payload) < 43 { // Minimum size for a ClientHello
		return nil
	}

	metadata := &TLSMetadata{}

	// Parse TLS record header
	// payload[0] = Content Type (0x16 for handshake)
	// payload[1:3] = TLS Version
	// payload[3:5] = Length

	if len(payload) < 5 {
		return nil
	}

	metadata.TLSVersion = uint16(payload[1])<<8 | uint16(payload[2])
	recordLength := int(payload[3])<<8 | int(payload[4])

	if len(payload) < 5+recordLength {
		return nil
	}

	// Parse handshake message
	handshakeData := payload[5:]
	if len(handshakeData) < 4 {
		return nil
	}

	handshakeType := handshakeData[0]

	switch handshakeType {
	case 0x01: // ClientHello
		e.parseClientHello(handshakeData, metadata)
	case 0x02: // ServerHello
		e.parseServerHello(handshakeData, metadata)
	}

	return metadata
}

// parseClientHello parses ClientHello message for JA3 fingerprinting
func (e *TLSExtractor) parseClientHello(data []byte, metadata *TLSMetadata) {
	if len(data) < 38 {
		return
	}

	offset := 6 // Skip handshake header and version

	// Skip random (32 bytes)
	offset += 32

	if offset >= len(data) {
		return
	}

	// Session ID length
	sessionIDLength := int(data[offset])
	offset += 1 + sessionIDLength

	if offset+2 > len(data) {
		return
	}

	// Cipher suites length
	cipherSuitesLength := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	if offset+cipherSuitesLength > len(data) {
		return
	}

	// Parse cipher suites
	for i := 0; i < cipherSuitesLength; i += 2 {
		if offset+i+1 < len(data) {
			cipherSuite := uint16(data[offset+i])<<8 | uint16(data[offset+i+1])
			metadata.CipherSuites = append(metadata.CipherSuites, cipherSuite)
		}
	}
	offset += cipherSuitesLength

	if offset >= len(data) {
		return
	}

	// Compression methods length
	compressionLength := int(data[offset])
	offset += 1 + compressionLength

	if offset+2 > len(data) {
		return
	}

	// Extensions length
	extensionsLength := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	if offset+extensionsLength > len(data) {
		return
	}

	// Parse extensions
	e.parseExtensions(data[offset:offset+extensionsLength], metadata)

	// Generate JA3 fingerprint
	metadata.JA3 = e.generateJA3(metadata)
}

// parseServerHello parses ServerHello message for JA3S fingerprinting
func (e *TLSExtractor) parseServerHello(data []byte, metadata *TLSMetadata) {
	if len(data) < 38 {
		return
	}

	offset := 6 // Skip handshake header and version

	// Skip random (32 bytes)
	offset += 32

	if offset >= len(data) {
		return
	}

	// Session ID length
	sessionIDLength := int(data[offset])
	offset += 1 + sessionIDLength

	if offset+2 > len(data) {
		return
	}

	// Selected cipher suite
	metadata.ServerCipherSuite = uint16(data[offset])<<8 | uint16(data[offset+1])
	offset += 2

	// Compression method
	offset += 1

	if offset+2 > len(data) {
		return
	}

	// Extensions length
	extensionsLength := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	if offset+extensionsLength <= len(data) {
		e.parseServerExtensions(data[offset:offset+extensionsLength], metadata)
	}

	// Generate JA3S fingerprint
	metadata.JA3S = e.generateJA3S(metadata)
}

// parseExtensions parses TLS extensions from ClientHello
func (e *TLSExtractor) parseExtensions(extensionsData []byte, metadata *TLSMetadata) {
	offset := 0

	for offset+4 <= len(extensionsData) {
		extensionType := uint16(extensionsData[offset])<<8 | uint16(extensionsData[offset+1])
		extensionLength := int(extensionsData[offset+2])<<8 | int(extensionsData[offset+3])
		offset += 4

		if offset+extensionLength > len(extensionsData) {
			break
		}

		metadata.Extensions = append(metadata.Extensions, extensionType)

		// Parse specific extensions
		switch extensionType {
		case 0x0000: // Server Name Indication (SNI)
			if extensionLength > 5 {
				e.parseSNI(extensionsData[offset:offset+extensionLength], metadata)
			}
		case 0x000a: // Supported Groups (Elliptic Curves)
			e.parseEllipticCurves(extensionsData[offset:offset+extensionLength], metadata)
		case 0x000b: // EC Point Formats
			e.parseECPointFormats(extensionsData[offset:offset+extensionLength], metadata)
		}

		offset += extensionLength
	}
}

// parseServerExtensions parses TLS extensions from ServerHello
func (e *TLSExtractor) parseServerExtensions(extensionsData []byte, metadata *TLSMetadata) {
	offset := 0

	for offset+4 <= len(extensionsData) {
		extensionType := uint16(extensionsData[offset])<<8 | uint16(extensionsData[offset+1])
		extensionLength := int(extensionsData[offset+2])<<8 | int(extensionsData[offset+3])
		offset += 4

		if offset+extensionLength > len(extensionsData) {
			break
		}

		metadata.ServerExtensions = append(metadata.ServerExtensions, extensionType)
		offset += extensionLength
	}
}

// parseSNI extracts Server Name Indication from extension
func (e *TLSExtractor) parseSNI(sniData []byte, metadata *TLSMetadata) {
	if len(sniData) < 5 {
		return
	}

	// SNI list length
	offset := 2

	if offset+3 > len(sniData) {
		return
	}

	// Name type (should be 0 for hostname)
	nameType := sniData[offset]
	if nameType != 0 {
		return
	}
	offset++

	// Hostname length
	hostnameLength := int(sniData[offset])<<8 | int(sniData[offset+1])
	offset += 2

	if offset+hostnameLength > len(sniData) {
		return
	}

	metadata.SNI = string(sniData[offset : offset+hostnameLength])
}

// parseEllipticCurves extracts supported elliptic curves
func (e *TLSExtractor) parseEllipticCurves(data []byte, metadata *TLSMetadata) {
	if len(data) < 2 {
		return
	}

	listLength := int(data[0])<<8 | int(data[1])
	offset := 2

	for offset+2 <= len(data) && offset < 2+listLength {
		curve := uint16(data[offset])<<8 | uint16(data[offset+1])
		metadata.EllipticCurves = append(metadata.EllipticCurves, curve)
		offset += 2
	}
}

// parseECPointFormats extracts EC point formats
func (e *TLSExtractor) parseECPointFormats(data []byte, metadata *TLSMetadata) {
	if len(data) < 1 {
		return
	}

	listLength := int(data[0])
	offset := 1

	for i := 0; i < listLength && offset < len(data); i++ {
		format := data[offset]
		metadata.EllipticCurvePointFormats = append(metadata.EllipticCurvePointFormats, format)
		offset++
	}
}

// generateJA3 generates JA3 fingerprint from ClientHello data
func (e *TLSExtractor) generateJA3(metadata *TLSMetadata) string {
	// JA3 format: TLSVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats

	// TLS Version
	tlsVersion := strconv.Itoa(int(metadata.TLSVersion))

	// Cipher Suites
	cipherSuites := make([]string, len(metadata.CipherSuites))
	for i, cs := range metadata.CipherSuites {
		cipherSuites[i] = strconv.Itoa(int(cs))
	}

	// Extensions
	extensions := make([]string, len(metadata.Extensions))
	for i, ext := range metadata.Extensions {
		extensions[i] = strconv.Itoa(int(ext))
	}

	// Elliptic Curves
	ellipticCurves := make([]string, len(metadata.EllipticCurves))
	for i, ec := range metadata.EllipticCurves {
		ellipticCurves[i] = strconv.Itoa(int(ec))
	}

	// Elliptic Curve Point Formats
	ecPointFormats := make([]string, len(metadata.EllipticCurvePointFormats))
	for i, format := range metadata.EllipticCurvePointFormats {
		ecPointFormats[i] = strconv.Itoa(int(format))
	}

	// Create JA3 string
	ja3String := fmt.Sprintf("%s,%s,%s,%s,%s",
		tlsVersion,
		strings.Join(cipherSuites, "-"),
		strings.Join(extensions, "-"),
		strings.Join(ellipticCurves, "-"),
		strings.Join(ecPointFormats, "-"))

	// Generate MD5 hash
	hash := md5.Sum([]byte(ja3String))
	return hex.EncodeToString(hash[:])
}

// generateJA3S generates JA3S fingerprint from ServerHello data
func (e *TLSExtractor) generateJA3S(metadata *TLSMetadata) string {
	// JA3S format: TLSVersion,CipherSuite,Extensions

	// TLS Version
	tlsVersion := strconv.Itoa(int(metadata.TLSVersion))

	// Selected Cipher Suite
	cipherSuite := strconv.Itoa(int(metadata.ServerCipherSuite))

	// Server Extensions
	extensions := make([]string, len(metadata.ServerExtensions))
	for i, ext := range metadata.ServerExtensions {
		extensions[i] = strconv.Itoa(int(ext))
	}

	// Create JA3S string
	ja3sString := fmt.Sprintf("%s,%s,%s",
		tlsVersion,
		cipherSuite,
		strings.Join(extensions, "-"))

	// Generate MD5 hash
	hash := md5.Sum([]byte(ja3sString))
	return hex.EncodeToString(hash[:])
}

// FlowTracker tracks network flows and their metadata
type FlowTracker struct {
	flows     map[string]*FlowMetadata
	extractor *TLSExtractor
}

// NewFlowTracker creates a new flow tracker
func NewFlowTracker() *FlowTracker {
	return &FlowTracker{
		flows:     make(map[string]*FlowMetadata),
		extractor: NewTLSExtractor(),
	}
}

// ProcessPacket processes a packet and updates flow information
func (ft *FlowTracker) ProcessPacket(packet gopacket.Packet) *FlowMetadata {
	// Extract basic flow information
	flowID := ft.extractFlowID(packet)
	if flowID == "" {
		return nil
	}

	// Get or create flow
	flow, exists := ft.flows[flowID]
	if !exists {
		flow = &FlowMetadata{
			FlowID:      flowID,
			Timestamps:  []time.Time{},
			PacketSizes: []int{},
		}
		ft.extractBasicInfo(packet, flow)
		ft.flows[flowID] = flow
	}

	// Update flow with packet data
	flow.Timestamps = append(flow.Timestamps, time.Now())
	flow.PacketSizes = append(flow.PacketSizes, len(packet.Data()))
	flow.TotalBytes += uint64(len(packet.Data()))

	if len(flow.Timestamps) > 1 {
		flow.Duration = flow.Timestamps[len(flow.Timestamps)-1].Sub(flow.Timestamps[0])
	}

	// Extract TLS metadata if available
	if tlsMetadata := ft.extractor.ExtractTLSMetadata(packet); tlsMetadata != nil {
		flow.SNI = tlsMetadata.SNI
		flow.JA3Hash = tlsMetadata.JA3
		flow.JA3SHash = tlsMetadata.JA3S
	}

	return flow
}

// extractFlowID generates a unique flow identifier
func (ft *FlowTracker) extractFlowID(packet gopacket.Packet) string {
	// Get network layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		// Try IPv6
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
		if ipLayer == nil {
			return ""
		}
	}

	// Get transport layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		if ip4, ok := ipLayer.(*layers.IPv4); ok {
			return fmt.Sprintf("%s:%d-%s:%d-tcp",
				ip4.SrcIP.String(), tcp.SrcPort,
				ip4.DstIP.String(), tcp.DstPort)
		}
		if ip6, ok := ipLayer.(*layers.IPv6); ok {
			return fmt.Sprintf("%s:%d-%s:%d-tcp",
				ip6.SrcIP.String(), tcp.SrcPort,
				ip6.DstIP.String(), tcp.DstPort)
		}
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		if ip4, ok := ipLayer.(*layers.IPv4); ok {
			return fmt.Sprintf("%s:%d-%s:%d-udp",
				ip4.SrcIP.String(), udp.SrcPort,
				ip4.DstIP.String(), udp.DstPort)
		}
		if ip6, ok := ipLayer.(*layers.IPv6); ok {
			return fmt.Sprintf("%s:%d-%s:%d-udp",
				ip6.SrcIP.String(), udp.SrcPort,
				ip6.DstIP.String(), udp.DstPort)
		}
	}

	return ""
}

// extractBasicInfo extracts basic flow information from packet
func (ft *FlowTracker) extractBasicInfo(packet gopacket.Packet, flow *FlowMetadata) {
	// Extract IP addresses and ports
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		flow.SourceIP = ip.SrcIP.String()
		flow.DestIP = ip.DstIP.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip := ipLayer.(*layers.IPv6)
		flow.SourceIP = ip.SrcIP.String()
		flow.DestIP = ip.DstIP.String()
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		flow.SourcePort = uint16(tcp.SrcPort)
		flow.DestPort = uint16(tcp.DstPort)
		flow.Protocol = "TCP"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		flow.SourcePort = uint16(udp.SrcPort)
		flow.DestPort = uint16(udp.DstPort)
		flow.Protocol = "UDP"
	}
}

// GetFlow returns a flow by ID
func (ft *FlowTracker) GetFlow(flowID string) *FlowMetadata {
	return ft.flows[flowID]
}

// GetAllFlows returns all tracked flows
func (ft *FlowTracker) GetAllFlows() map[string]*FlowMetadata {
	return ft.flows
}

// CleanupExpiredFlows removes expired flows
func (ft *FlowTracker) CleanupExpiredFlows(maxAge time.Duration) {
	expiredTime := time.Now().Add(-maxAge)

	for flowID, flow := range ft.flows {
		if len(flow.Timestamps) > 0 {
			lastSeen := flow.Timestamps[len(flow.Timestamps)-1]
			if lastSeen.Before(expiredTime) {
				delete(ft.flows, flowID)
			}
		}
	}
}
