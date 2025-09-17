package features

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"time"

	"masswall/internal/capture"
	"masswall/internal/ml"
)

// Extractor handles feature extraction from network flow metadata
type Extractor struct {
	windowSize int // Number of packets to consider for statistical features
}

// StatisticalFeatures represents statistical analysis of packet data
type StatisticalFeatures struct {
	Mean              float64
	Median            float64
	StandardDeviation float64
	Variance          float64
	Skewness          float64
	Kurtosis          float64
	Min               float64
	Max               float64
	Q1                float64 // First quartile
	Q3                float64 // Third quartile
	IQR               float64 // Interquartile range
}

// TimingFeatures represents timing-based features
type TimingFeatures struct {
	InterArrivalMean float64
	InterArrivalStd  float64
	BurstinessIndex  float64 // Measure of traffic burstiness
	PeriodicityScore float64 // Measure of periodic patterns
	IdleTimeRatio    float64 // Ratio of idle time to active time
}

// TLSFeatures represents TLS-specific features
type TLSFeatures struct {
	HasSNI           bool
	SNIEntropy       float64
	JA3Present       bool
	JA3SPresent      bool
	TLSVersionScore  float64 // Normalized TLS version score
	CipherStrength   float64 // Estimated cipher strength
	ExtensionCount   int
	ExtensionEntropy float64
}

// NewExtractor creates a new feature extractor
func NewExtractor(windowSize int) *Extractor {
	if windowSize <= 0 {
		windowSize = 50 // Default window size
	}
	return &Extractor{
		windowSize: windowSize,
	}
}

// ExtractFeatures extracts ML features from flow metadata
func (e *Extractor) ExtractFeatures(flowMetadata *capture.FlowMetadata) *ml.FeatureVector {
	if flowMetadata == nil || len(flowMetadata.PacketSizes) == 0 {
		return nil
	}

	features := &ml.FeatureVector{
		FlowID:   flowMetadata.FlowID,
		SNI:      flowMetadata.SNI,
		Protocol: flowMetadata.Protocol,
		JA3Hash:  flowMetadata.JA3Hash,
		JA3SHash: flowMetadata.JA3SHash,
	}

	// Basic flow features
	features.TotalBytes = float64(flowMetadata.TotalBytes)
	features.PacketCount = float64(len(flowMetadata.PacketSizes))
	features.PortNumber = float64(flowMetadata.DestPort)

	if len(flowMetadata.Timestamps) > 1 {
		features.FlowDuration = flowMetadata.Duration.Seconds()
	}

	// Convert packet sizes to float64
	packetSizes := make([]float64, len(flowMetadata.PacketSizes))
	for i, size := range flowMetadata.PacketSizes {
		packetSizes[i] = float64(size)
	}
	features.PacketSizes = packetSizes

	// Extract inter-arrival times
	if len(flowMetadata.Timestamps) > 1 {
		features.InterArrivalTimes = e.extractInterArrivalTimes(flowMetadata.Timestamps)
	}

	return features
}

// ExtractAdvancedFeatures extracts advanced statistical and behavioral features
func (e *Extractor) ExtractAdvancedFeatures(flowMetadata *capture.FlowMetadata) map[string]float64 {
	features := make(map[string]float64)

	if flowMetadata == nil || len(flowMetadata.PacketSizes) == 0 {
		return features
	}

	// Convert to float64 for calculations
	packetSizes := make([]float64, len(flowMetadata.PacketSizes))
	for i, size := range flowMetadata.PacketSizes {
		packetSizes[i] = float64(size)
	}

	// Packet size statistics
	sizeStats := e.calculateStatistics(packetSizes)
	features["pkt_size_mean"] = sizeStats.Mean
	features["pkt_size_std"] = sizeStats.StandardDeviation
	features["pkt_size_median"] = sizeStats.Median
	features["pkt_size_variance"] = sizeStats.Variance
	features["pkt_size_skewness"] = sizeStats.Skewness
	features["pkt_size_kurtosis"] = sizeStats.Kurtosis
	features["pkt_size_min"] = sizeStats.Min
	features["pkt_size_max"] = sizeStats.Max
	features["pkt_size_range"] = sizeStats.Max - sizeStats.Min
	features["pkt_size_iqr"] = sizeStats.IQR

	// Timing features if available
	if len(flowMetadata.Timestamps) > 1 {
		interArrivals := e.extractInterArrivalTimes(flowMetadata.Timestamps)
		if len(interArrivals) > 0 {
			timingFeatures := e.extractTimingFeatures(interArrivals)
			features["iat_mean"] = timingFeatures.InterArrivalMean
			features["iat_std"] = timingFeatures.InterArrivalStd
			features["burstiness"] = timingFeatures.BurstinessIndex
			features["periodicity"] = timingFeatures.PeriodicityScore
			features["idle_ratio"] = timingFeatures.IdleTimeRatio
		}
	}

	// TLS-specific features
	tlsFeatures := e.extractTLSFeatures(flowMetadata)
	features["has_sni"] = boolToFloat(tlsFeatures.HasSNI)
	features["sni_entropy"] = tlsFeatures.SNIEntropy
	features["ja3_present"] = boolToFloat(tlsFeatures.JA3Present)
	features["ja3s_present"] = boolToFloat(tlsFeatures.JA3SPresent)
	features["tls_version_score"] = tlsFeatures.TLSVersionScore
	features["cipher_strength"] = tlsFeatures.CipherStrength
	features["extension_count"] = float64(tlsFeatures.ExtensionCount)
	features["extension_entropy"] = tlsFeatures.ExtensionEntropy

	// Flow-level features
	if features["pkt_size_mean"] > 0 {
		features["bytes_per_packet"] = features["pkt_size_mean"]
	}

	if flowMetadata.Duration.Seconds() > 0 {
		features["packets_per_second"] = float64(len(flowMetadata.PacketSizes)) / flowMetadata.Duration.Seconds()
		features["bytes_per_second"] = float64(flowMetadata.TotalBytes) / flowMetadata.Duration.Seconds()
	}

	// Protocol-specific features
	features["is_tcp"] = boolToFloat(flowMetadata.Protocol == "TCP")
	features["is_udp"] = boolToFloat(flowMetadata.Protocol == "UDP")
	features["is_common_port"] = boolToFloat(e.isCommonPort(flowMetadata.DestPort))
	features["is_ephemeral_port"] = boolToFloat(flowMetadata.DestPort >= 32768)

	// Behavioral features
	features["small_packet_ratio"] = e.calculateSmallPacketRatio(packetSizes)
	features["large_packet_ratio"] = e.calculateLargePacketRatio(packetSizes)
	features["packet_size_entropy"] = e.calculateEntropy(packetSizes)

	return features
}

// extractInterArrivalTimes calculates inter-arrival times between packets
func (e *Extractor) extractInterArrivalTimes(timestamps []time.Time) []float64 {
	if len(timestamps) < 2 {
		return []float64{}
	}

	interArrivals := make([]float64, len(timestamps)-1)
	for i := 1; i < len(timestamps); i++ {
		interArrivals[i-1] = timestamps[i].Sub(timestamps[i-1]).Seconds()
	}

	return interArrivals
}

// calculateStatistics computes statistical features for a data series
func (e *Extractor) calculateStatistics(data []float64) *StatisticalFeatures {
	if len(data) == 0 {
		return &StatisticalFeatures{}
	}

	// Sort data for percentile calculations
	sortedData := make([]float64, len(data))
	copy(sortedData, data)
	sort.Float64s(sortedData)

	stats := &StatisticalFeatures{}

	// Basic statistics
	sum := 0.0
	for _, val := range data {
		sum += val
	}
	stats.Mean = sum / float64(len(data))
	stats.Min = sortedData[0]
	stats.Max = sortedData[len(sortedData)-1]

	// Median
	if len(sortedData)%2 == 0 {
		stats.Median = (sortedData[len(sortedData)/2-1] + sortedData[len(sortedData)/2]) / 2
	} else {
		stats.Median = sortedData[len(sortedData)/2]
	}

	// Quartiles
	q1Index := len(sortedData) / 4
	q3Index := 3 * len(sortedData) / 4
	if q1Index < len(sortedData) {
		stats.Q1 = sortedData[q1Index]
	}
	if q3Index < len(sortedData) {
		stats.Q3 = sortedData[q3Index]
	}
	stats.IQR = stats.Q3 - stats.Q1

	// Variance and standard deviation
	sumSquares := 0.0
	for _, val := range data {
		diff := val - stats.Mean
		sumSquares += diff * diff
	}
	stats.Variance = sumSquares / float64(len(data))
	stats.StandardDeviation = math.Sqrt(stats.Variance)

	// Skewness and kurtosis
	if stats.StandardDeviation > 0 {
		sumCubes := 0.0
		sumFourths := 0.0
		for _, val := range data {
			normalized := (val - stats.Mean) / stats.StandardDeviation
			sumCubes += normalized * normalized * normalized
			sumFourths += normalized * normalized * normalized * normalized
		}
		stats.Skewness = sumCubes / float64(len(data))
		stats.Kurtosis = (sumFourths / float64(len(data))) - 3.0 // Excess kurtosis
	}

	return stats
}

// extractTimingFeatures extracts timing-based behavioral features
func (e *Extractor) extractTimingFeatures(interArrivals []float64) *TimingFeatures {
	if len(interArrivals) == 0 {
		return &TimingFeatures{}
	}

	stats := e.calculateStatistics(interArrivals)

	features := &TimingFeatures{
		InterArrivalMean: stats.Mean,
		InterArrivalStd:  stats.StandardDeviation,
	}

	// Burstiness index (coefficient of variation)
	if stats.Mean > 0 {
		features.BurstinessIndex = stats.StandardDeviation / stats.Mean
	}

	// Simple periodicity score based on autocorrelation at lag 1
	if len(interArrivals) > 1 {
		features.PeriodicityScore = e.calculateAutocorrelation(interArrivals, 1)
	}

	// Idle time ratio (proportion of long inter-arrival times)
	threshold := stats.Mean + 2*stats.StandardDeviation
	idleCount := 0
	for _, iat := range interArrivals {
		if iat > threshold {
			idleCount++
		}
	}
	features.IdleTimeRatio = float64(idleCount) / float64(len(interArrivals))

	return features
}

// extractTLSFeatures extracts TLS-specific features
func (e *Extractor) extractTLSFeatures(flowMetadata *capture.FlowMetadata) *TLSFeatures {
	features := &TLSFeatures{}

	// SNI features
	features.HasSNI = flowMetadata.SNI != ""
	if features.HasSNI {
		features.SNIEntropy = e.calculateStringEntropy(flowMetadata.SNI)
	}

	// JA3/JA3S features
	features.JA3Present = flowMetadata.JA3Hash != ""
	features.JA3SPresent = flowMetadata.JA3SHash != ""

	// Placeholder for TLS version and cipher strength scoring
	// In a real implementation, these would analyze actual TLS handshake data
	features.TLSVersionScore = 0.8 // Default score
	features.CipherStrength = 0.9  // Default strength

	return features
}

// calculateAutocorrelation calculates autocorrelation at a given lag
func (e *Extractor) calculateAutocorrelation(data []float64, lag int) float64 {
	if len(data) <= lag {
		return 0.0
	}

	// Calculate mean
	sum := 0.0
	for _, val := range data {
		sum += val
	}
	mean := sum / float64(len(data))

	// Calculate autocorrelation
	numerator := 0.0
	denominator := 0.0

	for i := 0; i < len(data)-lag; i++ {
		numerator += (data[i] - mean) * (data[i+lag] - mean)
	}

	for _, val := range data {
		denominator += (val - mean) * (val - mean)
	}

	if denominator == 0 {
		return 0.0
	}

	return numerator / denominator
}

// calculateEntropy calculates Shannon entropy of a data series
func (e *Extractor) calculateEntropy(data []float64) float64 {
	if len(data) == 0 {
		return 0.0
	}

	// Create frequency map with binning for continuous values
	bins := 10 // Number of bins for discretization
	min := data[0]
	max := data[0]
	for _, val := range data {
		if val < min {
			min = val
		}
		if val > max {
			max = val
		}
	}

	if max == min {
		return 0.0 // All values are the same
	}

	binSize := (max - min) / float64(bins)
	frequency := make(map[int]int)

	for _, val := range data {
		bin := int((val - min) / binSize)
		if bin >= bins {
			bin = bins - 1
		}
		frequency[bin]++
	}

	// Calculate entropy
	entropy := 0.0
	total := float64(len(data))
	for _, count := range frequency {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// calculateStringEntropy calculates Shannon entropy of a string
func (e *Extractor) calculateStringEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	frequency := make(map[rune]int)
	for _, char := range s {
		frequency[char]++
	}

	entropy := 0.0
	length := float64(len(s))
	for _, count := range frequency {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// isCommonPort checks if a port is commonly used
func (e *Extractor) isCommonPort(port uint16) bool {
	commonPorts := map[uint16]bool{
		20: true, 21: true, 22: true, 23: true, 25: true, 53: true, 80: true, 110: true,
		143: true, 443: true, 993: true, 995: true, 465: true, 587: true, 636: true,
		989: true, 990: true, 8080: true, 8443: true, 3389: true, 5432: true, 3306: true,
	}
	return commonPorts[port]
}

// calculateSmallPacketRatio calculates the ratio of small packets (<= 64 bytes)
func (e *Extractor) calculateSmallPacketRatio(packetSizes []float64) float64 {
	if len(packetSizes) == 0 {
		return 0.0
	}

	smallCount := 0
	for _, size := range packetSizes {
		if size <= 64.0 {
			smallCount++
		}
	}

	return float64(smallCount) / float64(len(packetSizes))
}

// calculateLargePacketRatio calculates the ratio of large packets (>= 1400 bytes)
func (e *Extractor) calculateLargePacketRatio(packetSizes []float64) float64 {
	if len(packetSizes) == 0 {
		return 0.0
	}

	largeCount := 0
	for _, size := range packetSizes {
		if size >= 1400.0 {
			largeCount++
		}
	}

	return float64(largeCount) / float64(len(packetSizes))
}

// boolToFloat converts boolean to float64 (0.0 or 1.0)
func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

// GenerateFlowHash generates a hash for flow identification
func (e *Extractor) GenerateFlowHash(flowMetadata *capture.FlowMetadata) string {
	data := fmt.Sprintf("%s:%d-%s:%d-%s",
		flowMetadata.SourceIP, flowMetadata.SourcePort,
		flowMetadata.DestIP, flowMetadata.DestPort,
		flowMetadata.Protocol)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
