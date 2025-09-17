package metrics

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// Collector manages Prometheus metrics collection for SentinelAI
type Collector struct {
	logger *logrus.Logger
	server *http.Server

	// Packet capture metrics
	packetsTotal   *prometheus.CounterVec
	bytesTotal     *prometheus.CounterVec
	packetsDropped prometheus.Counter
	captureLatency prometheus.Histogram

	// Flow analysis metrics
	flowsTotal   *prometheus.CounterVec
	flowDuration prometheus.Histogram
	flowBytes    prometheus.Histogram
	activeFlows  prometheus.Gauge

	// ML inference metrics
	inferenceTotal   *prometheus.CounterVec
	inferenceLatency prometheus.Histogram
	threatScore      prometheus.Histogram
	modelErrors      prometheus.Counter

	// Policy enforcement metrics
	actionsTotal   *prometheus.CounterVec
	rulesEvaluated prometheus.Counter
	policyLatency  prometheus.Histogram

	// System performance metrics
	cpuUsage      prometheus.Gauge
	memoryUsage   prometheus.Gauge
	goroutines    prometheus.Gauge
	systemLatency prometheus.Histogram

	// Security metrics
	threatsDetected *prometheus.CounterVec
	alertsGenerated *prometheus.CounterVec
	falsePositives  prometheus.Counter
	falseNegatives  prometheus.Counter
}

// NewCollector creates a new metrics collector
func NewCollector(logger *logrus.Logger) *Collector {
	c := &Collector{
		logger: logger,
	}

	c.initializeMetrics()
	return c
}

// initializeMetrics initializes all Prometheus metrics
func (c *Collector) initializeMetrics() {
	// Packet capture metrics
	c.packetsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sentinelai_packets_total",
			Help: "Total number of packets captured",
		},
		[]string{"interface", "protocol"},
	)

	c.bytesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sentinelai_bytes_total",
			Help: "Total bytes captured",
		},
		[]string{"interface", "protocol"},
	)

	c.packetsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "sentinelai_packets_dropped_total",
			Help: "Total number of packets dropped",
		},
	)

	c.captureLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sentinelai_capture_latency_seconds",
			Help:    "Packet capture processing latency",
			Buckets: prometheus.DefBuckets,
		},
	)

	// Flow analysis metrics
	c.flowsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sentinelai_flows_total",
			Help: "Total number of network flows processed",
		},
		[]string{"protocol", "direction"},
	)

	c.flowDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sentinelai_flow_duration_seconds",
			Help:    "Duration of network flows",
			Buckets: []float64{0.1, 0.5, 1, 5, 10, 30, 60, 300, 600, 1800, 3600},
		},
	)

	c.flowBytes = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sentinelai_flow_bytes",
			Help:    "Bytes transferred in network flows",
			Buckets: []float64{100, 1024, 10240, 102400, 1048576, 10485760, 104857600},
		},
	)

	c.activeFlows = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "sentinelai_active_flows",
			Help: "Number of currently active flows",
		},
	)

	// ML inference metrics
	c.inferenceTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sentinelai_ml_inference_total",
			Help: "Total number of ML inferences performed",
		},
		[]string{"model", "result"},
	)

	c.inferenceLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sentinelai_ml_inference_latency_seconds",
			Help:    "ML inference latency",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
		},
	)

	c.threatScore = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sentinelai_threat_score",
			Help:    "Distribution of threat scores",
			Buckets: []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
		},
	)

	c.modelErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "sentinelai_model_errors_total",
			Help: "Total number of ML model errors",
		},
	)

	// Policy enforcement metrics
	c.actionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sentinelai_policy_actions_total",
			Help: "Total number of policy actions taken",
		},
		[]string{"action", "rule_id"},
	)

	c.rulesEvaluated = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "sentinelai_rules_evaluated_total",
			Help: "Total number of policy rules evaluated",
		},
	)

	c.policyLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sentinelai_policy_latency_seconds",
			Help:    "Policy evaluation latency",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1},
		},
	)

	// System performance metrics
	c.cpuUsage = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "sentinelai_cpu_usage_percent",
			Help: "CPU usage percentage",
		},
	)

	c.memoryUsage = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "sentinelai_memory_usage_bytes",
			Help: "Memory usage in bytes",
		},
	)

	c.goroutines = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "sentinelai_goroutines",
			Help: "Number of active goroutines",
		},
	)

	c.systemLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sentinelai_system_latency_seconds",
			Help:    "Overall system processing latency",
			Buckets: prometheus.DefBuckets,
		},
	)

	// Security metrics
	c.threatsDetected = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sentinelai_threats_detected_total",
			Help: "Total number of threats detected",
		},
		[]string{"threat_type", "severity"},
	)

	c.alertsGenerated = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sentinelai_alerts_generated_total",
			Help: "Total number of security alerts generated",
		},
		[]string{"alert_type", "severity"},
	)

	c.falsePositives = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "sentinelai_false_positives_total",
			Help: "Total number of false positive detections",
		},
	)

	c.falseNegatives = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "sentinelai_false_negatives_total",
			Help: "Total number of false negative detections",
		},
	)

	// Register all metrics
	c.registerMetrics()
}

// registerMetrics registers all metrics with Prometheus
func (c *Collector) registerMetrics() {
	prometheus.MustRegister(
		// Packet capture
		c.packetsTotal,
		c.bytesTotal,
		c.packetsDropped,
		c.captureLatency,

		// Flow analysis
		c.flowsTotal,
		c.flowDuration,
		c.flowBytes,
		c.activeFlows,

		// ML inference
		c.inferenceTotal,
		c.inferenceLatency,
		c.threatScore,
		c.modelErrors,

		// Policy enforcement
		c.actionsTotal,
		c.rulesEvaluated,
		c.policyLatency,

		// System performance
		c.cpuUsage,
		c.memoryUsage,
		c.goroutines,
		c.systemLatency,

		// Security
		c.threatsDetected,
		c.alertsGenerated,
		c.falsePositives,
		c.falseNegatives,
	)
}

// Start starts the metrics HTTP server
func (c *Collector) Start(ctx context.Context, port int) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", c.healthHandler)

	c.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	c.logger.WithField("port", port).Info("Starting metrics server")

	// Start server in goroutine
	go func() {
		if err := c.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			c.logger.WithError(err).Error("Metrics server error")
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return c.server.Shutdown(shutdownCtx)
}

// healthHandler provides a health check endpoint
func (c *Collector) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Packet Capture Metrics Methods
func (c *Collector) RecordPacket(interfaceName, protocol string, bytes int) {
	c.packetsTotal.WithLabelValues(interfaceName, protocol).Inc()
	c.bytesTotal.WithLabelValues(interfaceName, protocol).Add(float64(bytes))
}

func (c *Collector) RecordPacketDropped() {
	c.packetsDropped.Inc()
}

func (c *Collector) RecordCaptureLatency(duration time.Duration) {
	c.captureLatency.Observe(duration.Seconds())
}

// Flow Analysis Metrics Methods
func (c *Collector) RecordFlow(protocol, direction string, duration time.Duration, bytes uint64) {
	c.flowsTotal.WithLabelValues(protocol, direction).Inc()
	c.flowDuration.Observe(duration.Seconds())
	c.flowBytes.Observe(float64(bytes))
}

func (c *Collector) SetActiveFlows(count int) {
	c.activeFlows.Set(float64(count))
}

// ML Inference Metrics Methods
func (c *Collector) RecordInference(model, result string, latency time.Duration, score float64) {
	c.inferenceTotal.WithLabelValues(model, result).Inc()
	c.inferenceLatency.Observe(latency.Seconds())
	c.threatScore.Observe(score)
}

func (c *Collector) RecordModelError() {
	c.modelErrors.Inc()
}

// Policy Enforcement Metrics Methods
func (c *Collector) RecordPolicyAction(action, ruleID string, latency time.Duration) {
	c.actionsTotal.WithLabelValues(action, ruleID).Inc()
	c.policyLatency.Observe(latency.Seconds())
}

func (c *Collector) RecordRuleEvaluation() {
	c.rulesEvaluated.Inc()
}

// System Performance Metrics Methods
func (c *Collector) UpdateSystemMetrics(cpuPercent, memoryBytes float64, goroutineCount int) {
	c.cpuUsage.Set(cpuPercent)
	c.memoryUsage.Set(memoryBytes)
	c.goroutines.Set(float64(goroutineCount))
}

func (c *Collector) RecordSystemLatency(duration time.Duration) {
	c.systemLatency.Observe(duration.Seconds())
}

// Security Metrics Methods
func (c *Collector) RecordThreatDetection(threatType, severity string) {
	c.threatsDetected.WithLabelValues(threatType, severity).Inc()
}

func (c *Collector) RecordAlert(alertType, severity string) {
	c.alertsGenerated.WithLabelValues(alertType, severity).Inc()
}

func (c *Collector) RecordFalsePositive() {
	c.falsePositives.Inc()
}

func (c *Collector) RecordFalseNegative() {
	c.falseNegatives.Inc()
}

// PerformanceMonitor monitors system performance metrics
type PerformanceMonitor struct {
	collector *Collector
	logger    *logrus.Logger
	interval  time.Duration
}

// NewPerformanceMonitor creates a new performance monitor
func NewPerformanceMonitor(collector *Collector, logger *logrus.Logger, interval time.Duration) *PerformanceMonitor {
	return &PerformanceMonitor{
		collector: collector,
		logger:    logger,
		interval:  interval,
	}
}

// Start starts the performance monitoring loop
func (pm *PerformanceMonitor) Start(ctx context.Context) {
	ticker := time.NewTicker(pm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pm.collectSystemMetrics()
		}
	}
}

// collectSystemMetrics collects and reports system metrics
func (pm *PerformanceMonitor) collectSystemMetrics() {
	// Get system metrics (simplified version)
	// In a real implementation, this would use system-specific APIs
	// or libraries like gopsutil

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	memoryBytes := float64(m.Alloc)
	goroutineCount := runtime.NumGoroutine()

	// CPU usage would require additional libraries or system calls
	cpuPercent := 0.0 // Placeholder

	pm.collector.UpdateSystemMetrics(cpuPercent, memoryBytes, goroutineCount)
}
