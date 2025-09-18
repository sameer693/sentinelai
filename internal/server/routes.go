package server

import (
	"encoding/json"
	"log"
	"net/http"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var startTime = time.Now()

func (s *Server) RegisterRoutes() http.Handler {
	mux := http.NewServeMux()

	// Register routes
	mux.HandleFunc("/", s.HelloWorldHandler)
	mux.HandleFunc("/health", s.HealthHandler)
	mux.HandleFunc("/api/status", s.StatusHandler)
	mux.HandleFunc("/api/metrics", s.MetricsHandler)
	mux.HandleFunc("/api/threats", s.ThreatsHandler)
	mux.HandleFunc("/api/flows", s.FlowsHandler)
	mux.HandleFunc("/api/alerts", s.AlertsHandler)
	mux.HandleFunc("/api/system", s.SystemHandler)

	// Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())

	// Wrap the mux with CORS middleware
	return s.corsMiddleware(mux)
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*") // Replace "*" with specific origins if needed
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-CSRF-Token")
		w.Header().Set("Access-Control-Allow-Credentials", "false") // Set to "true" if credentials are required

		// Handle preflight OPTIONS requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Proceed with the next handler
		next.ServeHTTP(w, r)
	})
}

func (s *Server) HelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	resp := map[string]string{
		"message": "SentinelAI - AI-Powered Next-Generation Firewall",
		"version": "v0.1.0-alpha",
		"status":  "running",
	}
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(jsonResp); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func (s *Server) HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"uptime":    time.Since(startTime).String(),
		"version":   "v0.1.0-alpha",
	}

	json.NewEncoder(w).Encode(health)
}

func (s *Server) StatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	status := map[string]interface{}{
		"service":   "SentinelAI NGFW",
		"version":   "v0.1.0-alpha",
		"status":    "operational",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"uptime":    time.Since(startTime).String(),
		"components": map[string]string{
			"packet_capture": "enabled",
			"ml_inference":   "enabled",
			"policy_engine":  "enabled",
			"monitoring":     "enabled",
		},
		"metrics": map[string]interface{}{
			"active_flows":      0, // Placeholder
			"threats_detected":  0, // Placeholder
			"packets_processed": 0, // Placeholder
		},
	}

	json.NewEncoder(w).Encode(status)
}

func (s *Server) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("# SentinelAI Metrics - Use /metrics endpoint for Prometheus format\n"))
}

func (s *Server) ThreatsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Mock threat data - in production, this would come from the threat detection engine
	threats := map[string]interface{}{
		"recent_threats": []map[string]interface{}{
			{
				"id":          "threat_001",
				"type":        "malware",
				"severity":    "high",
				"source_ip":   "192.168.1.100",
				"dest_ip":     "10.0.0.5",
				"timestamp":   time.Now().UTC().Format(time.RFC3339),
				"description": "Suspicious executable download detected",
				"score":       0.85,
			},
			{
				"id":          "threat_002",
				"type":        "dos",
				"severity":    "medium",
				"source_ip":   "172.16.0.50",
				"dest_ip":     "10.0.0.10",
				"timestamp":   time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339),
				"description": "High connection rate detected",
				"score":       0.72,
			},
		},
		"summary": map[string]interface{}{
			"total_threats_today": 15,
			"high_severity":       3,
			"medium_severity":     8,
			"low_severity":        4,
			"blocked_attacks":     12,
			"false_positives":     2,
		},
	}

	json.NewEncoder(w).Encode(threats)
}

func (s *Server) FlowsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Mock flow data
	flows := map[string]interface{}{
		"active_flows": []map[string]interface{}{
			{
				"flow_id":      "flow_001",
				"source_ip":    "192.168.1.100",
				"dest_ip":      "8.8.8.8",
				"source_port":  52341,
				"dest_port":    443,
				"protocol":     "TCP",
				"bytes_sent":   1024,
				"bytes_recv":   4096,
				"duration":     30.5,
				"status":       "active",
				"threat_score": 0.1,
			},
			{
				"flow_id":      "flow_002",
				"source_ip":    "10.0.0.5",
				"dest_ip":      "172.16.1.10",
				"source_port":  8080,
				"dest_port":    3389,
				"protocol":     "TCP",
				"bytes_sent":   512,
				"bytes_recv":   256,
				"duration":     15.2,
				"status":       "suspicious",
				"threat_score": 0.75,
			},
		},
		"flow_stats": map[string]interface{}{
			"total_flows":      1250,
			"active_flows":     45,
			"completed_flows":  1205,
			"suspicious_flows": 8,
			"avg_duration":     25.3,
			"total_bytes":      50 * 1024 * 1024,
		},
	}

	json.NewEncoder(w).Encode(flows)
}

func (s *Server) AlertsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Mock alerts data
	alerts := map[string]interface{}{
		"active_alerts": []map[string]interface{}{
			{
				"id":          "alert_001",
				"name":        "High CPU Usage",
				"severity":    "warning",
				"status":      "firing",
				"started_at":  time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339),
				"description": "CPU usage is above 80% for more than 5 minutes",
				"value":       "85%",
				"labels": map[string]string{
					"component": "system",
					"instance":  "sentinelai-01",
				},
			},
			{
				"id":          "alert_002",
				"name":        "High Threat Detection Rate",
				"severity":    "critical",
				"status":      "firing",
				"started_at":  time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339),
				"description": "Threat detection rate is unusually high",
				"value":       "15 threats/sec",
				"labels": map[string]string{
					"component": "threat_detection",
					"instance":  "sentinelai-01",
				},
			},
		},
		"alert_summary": map[string]interface{}{
			"total_alerts":    2,
			"critical_alerts": 1,
			"warning_alerts":  1,
			"info_alerts":     0,
			"resolved_today":  5,
		},
	}

	json.NewEncoder(w).Encode(alerts)
}

func (s *Server) SystemHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get system metrics
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	system := map[string]interface{}{
		"performance": map[string]interface{}{
			"cpu_usage_percent":  75.5, // Mock data - would be real in production
			"memory_usage_bytes": m.Alloc,
			"memory_total_bytes": m.Sys,
			"goroutines":         runtime.NumGoroutine(),
			"gc_cycles":          m.NumGC,
			"uptime_seconds":     time.Since(startTime).Seconds(),
		},
		"network": map[string]interface{}{
			"packets_per_second": 1500,             // Mock data
			"bytes_per_second":   1024 * 1024 * 10, // 10MB/s
			"active_connections": 250,
			"dropped_packets":    5,
			"interface_status":   "up",
		},
		"ml_engine": map[string]interface{}{
			"inferences_per_second": 500,
			"avg_inference_latency": 0.5, // milliseconds
			"model_accuracy":        0.95,
			"model_version":         "v1.0.0",
			"last_training":         "2025-09-15T10:00:00Z",
		},
		"storage": map[string]interface{}{
			"logs_size_bytes":    1024 * 1024 * 100, // 100MB
			"models_size_bytes":  1024 * 1024 * 50,  // 50MB
			"cache_size_bytes":   1024 * 1024 * 25,  // 25MB
			"disk_usage_percent": 35.2,
		},
	}

	json.NewEncoder(w).Encode(system)
}
