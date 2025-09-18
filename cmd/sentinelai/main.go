package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"masswall/internal/capture"
	"masswall/internal/metrics"
	"masswall/internal/ml"
	"masswall/internal/ngfw"
	"masswall/internal/policy"
	"masswall/internal/server"

	"github.com/gopacket/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	version = "v0.1.0-alpha"
	logger  = logrus.New()
)

func init() {
	// Configure logging
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	// Configure viper for configuration management
	viper.SetConfigName("sentinelai")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
}

var rootCmd = &cobra.Command{
	Use:   "sentinelai",
	Short: "SentinelAI - AI-Powered Next-Generation Firewall",
	Long: `SentinelAI is an AI-powered Next-Generation Firewall that integrates 
deep learning, Zero Trust enforcement, federated AI, and real-time performance monitoring.`,
	Version: version,
	Run:     runSentinelAI,
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start SentinelAI NGFW",
	Run:   runSentinelAI,
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage SentinelAI configuration",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Configuration management - Coming soon")
	},
}

var interfacesCmd = &cobra.Command{
	Use:   "interfaces",
	Short: "List available network interfaces",
	Run:   listInterfaces,
}

func init() {
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(interfacesCmd)

	// Add flags
	rootCmd.PersistentFlags().String("config", "", "config file (default is ./configs/sentinelai.yaml)")
	rootCmd.PersistentFlags().String("interface", "eth0", "network interface to monitor")
	rootCmd.PersistentFlags().Int("port", 8080, "management API port")
	rootCmd.PersistentFlags().String("log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().Bool("enable-ml", true, "enable ML-based threat detection")
	rootCmd.PersistentFlags().Bool("enable-capture", true, "enable packet capture")

	viper.BindPFlags(rootCmd.PersistentFlags())
}

func runSentinelAI(cmd *cobra.Command, args []string) {
	// Read configuration
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			logger.Warn("No config file found, using defaults")
		} else {
			logger.Fatalf("Error reading config file: %v", err)
		}
	}

	// Set log level
	if level, err := logrus.ParseLevel(viper.GetString("log-level")); err == nil {
		logger.SetLevel(level)
	}

	logger.WithFields(logrus.Fields{
		"version":        version,
		"interface":      viper.GetString("interface"),
		"port":           viper.GetInt("port"),
		"enable_ml":      viper.GetBool("enable-ml"),
		"enable_capture": viper.GetBool("enable-capture"),
	}).Info("Starting SentinelAI NGFW")

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create components
	var wg sync.WaitGroup

	// Initialize components
	policyEngine := policy.NewEngine(logger)
	mlService := ml.NewService(logger)

	// Initialize metrics collector
	metricsCollector := metrics.NewCollector(logger)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := metricsCollector.Start(ctx, 9090); err != nil {
			logger.Errorf("Metrics collector error: %v", err)
		}
	}()

	// Start packet capture if enabled
	if viper.GetBool("enable-capture") {
		captureService := capture.NewService(viper.GetString("interface"), logger)

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := captureService.Start(ctx); err != nil {
				logger.Errorf("Packet capture error: %v", err)
			}
		}()
	}

	// Start ML inference service if enabled
	if viper.GetBool("enable-ml") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := mlService.Start(ctx); err != nil {
				logger.Errorf("ML service error: %v", err)
			}
		}()
	}

	// Start NGFW core engine
	ngfwEngine := ngfw.NewEngine(policyEngine, mlService, logger)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := ngfwEngine.Start(ctx); err != nil {
			logger.Errorf("NGFW engine error: %v", err)
		}
	}()

	// Start management API server
	managementServer := server.NewServer()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := managementServer.ListenAndServe(); err != nil {
			logger.Errorf("Management server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	logger.Info("Received shutdown signal, gracefully shutting down...")

	// Cancel context to signal all goroutines to stop
	cancel()

	// Wait for all goroutines to finish or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("Graceful shutdown completed")
	case <-time.After(30 * time.Second):
		logger.Warn("Shutdown timeout reached, forcing exit")
	}
}

func listInterfaces(cmd *cobra.Command, args []string) {
	fmt.Println("Available network interfaces:")
	fmt.Println("=============================")

	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Printf("Error listing interfaces: %v\n", err)
		return
	}

	for i, device := range devices {
		fmt.Printf("%d. %s\n", i+1, device.Name)
		if device.Description != "" {
			fmt.Printf("   Description: %s\n", device.Description)
		}

		if len(device.Addresses) > 0 {
			fmt.Printf("   Addresses:\n")
			for _, addr := range device.Addresses {
				if addr.IP != nil {
					fmt.Printf("     IP: %s\n", addr.IP.String())
				}
			}
		}
		fmt.Println()
	}

	if len(devices) == 0 {
		fmt.Println("No network interfaces found.")
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
