package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"masswall/internal/metrics"
	"masswall/internal/server"
)

func gracefulShutdown(apiServer *http.Server, cancel context.CancelFunc, done chan bool) {
	// Create context that listens for the interrupt signal from the OS.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Listen for the interrupt signal.
	<-ctx.Done()

	log.Println("shutting down gracefully, press Ctrl+C again to force")

	// Cancel the metrics collector context
	cancel()

	stop() // Allow Ctrl+C to force shutdown

	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := apiServer.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown with error: %v", err)
	}

	log.Println("Server exiting")

	// Notify the main goroutine that the shutdown is complete
	done <- true
}

func main() {
	log.Println("Starting SentinelAI API Server with Metrics...")

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	// Start metrics collector
	metricsCollector := metrics.NewCollector(nil) // Pass nil for logger, will use default
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Println("Starting metrics collector on port 9090...")
		if err := metricsCollector.Start(ctx, 9090); err != nil && err != http.ErrServerClosed {
			log.Printf("Metrics collector error: %v", err)
		}
	}()

	// Create HTTP server
	server := server.NewServer()

	// Create a done channel to signal when the shutdown is complete
	done := make(chan bool, 1)

	// Run graceful shutdown in a separate goroutine
	go gracefulShutdown(server, cancel, done)

	log.Println("Starting HTTP API server on port 8080...")
	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		panic(fmt.Sprintf("http server error: %s", err))
	}

	// Wait for all goroutines to finish
	wg.Wait()

	// Wait for the graceful shutdown to complete
	<-done
	log.Println("Graceful shutdown complete.")
}
