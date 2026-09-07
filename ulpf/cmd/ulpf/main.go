package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bashmyhed/ulpf/internal/config"
	"github.com/bashmyhed/ulpf/internal/ingest"
	"github.com/bashmyhed/ulpf/internal/metrics"
)

func main() {
	var (
		configPath = flag.String("config", "configs/ulpf.yaml", "Path to config file")
	)
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	metricsCollector := metrics.NewCollector()

	tcpCollector := ingest.NewTCPCollector(ingest.TCPConfig{
		Listen: cfg.Network.TCPListen,
	}, func(data []byte) error {
		metricsCollector.IncrementEventsReceived()
		metricsCollector.AddBytesReceived(int64(len(data)))
		log.Printf("Received: %s", string(data))
		return nil
	})

	if err := tcpCollector.Start(); err != nil {
		log.Fatalf("Failed to start TCP collector: %v", err)
	}

	go func() {
		http.Handle("/metrics", metricsCollector.Handler())
		http.ListenAndServe(cfg.Network.MetricsListen, nil)
	}()

	log.Printf("ULPF started. Listening on %s (TCP), %s (Metrics)",
		cfg.Network.TCPListen, cfg.Network.MetricsListen)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
	tcpCollector.Stop()
	time.Sleep(100 * time.Millisecond)
}