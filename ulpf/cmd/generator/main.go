package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bashmyhed/ulpf/internal/generator"
)

func main() {
	var (
		genType  = flag.String("type", "firewall", "Generator type")
		rate     = flag.Int("rate", 10, "Events per second")
		burst    = flag.Int("burst", 1, "Burst size")
		format   = flag.String("format", "syslog", "Output format")
		host     = flag.String("host", "localhost", "ULPF host")
		port     = flag.Int("port", 5514, "ULPF port")
		seed     = flag.Int64("seed", 42, "Random seed")
		hostname = flag.String("hostname", "dummy-host", "Hostname")
	)
	flag.Parse()

	var gen generator.Generator
	switch *genType {
	case "firewall":
		gen = generator.NewFirewallGenerator(generator.FirewallConfig{
			Seed: *seed, Rate: *rate, Burst: *burst, Format: *format, Hostname: *hostname,
		})
	case "ids":
		gen = generator.NewIDSGenerator(generator.IDSConfig{
			Seed: *seed, Rate: *rate, Burst: *burst, Format: *format, Hostname: *hostname,
		})
	case "dns":
		gen = generator.NewDNSGenerator(generator.DNSConfig{
			Seed: *seed, Rate: *rate, Burst: *burst, Format: *format, Hostname: *hostname,
		})
	case "router":
		gen = generator.NewRouterGenerator(generator.RouterConfig{
			Seed: *seed, Rate: *rate, Burst: *burst, Format: *format, Hostname: *hostname,
		})
	case "linux":
		gen = generator.NewLinuxGenerator(generator.LinuxConfig{
			Seed: *seed, Rate: *rate, Burst: *burst, Format: *format, Hostname: *hostname,
		})
	case "web":
		gen = generator.NewWebGenerator(generator.WebConfig{
			Seed: *seed, Rate: *rate, Burst: *burst, Format: *format, Hostname: *hostname,
		})
	case "application":
		gen = generator.NewApplicationGenerator(generator.ApplicationConfig{
			Seed: *seed, Rate: *rate, Burst: *burst, Format: *format, Hostname: *hostname,
		})
	case "database":
		gen = generator.NewDatabaseGenerator(generator.DatabaseConfig{
			Seed: *seed, Rate: *rate, Burst: *burst, Format: *format, Hostname: *hostname,
		})
	case "windows":
		gen = generator.NewWindowsGenerator(generator.WindowsConfig{
			Seed: *seed, Rate: *rate, Burst: *burst, Format: *format, Hostname: *hostname,
		})
	case "auth":
		gen = generator.NewAuthGenerator(generator.AuthConfig{
			Seed: *seed, Rate: *rate, Burst: *burst, Format: *format, Hostname: *hostname,
		})
	default:
		log.Fatalf("Unknown generator type: %s", *genType)
	}

	addr := fmt.Sprintf("%s:%d", *host, *port)
	log.Printf("Connecting to %s", addr)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(time.Second / time.Duration(*rate))
	defer ticker.Stop()

	for {
		select {
		case <-sigCh:
			log.Println("Shutting down...")
			return
		case <-ticker.C:
			event, err := gen.Generate()
			if err != nil {
				log.Printf("Generate error: %v", err)
				continue
			}
			fmt.Println(event.Payload)
		}
	}
}