package generator_test

import (
	"strings"
	"testing"

	"github.com/bashmyhed/ulpf/internal/generator"
)

// Test data for deterministic generation
var testSeed int64 = 42

// T07: Network-device events

func TestFirewallAllowEvent(t *testing.T) {
	g := generator.NewFirewallGenerator(generator.FirewallConfig{
		Seed:     testSeed,
		Hostname: "fw-dummy-01",
	})

	event, err := g.GenerateAllow()
	if err != nil {
		t.Fatalf("GenerateAllow failed: %v", err)
	}

	if event.SourceID != "firewall" {
		t.Errorf("expected source_id=firewall, got %s", event.SourceID)
	}
	if event.Hostname != "fw-dummy-01" {
		t.Errorf("expected hostname=fw-dummy-01, got %s", event.Hostname)
	}
	if !strings.Contains(event.Payload, "ALLOW") {
		t.Errorf("expected ALLOW in payload, got: %s", event.Payload)
	}
	if event.Severity == "" {
		t.Error("severity should not be empty")
	}
	if event.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}
}

func TestFirewallDenyEvent(t *testing.T) {
	g := generator.NewFirewallGenerator(generator.FirewallConfig{
		Seed:     testSeed,
		Hostname: "fw-dummy-01",
	})

	event, err := g.GenerateDeny()
	if err != nil {
		t.Fatalf("GenerateDeny failed: %v", err)
	}

	if !strings.Contains(event.Payload, "DENY") {
		t.Errorf("expected DENY in payload, got: %s", event.Payload)
	}
}

func TestFirewallNATEvent(t *testing.T) {
	g := generator.NewFirewallGenerator(generator.FirewallConfig{
		Seed:     testSeed,
		Hostname: "fw-dummy-01",
	})

	event, err := g.GenerateNAT()
	if err != nil {
		t.Fatalf("GenerateNAT failed: %v", err)
	}

	if !strings.Contains(event.Payload, "NAT") {
		t.Errorf("expected NAT in payload, got: %s", event.Payload)
	}
}

func TestIDSEvent(t *testing.T) {
	g := generator.NewIDSGenerator(generator.IDSConfig{
		Seed:     testSeed,
		Hostname: "ids-dummy-01",
	})

	event, err := g.GenerateAlert()
	if err != nil {
		t.Fatalf("GenerateAlert failed: %v", err)
	}

	if event.SourceID != "ids" {
		t.Errorf("expected source_id=ids, got %s", event.SourceID)
	}
	if !strings.Contains(event.Payload, "alert") {
		t.Errorf("expected 'alert' in payload, got: %s", event.Payload)
	}
}

func TestVPNEvent(t *testing.T) {
	g := generator.NewFirewallGenerator(generator.FirewallConfig{
		Seed:     testSeed,
		Hostname: "fw-dummy-01",
	})

	event, err := g.GenerateVPN()
	if err != nil {
		t.Fatalf("GenerateVPN failed: %v", err)
	}

	if !strings.Contains(event.Payload, "VPN") {
		t.Errorf("expected VPN in payload, got: %s", event.Payload)
	}
}

func TestDNSQueryEvent(t *testing.T) {
	g := generator.NewDNSGenerator(generator.DNSConfig{
		Seed:     testSeed,
		Hostname: "dns-dummy-01",
	})

	event, err := g.GenerateQuery()
	if err != nil {
		t.Fatalf("GenerateQuery failed: %v", err)
	}

	if event.SourceID != "dns" {
		t.Errorf("expected source_id=dns, got %s", event.SourceID)
	}
}

func TestDHCPEvent(t *testing.T) {
	g := generator.NewRouterGenerator(generator.RouterConfig{
		Seed:     testSeed,
		Hostname: "router-dummy-01",
	})

	event, err := g.GenerateDHCP()
	if err != nil {
		t.Fatalf("GenerateDHCP failed: %v", err)
	}

	if !strings.Contains(event.Payload, "DHCP") {
		t.Errorf("expected DHCP in payload, got: %s", event.Payload)
	}
}

func TestRoutingEvent(t *testing.T) {
	g := generator.NewRouterGenerator(generator.RouterConfig{
		Seed:     testSeed,
		Hostname: "router-dummy-01",
	})

	event, err := g.GenerateRouting()
	if err != nil {
		t.Fatalf("GenerateRouting failed: %v", err)
	}

	if !strings.Contains(event.Payload, "BGP") && !strings.Contains(event.Payload, "OSPF") {
		t.Errorf("expected routing protocol in payload, got: %s", event.Payload)
	}
}

// T08: Linux server events

func TestSSHLoginEvent(t *testing.T) {
	g := generator.NewLinuxGenerator(generator.LinuxConfig{
		Seed:     testSeed,
		Hostname: "linux-dummy-01",
	})

	event, err := g.GenerateSSHLogin()
	if err != nil {
		t.Fatalf("GenerateSSHLogin failed: %v", err)
	}

	if event.SourceID != "linux" {
		t.Errorf("expected source_id=linux, got %s", event.SourceID)
	}
	if !strings.Contains(event.Payload, "Accepted") {
		t.Errorf("expected 'Accepted' in payload, got: %s", event.Payload)
	}
}

func TestSudoEvent(t *testing.T) {
	g := generator.NewLinuxGenerator(generator.LinuxConfig{
		Seed:     testSeed,
		Hostname: "linux-dummy-01",
	})

	event, err := g.GenerateSudo()
	if err != nil {
		t.Fatalf("GenerateSudo failed: %v", err)
	}

	if !strings.Contains(event.Payload, "sudo") && !strings.Contains(event.Payload, "COMMAND") {
		t.Errorf("expected sudo/COMMAND in payload, got: %s", event.Payload)
	}
}

func TestProcessExecutionEvent(t *testing.T) {
	g := generator.NewLinuxGenerator(generator.LinuxConfig{
		Seed:     testSeed,
		Hostname: "linux-dummy-01",
	})

	event, err := g.GenerateProcessExec()
	if err != nil {
		t.Fatalf("GenerateProcessExec failed: %v", err)
	}

	// syscall=59 is execve on x86_64
	if !strings.Contains(event.Payload, "syscall=") {
		t.Errorf("expected syscall= in payload, got: %s", event.Payload)
	}
}

func TestAuthFailureEvent(t *testing.T) {
	g := generator.NewLinuxGenerator(generator.LinuxConfig{
		Seed:     testSeed,
		Hostname: "linux-dummy-01",
	})

	event, err := g.GenerateAuthFailure()
	if err != nil {
		t.Fatalf("GenerateAuthFailure failed: %v", err)
	}

	if !strings.Contains(event.Payload, "Failed") {
		t.Errorf("expected 'Failed' in payload, got: %s", event.Payload)
	}
}

func TestServiceEvent(t *testing.T) {
	g := generator.NewLinuxGenerator(generator.LinuxConfig{
		Seed:     testSeed,
		Hostname: "linux-dummy-01",
	})

	event, err := g.GenerateService()
	if err != nil {
		t.Fatalf("GenerateService failed: %v", err)
	}

	validActions := []string{"Started", "Stopped", "Reloaded", "Failed"}
	found := false
	for _, action := range validActions {
		if strings.Contains(event.Payload, action) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected service action in payload, got: %s", event.Payload)
	}
}

// T09: Application logs

func TestHTTPAccessLog(t *testing.T) {
	g := generator.NewWebGenerator(generator.WebConfig{
		Seed:     testSeed,
		Hostname: "web-dummy-01",
	})

	event, err := g.GenerateHTTPAccess()
	if err != nil {
		t.Fatalf("GenerateHTTPAccess failed: %v", err)
	}

	if event.SourceID != "web" {
		t.Errorf("expected source_id=web, got %s", event.SourceID)
	}
	if !strings.Contains(event.Payload, "GET") && !strings.Contains(event.Payload, "POST") {
		t.Errorf("expected HTTP method in payload, got: %s", event.Payload)
	}
}

func TestApplicationError(t *testing.T) {
	g := generator.NewApplicationGenerator(generator.ApplicationConfig{
		Seed:     testSeed,
		Hostname: "app-dummy-01",
	})

	event, err := g.GenerateError()
	if err != nil {
		t.Fatalf("GenerateError failed: %v", err)
	}

	if event.SourceID != "application" {
		t.Errorf("expected source_id=application, got %s", event.SourceID)
	}
	if !strings.Contains(event.Payload, "error") && !strings.Contains(event.Payload, "ERROR") {
		t.Errorf("expected error level in payload, got: %s", event.Payload)
	}
}

func TestStackTrack(t *testing.T) {
	g := generator.NewApplicationGenerator(generator.ApplicationConfig{
		Seed:     testSeed,
		Hostname: "app-dummy-01",
	})

	event, err := g.GenerateStackTrace()
	if err != nil {
		t.Fatalf("GenerateStackTrace failed: %v", err)
	}

	if !strings.Contains(event.Payload, "\n") {
		t.Errorf("expected multi-line stack trace, got: %s", event.Payload)
	}
}

// T10: Database logs

func TestDBAuthEvent(t *testing.T) {
	g := generator.NewDatabaseGenerator(generator.DatabaseConfig{
		Seed:     testSeed,
		Hostname: "db-dummy-01",
	})

	event, err := g.GenerateConnection()
	if err != nil {
		t.Fatalf("GenerateConnection failed: %v", err)
	}

	if event.SourceID != "database" {
		t.Errorf("expected source_id=database, got %s", event.SourceID)
	}
	if !strings.Contains(event.Payload, "connection") {
		t.Errorf("expected 'connection' in payload, got: %s", event.Payload)
	}
}

func TestDBQueryEvent(t *testing.T) {
	g := generator.NewDatabaseGenerator(generator.DatabaseConfig{
		Seed:     testSeed,
		Hostname: "db-dummy-01",
	})

	event, err := g.GenerateQuery()
	if err != nil {
		t.Fatalf("GenerateQuery failed: %v", err)
	}

	if !strings.Contains(event.Payload, "SELECT") && !strings.Contains(event.Payload, "INSERT") {
		t.Errorf("expected SQL query in payload, got: %s", event.Payload)
	}
}

func TestDBFailureEvent(t *testing.T) {
	g := generator.NewDatabaseGenerator(generator.DatabaseConfig{
		Seed:     testSeed,
		Hostname: "db-dummy-01",
	})

	event, err := g.GenerateFailure()
	if err != nil {
		t.Fatalf("GenerateFailure failed: %v", err)
	}

	if !strings.Contains(event.Payload, "FATAL") && !strings.Contains(event.Payload, "ERROR") {
		t.Errorf("expected error level in payload, got: %s", event.Payload)
	}
}

// Determinism test: same seed produces same output

func TestDeterministicGeneration(t *testing.T) {
	g1 := generator.NewFirewallGenerator(generator.FirewallConfig{Seed: 42, Hostname: "fw-01"})
	g2 := generator.NewFirewallGenerator(generator.FirewallConfig{Seed: 42, Hostname: "fw-01"})

	events1 := make([]string, 10)
	events2 := make([]string, 10)

	for i := 0; i < 10; i++ {
		e1, _ := g1.GenerateAllow()
		e2, _ := g2.GenerateAllow()
		events1[i] = e1.Payload
		events2[i] = e2.Payload
	}

	for i := range events1 {
		if events1[i] != events2[i] {
			t.Errorf("non-deterministic output at index %d: %q != %q", i, events1[i], events2[i])
		}
	}
}

// Rate/burst configuration test

func TestRateBurstConfig(t *testing.T) {
	g := generator.NewFirewallGenerator(generator.FirewallConfig{
		Seed:     testSeed,
		Hostname: "fw-01",
		Rate:     100,
		Burst:    10,
	})

	if g.Rate != 100 {
		t.Errorf("expected rate=100, got %d", g.Rate)
	}
	if g.Burst != 10 {
		t.Errorf("expected burst=10, got %d", g.Burst)
	}
}

// Format configuration test

func TestFormatConfig(t *testing.T) {
	formats := []string{"syslog", "json", "keyvalue", "apache"}
	for _, format := range formats {
		g := generator.NewFirewallGenerator(generator.FirewallConfig{
			Seed:     testSeed,
			Hostname: "fw-01",
			Format:   format,
		})
		if g.Format != format {
			t.Errorf("expected format=%s, got %s", format, g.Format)
		}
	}
}
