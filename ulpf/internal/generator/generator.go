package generator

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"time"
)

// Event represents a synthetic log event.
type Event struct {
	SourceID  string    `json:"source_id"`
	Hostname  string    `json:"hostname"`
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
	Format    string    `json:"format"`
	Payload   string    `json:"payload"`
}

// Generator is the interface all synthetic source generators implement.
type Generator interface {
	Generate() (*Event, error)
}

// BaseGenerator holds common configuration.
type BaseGenerator struct {
	Seed     int64
	Rate     int
	Burst    int
	Format   string
	Hostname string
	rng      *rand.Rand
}

// Severities for random selection
var severities = []string{"INFO", "WARNING", "ERROR", "CRITICAL", "DEBUG", "NOTICE", "ALERT", "EMERGENCY"}

func randomSeverity(rng *rand.Rand) string {
	return severities[rng.Intn(len(severities))]
}

var srcIPs = []string{"10.0.0.10", "10.0.0.20", "192.168.1.100", "172.16.0.5", "10.10.10.1"}
var dstIPs = []string{"8.8.8.8", "1.1.1.1", "208.67.222.222", "93.184.216.34", "151.101.1.140"}

// -----------------------------------------------------------------------------
// Firewall Generator
// -----------------------------------------------------------------------------

type FirewallConfig struct {
	Seed     int64
	Rate     int
	Burst    int
	Format   string
	Hostname string
}

type FirewallGenerator struct {
	BaseGenerator
}

func NewFirewallGenerator(cfg FirewallConfig) *FirewallGenerator {
	return &FirewallGenerator{
		BaseGenerator: BaseGenerator{
			Seed:     cfg.Seed,
			Rate:     cfg.Rate,
			Burst:    cfg.Burst,
			Format:   cfg.Format,
			Hostname: cfg.Hostname,
			rng:      rand.New(rand.NewSource(cfg.Seed)),
		},
	}
}

func (g *FirewallGenerator) Generate() (*Event, error) {
	return g.GenerateAllow()
}

func (g *FirewallGenerator) GenerateAllow() (*Event, error) {
	srcIP := srcIPs[g.rng.Intn(len(srcIPs))]
	dstIP := dstIPs[g.rng.Intn(len(dstIPs))]
	srcPort := g.rng.Intn(65535) + 1
	dstPort := g.rng.Intn(65535) + 1
	action := "ALLOW"
	protocol := "TCP"
	if g.rng.Intn(2) == 0 {
		protocol = "UDP"
	}
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("%s %s src=%s dst=%s sport=%d dport=%d proto=%s",
		timestamp.Format("2006-01-02T15:04:05.000Z"), action, srcIP, dstIP, srcPort, dstPort, protocol)
	if g.Format == "syslog" {
		payload = fmt.Sprintf("<134>1 %s %s firewall - - - %s",
			timestamp.Format("2006-01-02T15:04:05.000Z07:00"), g.Hostname, payload)
	}
	return &Event{
		SourceID:  "firewall",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  randomSeverity(g.rng),
		Format:    g.Format,
		Payload:   payload,
	}, nil
}

func (g *FirewallGenerator) GenerateDeny() (*Event, error) {
	srcIP := srcIPs[g.rng.Intn(len(srcIPs))]
	dstIP := dstIPs[g.rng.Intn(len(dstIPs))]
	srcPort := g.rng.Intn(65535) + 1
	dstPort := g.rng.Intn(65535) + 1
	action := "DENY"
	protocol := "TCP"
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("%s %s proto=%s src=%s:%d dst=%s:%d",
		timestamp.Format("2006-01-02T15:04:05.000Z"), action, protocol, srcIP, srcPort, dstIP, dstPort)
	return &Event{
		SourceID:  "firewall",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "WARNING",
		Format:    g.Format,
		Payload:   payload,
	}, nil
}

func (g *FirewallGenerator) GenerateNAT() (*Event, error) {
	origIP := srcIPs[g.rng.Intn(len(srcIPs))]
	natIP := "203.0.113." + fmt.Sprintf("%d", g.rng.Intn(254)+1)
	dstIP := dstIPs[g.rng.Intn(len(dstIPs))]
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("%s NAT src=%s nat_src=%s dst=%s",
		timestamp.Format("2006-01-02T15:04:05.000Z"), origIP, natIP, dstIP)
	return &Event{
		SourceID:  "firewall",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "INFO",
		Format:    g.Format,
		Payload:   payload,
	}, nil
}

func (g *FirewallGenerator) GenerateVPN() (*Event, error) {
	remoteIP := "198.51.100." + fmt.Sprintf("%d", g.rng.Intn(254)+1)
	user := "user" + fmt.Sprintf("%d", g.rng.Intn(100))
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("%s VPN user=%s remote_ip=%s action=connect",
		timestamp.Format("2006-01-02T15:04:05.000Z"), user, remoteIP)
	return &Event{
		SourceID:  "firewall",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "INFO",
		Format:    g.Format,
		Payload:   payload,
	}, nil
}

// -----------------------------------------------------------------------------
// IDS Generator
// -----------------------------------------------------------------------------

type IDSConfig struct {
	Seed     int64
	Rate     int
	Burst    int
	Format   string
	Hostname string
}

type IDSGenerator struct {
	BaseGenerator
}

func NewIDSGenerator(cfg IDSConfig) *IDSGenerator {
	return &IDSGenerator{
		BaseGenerator: BaseGenerator{
			Seed:     cfg.Seed,
			Rate:     cfg.Rate,
			Burst:    cfg.Burst,
			Format:   cfg.Format,
			Hostname: cfg.Hostname,
			rng:      rand.New(rand.NewSource(cfg.Seed)),
		},
	}
}

var signatures = []string{
	"ET SCAN Nmap Scripting Engine",
	"TROJAN Known Trojan Checkin",
	"SQL Injection Attempt",
	"XSS Attempt",
	"Brute Force SSH",
	"Malware C2 Communication",
	"Suspicious Outbound Connection",
}

func (g *IDSGenerator) GenerateAlert() (*Event, error) {
	sig := signatures[g.rng.Intn(len(signatures))]
	srcIP := srcIPs[g.rng.Intn(len(srcIPs))]
	dstIP := dstIPs[g.rng.Intn(len(dstIPs))]
	srcPort := g.rng.Intn(65535) + 1
	dstPort := g.rng.Intn(65535) + 1
	priority := g.rng.Intn(5) + 1
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("alert: [%d] %s src=%s:%d dst=%s:%d priority=%d action=alert",
		g.rng.Intn(100000), sig, srcIP, srcPort, dstIP, dstPort, priority)
	return &Event{
		SourceID:  "ids",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "ALERT",
		Format:    g.Format,
		Payload:   payload,
	}, nil
}

func (g *IDSGenerator) Generate() (*Event, error) {
	return g.GenerateAlert()
}

// -----------------------------------------------------------------------------
// DNS Generator
// -----------------------------------------------------------------------------

type DNSConfig struct {
	Seed     int64
	Rate     int
	Burst    int
	Format   string
	Hostname string
}

type DNSGenerator struct {
	BaseGenerator
}

func NewDNSGenerator(cfg DNSConfig) *DNSGenerator {
	return &DNSGenerator{
		BaseGenerator: BaseGenerator{
			Seed:     cfg.Seed,
			Rate:     cfg.Rate,
			Burst:    cfg.Burst,
			Format:   cfg.Format,
			Hostname: cfg.Hostname,
			rng:      rand.New(rand.NewSource(cfg.Seed)),
		},
	}
}

var dnsNames = []string{"example.com", "google.com", "github.com", "stackoverflow.com", "api.service.local", "mail.company.internal"}

func (g *DNSGenerator) GenerateQuery() (*Event, error) {
	name := dnsNames[g.rng.Intn(len(dnsNames))]
	queryTypes := []string{"A", "AAAA", "CNAME", "MX", "TXT"}
	qtype := queryTypes[g.rng.Intn(len(queryTypes))]
	srcIP := srcIPs[g.rng.Intn(len(srcIPs))]
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("%s DNS query from %s name=%s type=%s",
		timestamp.Format("2006-01-02T15:04:05.000Z"), srcIP, name, qtype)
	return &Event{
		SourceID:  "dns",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "INFO",
		Format:    g.Format,
		Payload:   payload,
	}, nil
}

func (g *DNSGenerator) Generate() (*Event, error) {
	return g.GenerateQuery()
}

// -----------------------------------------------------------------------------
// Router Generator
// -----------------------------------------------------------------------------

type RouterConfig struct {
	Seed     int64
	Rate     int
	Burst    int
	Format   string
	Hostname string
}

type RouterGenerator struct {
	BaseGenerator
}

func NewRouterGenerator(cfg RouterConfig) *RouterGenerator {
	return &RouterGenerator{
		BaseGenerator: BaseGenerator{
			Seed:     cfg.Seed,
			Rate:     cfg.Rate,
			Burst:    cfg.Burst,
			Format:   cfg.Format,
			Hostname: cfg.Hostname,
			rng:      rand.New(rand.NewSource(cfg.Seed)),
		},
	}
}

func (g *RouterGenerator) GenerateDHCP() (*Event, error) {
	mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		g.rng.Intn(256), g.rng.Intn(256), g.rng.Intn(256),
		g.rng.Intn(256), g.rng.Intn(256), g.rng.Intn(256))
	ip := fmt.Sprintf("192.168.1.%d", g.rng.Intn(254)+1)
	action := "assign"
	if g.rng.Intn(2) == 0 {
		action = "release"
	}
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("%s DHCP %s mac=%s ip=%s",
		timestamp.Format("2006-01-02T15:04:05.000Z"), action, mac, ip)
	return &Event{
		SourceID:  "router",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "INFO",
		Format:    g.Format,
		Payload:   payload,
	}, nil
}

func (g *RouterGenerator) GenerateRouting() (*Event, error) {
	protocols := []string{"BGP", "OSPF"}
	proto := protocols[g.rng.Intn(len(protocols))]
	neighbor := "10.255.255." + fmt.Sprintf("%d", g.rng.Intn(254)+1)
	states := []string{"Idle", "Connect", "Active", "OpenSent", "OpenConfirm", "Established"}
	state := states[g.rng.Intn(len(states))]
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("%s %s neighbor=%s state=%s",
		timestamp.Format("2006-01-02T15:04:05.000Z"), proto, neighbor, state)
	return &Event{
		SourceID:  "router",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "NOTICE",
		Format:    g.Format,
		Payload:   payload,
	}, nil
}

func (g *RouterGenerator) Generate() (*Event, error) {
	if g.rng.Intn(2) == 0 {
		return g.GenerateDHCP()
	}
	return g.GenerateRouting()
}

// -----------------------------------------------------------------------------
// Linux Generator
// -----------------------------------------------------------------------------

type LinuxConfig struct {
	Seed     int64
	Rate     int
	Burst    int
	Format   string
	Hostname string
}

type LinuxGenerator struct {
	BaseGenerator
}

func NewLinuxGenerator(cfg LinuxConfig) *LinuxGenerator {
	return &LinuxGenerator{
		BaseGenerator: BaseGenerator{
			Seed:     cfg.Seed,
			Rate:     cfg.Rate,
			Burst:    cfg.Burst,
			Format:   cfg.Format,
			Hostname: cfg.Hostname,
			rng:      rand.New(rand.NewSource(cfg.Seed)),
		},
	}
}

func (g *LinuxGenerator) GenerateSSHLogin() (*Event, error) {
	users := []string{"root", "admin", "deploy", "user1", "backup"}
	user := users[g.rng.Intn(len(users))]
	srcIP := "192.168.1." + fmt.Sprintf("%d", g.rng.Intn(254)+1)
	port := g.rng.Intn(65535) + 1
	methods := []string{"publickey", "password", "keyboard-interactive"}
	method := methods[g.rng.Intn(len(methods))]
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("Accepted %s for %s from %s port %d ssh2",
		method, user, srcIP, port)
	return &Event{
		SourceID:  "linux",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "INFO",
		Format:    "syslog",
		Payload:   payload,
	}, nil
}

func (g *LinuxGenerator) GenerateSudo() (*Event, error) {
	users := []string{"admin", "deploy", "ops"}
	user := users[g.rng.Intn(len(users))]
	tty := fmt.Sprintf("pts/%d", g.rng.Intn(10))
	commands := []string{"/bin/ls", "/usr/bin/systemctl restart nginx", "/bin/cat /etc/shadow", "/usr/bin/vim /etc/passwd"}
	cmd := commands[g.rng.Intn(len(commands))]
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("%s : TTY=%s ; PWD=/home/%s ; USER=root ; COMMAND=%s",
		user, tty, user, cmd)
	return &Event{
		SourceID:  "linux",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "NOTICE",
		Format:    "syslog",
		Payload:   payload,
	}, nil
}

func (g *LinuxGenerator) GenerateProcessExec() (*Event, error) {
	pid := g.rng.Intn(32768) + 1000
	uid := g.rng.Intn(1000) + 1000
	commands := []string{"/usr/bin/python3 script.py", "/bin/bash -c 'ls -la'", "/usr/bin/curl http://example.com", "/usr/bin/sudo reboot"}
	cmd := commands[g.rng.Intn(len(commands))]
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("type=SYSCALL msg=audit(%d.%06d:%d): arch=c000003e syscall=59 success=yes exit=0 pid=%d uid=%d comm=%q",
		timestamp.Unix(), timestamp.Nanosecond()/1000, pid, pid, uid, cmd)
	return &Event{
		SourceID:  "linux",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "INFO",
		Format:    "syslog",
		Payload:   payload,
	}, nil
}

func (g *LinuxGenerator) GenerateAuthFailure() (*Event, error) {
	users := []string{"admin", "root", "testuser", "guest", "nobody"}
	user := users[g.rng.Intn(len(users))]
	srcIP := "10.0.0." + fmt.Sprintf("%d", g.rng.Intn(254)+1)
	port := g.rng.Intn(65535) + 1
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("Failed password for invalid user %s from %s port %d ssh2",
		user, srcIP, port)
	return &Event{
		SourceID:  "linux",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "WARNING",
		Format:    "syslog",
		Payload:   payload,
	}, nil
}

func (g *LinuxGenerator) GenerateService() (*Event, error) {
	services := []string{"nginx", "sshd", "postgresql", "docker", "redis", "app-backend"}
	service := services[g.rng.Intn(len(services))]
	actions := []string{"Started", "Stopped", "Reloaded", "Failed"}
	action := actions[g.rng.Intn(len(actions))]
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("%s %s.", action, service)
	return &Event{
		SourceID:  "linux",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "INFO",
		Format:    "syslog",
		Payload:   payload,
	}, nil
}

func (g *LinuxGenerator) GenerateFilesystem() (*Event, error) {
	paths := []string{"/etc/passwd", "/home/user/documents/secret.txt", "/var/log/auth.log", "/etc/shadow"}
	path := paths[g.rng.Intn(len(paths))]
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("type=PATH msg=audit(%d.%06d:12345): item=0 name=%s inode=1234567 dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00",
		timestamp.Unix(), timestamp.Nanosecond()/1000, path)
	return &Event{
		SourceID:  "linux",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "INFO",
		Format:    "syslog",
		Payload:   payload,
	}, nil
}

func (g *LinuxGenerator) GenerateKernel() (*Event, error) {
	msgs := []string{"TCP: request_sock_TCP: Possible SYN flooding on port 80",
		"Out of memory: Killed process 12345 (java)",
		"eth0: link up",
		"usb 1-1: new high-speed USB device number 2 using xhci_hcd",
		"EXT4-fs (sda1): mounted filesystem with ordered data mode"}
	msg := msgs[g.rng.Intn(len(msgs))]
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("kernel: [%d.%06d] %s",
		timestamp.Unix(), timestamp.Nanosecond()/1000, msg)
	return &Event{
		SourceID:  "linux",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "NOTICE",
		Format:    "syslog",
		Payload:   payload,
	}, nil
}

func (g *LinuxGenerator) Generate() (*Event, error) {
	generators := []func() (*Event, error){
		g.GenerateSSHLogin, g.GenerateSudo, g.GenerateProcessExec,
		g.GenerateAuthFailure, g.GenerateService, g.GenerateFilesystem, g.GenerateKernel,
	}
	return generators[g.rng.Intn(len(generators))]()
}

// -----------------------------------------------------------------------------
// Web Generator
// -----------------------------------------------------------------------------

type WebConfig struct {
	Seed     int64
	Rate     int
	Burst    int
	Format   string
	Hostname string
}

type WebGenerator struct {
	BaseGenerator
}

func NewWebGenerator(cfg WebConfig) *WebGenerator {
	return &WebGenerator{
		BaseGenerator: BaseGenerator{
			Seed:     cfg.Seed,
			Rate:     cfg.Rate,
			Burst:    cfg.Burst,
			Format:   cfg.Format,
			Hostname: cfg.Hostname,
			rng:      rand.New(rand.NewSource(cfg.Seed)),
		},
	}
}

func (g *WebGenerator) GenerateHTTPAccess() (*Event, error) {
	methods := []string{"GET", "POST", "PUT", "DELETE"}
	method := methods[g.rng.Intn(len(methods))]
	paths := []string{"/", "/api/v1/users", "/login", "/static/index.html", "/health", "/admin"}
	path := paths[g.rng.Intn(len(paths))]
	statuses := []int{200, 201, 301, 302, 400, 401, 403, 404, 500}
	status := statuses[g.rng.Intn(len(statuses))]
	size := g.rng.Intn(100000) + 100
	clientIP := "192.168.1." + fmt.Sprintf("%d", g.rng.Intn(254)+1)
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("%s - - [%s] \"%s %s HTTP/1.1\" %d %d \"-\" \"Mozilla/5.0\"",
		clientIP, timestamp.Format("02/Jan/2006:15:04:05 -0700"),
		method, path, status, size)
	return &Event{
		SourceID:  "web",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "INFO",
		Format:    "apache",
		Payload:   payload,
	}, nil
}

func (g *WebGenerator) GenerateJSONAccess() (*Event, error) {
	methods := []string{"GET", "POST", "PUT", "DELETE"}
	method := methods[g.rng.Intn(len(methods))]
	paths := []string{"/api/v1/users", "/api/v1/orders", "/health", "/metrics"}
	path := paths[g.rng.Intn(len(paths))]
	statuses := []int{200, 201, 400, 401, 403, 500}
	status := statuses[g.rng.Intn(len(statuses))]
	clientIP := "10.0.0." + fmt.Sprintf("%d", g.rng.Intn(254)+1)
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	data := map[string]interface{}{
		"timestamp":   timestamp.Format(time.RFC3339Nano),
		"level":       "info",
		"method":      method,
		"path":        path,
		"status":      status,
		"client_ip":   clientIP,
		"duration_ms": g.rng.Intn(500),
		"user_agent":  "Mozilla/5.0",
	}
	jsonBytes, _ := json.Marshal(data)
	return &Event{
		SourceID:  "web",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "INFO",
		Format:    "json",
		Payload:   string(jsonBytes),
	}, nil
}

func (g *WebGenerator) Generate() (*Event, error) {
	if g.rng.Intn(2) == 0 {
		return g.GenerateHTTPAccess()
	}
	return g.GenerateJSONAccess()
}

// -----------------------------------------------------------------------------
// Application Generator
// -----------------------------------------------------------------------------

type ApplicationConfig struct {
	Seed     int64
	Rate     int
	Burst    int
	Format   string
	Hostname string
}

type ApplicationGenerator struct {
	BaseGenerator
}

func NewApplicationGenerator(cfg ApplicationConfig) *ApplicationGenerator {
	return &ApplicationGenerator{
		BaseGenerator: BaseGenerator{
			Seed:     cfg.Seed,
			Rate:     cfg.Rate,
			Burst:    cfg.Burst,
			Format:   cfg.Format,
			Hostname: cfg.Hostname,
			rng:      rand.New(rand.NewSource(cfg.Seed)),
		},
	}
}

func (g *ApplicationGenerator) GenerateError() (*Event, error) {
	messages := []string{"Connection refused to database at db:5432",
		"Failed to process payment: insufficient funds",
		"NullPointerException at com.app.Service.handleRequest(Service.java:42)",
		"Timeout waiting for response from upstream service",
		"Rate limit exceeded for API key abc123"}
	msg := messages[g.rng.Intn(len(messages))]
	level := "ERROR"
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("{\"@timestamp\":\"%s\",\"level\":\"%s\",\"message\":\"%s\",\"service\":\"backend\",\"trace_id\":\"%s\"}",
		timestamp.Format(time.RFC3339Nano), level, msg, fmt.Sprintf("%016x", g.rng.Uint64()))
	return &Event{
		SourceID:  "application",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "ERROR",
		Format:    "json",
		Payload:   payload,
	}, nil
}

func (g *ApplicationGenerator) GenerateStackTrace() (*Event, error) {
	trace := "java.lang.NullPointerException: Cannot invoke method on null object\n" +
		"\tat com.app.controller.UserController.getUser(UserController.java:45)\n" +
		"\tat com.app.service.UserService.findUser(UserService.java:128)\n" +
		"\tat com.app.repository.UserRepository.findById(UserRepository.java:67)\n" +
		"\tat sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\n" +
		"\tat java.lang.reflect.Method.invoke(Method.java:498)\n" +
		"\tat org.springframework.web.method.support.InvocableHandlerMethod.doInvoke(InvocableHandlerMethod.java:205)\n" +
		"\tat org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter.invokeHandlerMethod(RequestMappingHandlerAdapter.java:870)\n" +
		"\tat org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter.handleInternal(RequestMappingHandlerAdapter.java:776)\n" +
		"\tat org.springframework.web.servlet.mvc.method.AbstractHandlerMethodAdapter.handle(AbstractHandlerMethodAdapter.java:87)\n" +
		"\tat org.springframework.web.servlet.DispatcherServlet.doService(DispatcherServlet.java:943)\n" +
		"\tat org.springframework.web.servlet.FrameworkServlet.processRequest(FrameworkServlet.java:970)\n" +
		"\tat javax.servlet.http.HttpServlet.service(HttpServlet.java:742)\n" +
		"\tat org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:231)"
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	return &Event{
		SourceID:  "application",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "ERROR",
		Format:    "text",
		Payload:   trace,
	}, nil
}

func (g *ApplicationGenerator) Generate() (*Event, error) {
	if g.rng.Intn(2) == 0 {
		return g.GenerateError()
	}
	return g.GenerateStackTrace()
}

// -----------------------------------------------------------------------------
// Database Generator
// -----------------------------------------------------------------------------

type DatabaseConfig struct {
	Seed     int64
	Rate     int
	Burst    int
	Format   string
	Hostname string
}

type DatabaseGenerator struct {
	BaseGenerator
}

func NewDatabaseGenerator(cfg DatabaseConfig) *DatabaseGenerator {
	return &DatabaseGenerator{
		BaseGenerator: BaseGenerator{
			Seed:     cfg.Seed,
			Rate:     cfg.Rate,
			Burst:    cfg.Burst,
			Format:   cfg.Format,
			Hostname: cfg.Hostname,
			rng:      rand.New(rand.NewSource(cfg.Seed)),
		},
	}
}

func (g *DatabaseGenerator) GenerateConnection() (*Event, error) {
	users := []string{"app_user", "readonly", "admin", "backup"}
	user := users[g.rng.Intn(len(users))]
	databases := []string{"app_db", "reporting", "auth", "analytics"}
	db := databases[g.rng.Intn(len(databases))]
	srcIP := "10.0.0." + fmt.Sprintf("%d", g.rng.Intn(254)+1)
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("%s LOG:  connection authorized: user=%s database=%s host=%s port=5432",
		timestamp.Format("2006-01-02 15:04:05 MST"), user, db, srcIP)
	return &Event{
		SourceID:  "database",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "INFO",
		Format:    "syslog",
		Payload:   payload,
	}, nil
}

func (g *DatabaseGenerator) GenerateQuery() (*Event, error) {
	queries := []string{"SELECT id, name, email FROM users WHERE active = true",
		"INSERT INTO orders (user_id, total) VALUES (123, 45.99)",
		"UPDATE sessions SET last_seen = NOW() WHERE id = 'abc123'",
		"DELETE FROM cache WHERE expires_at < NOW()",
		"CREATE INDEX idx_users_email ON users(email)"}
	query := queries[g.rng.Intn(len(queries))]
	duration := g.rng.Float64() * 1000
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("%s LOG:  duration: %.3f ms  statement: %s",
		timestamp.Format("2006-01-02 15:04:05 MST"), duration, query)
	return &Event{
		SourceID:  "database",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "INFO",
		Format:    "syslog",
		Payload:   payload,
	}, nil
}

func (g *DatabaseGenerator) GenerateFailure() (*Event, error) {
	users := []string{"admin", "unknown_user", "postgres"}
	user := users[g.rng.Intn(len(users))]
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("FATAL:  password authentication failed for user \"%s\"", user)
	return &Event{
		SourceID:  "database",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "ERROR",
		Format:    "syslog",
		Payload:   payload,
	}, nil
}

func (g *DatabaseGenerator) GeneratePrivilege() (*Event, error) {
	actions := []string{"GRANT SELECT", "REVOKE INSERT", "GRANT ALL PRIVILEGES", "REVOKE ALL"}
	action := actions[g.rng.Intn(len(actions))]
	objects := []string{"TABLE users", "DATABASE app_db", "SCHEMA public"}
	object := objects[g.rng.Intn(len(objects))]
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("STATEMENT:  %s ON %s TO app_user", action, object)
	return &Event{
		SourceID:  "database",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "NOTICE",
		Format:    "syslog",
		Payload:   payload,
	}, nil
}

func (g *DatabaseGenerator) Generate() (*Event, error) {
	generators := []func() (*Event, error){
		g.GenerateConnection, g.GenerateQuery, g.GenerateFailure, g.GeneratePrivilege,
	}
	return generators[g.rng.Intn(len(generators))]()
}

// -----------------------------------------------------------------------------
// Windows Generator
// -----------------------------------------------------------------------------

type WindowsConfig struct {
	Seed     int64
	Rate     int
	Burst    int
	Format   string
	Hostname string
}

type WindowsGenerator struct {
	BaseGenerator
}

func NewWindowsGenerator(cfg WindowsConfig) *WindowsGenerator {
	return &WindowsGenerator{
		BaseGenerator: BaseGenerator{
			Seed:     cfg.Seed,
			Rate:     cfg.Rate,
			Burst:    cfg.Burst,
			Format:   cfg.Format,
			Hostname: cfg.Hostname,
			rng:      rand.New(rand.NewSource(cfg.Seed)),
		},
	}
}

func (g *WindowsGenerator) GenerateLogin() (*Event, error) {
	eventID := 4624
	users := []string{"Administrator", "jsmith", "backup_svc", "sql_service"}
	user := users[g.rng.Intn(len(users))]
	logonTypes := []string{"2 (Interactive)", "3 (Network)", "10 (RemoteInteractive)"}
	logonType := logonTypes[g.rng.Intn(len(logonTypes))]
	srcIP := "192.168.1." + fmt.Sprintf("%d", g.rng.Intn(254)+1)
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	data := map[string]interface{}{
		"EventID":         eventID,
		"TimeCreated":     timestamp.Format("2006-01-02T15:04:05.000Z"),
		"Provider":        "Microsoft-Windows-Security-Auditing",
		"TargetUserName":  user,
		"LogonType":       logonType,
		"IpAddress":       srcIP,
		"ProcessName":     "C:\\Windows\\System32\\winlogon.exe",
		"Status":          "0x0",
		"SubjectUserName": user,
	}
	jsonBytes, _ := json.Marshal(data)
	return &Event{
		SourceID:  "windows",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "INFO",
		Format:    "json",
		Payload:   string(jsonBytes),
	}, nil
}

func (g *WindowsGenerator) GenerateProcess() (*Event, error) {
	eventID := 4688
	procs := []string{"C:\\Windows\\System32\\cmd.exe /c dir", "C:\\Program Files\\App\\service.exe", "powershell.exe -enc AQB0AG...", "C:\\Windows\\System32\\net.exe user /add"}
	proc := procs[g.rng.Intn(len(procs))]
	pid := g.rng.Intn(32768) + 1000
	ppid := g.rng.Intn(32768) + 1000
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	data := map[string]interface{}{
		"EventID":        eventID,
		"TimeCreated":    timestamp.Format("2006-01-02T15:04:05.000Z"),
		"NewProcessName": proc,
		"ProcessId":      pid,
		"ParentProcessId": ppid,
		"CommandLine":    proc,
		"SubjectUserName": "Administrator",
	}
	jsonBytes, _ := json.Marshal(data)
	return &Event{
		SourceID:  "windows",
		Hostname:  g.Hostname,
		Timestamp: timestamp,
		Severity:  "INFO",
		Format:    "json",
		Payload:   string(jsonBytes),
	}, nil
}

func (g *WindowsGenerator) Generate() (*Event, error) {
	if g.rng.Intn(2) == 0 {
		return g.GenerateLogin()
	}
	return g.GenerateProcess()
}

// -----------------------------------------------------------------------------
// Auth Generator (dedicated auth service)
// -----------------------------------------------------------------------------

type AuthConfig struct {
	Seed     int64
	Rate     int
	Burst    int
	Format   string
	Hostname string
}

type AuthGenerator struct {
	BaseGenerator
}

func NewAuthGenerator(cfg AuthConfig) *AuthGenerator {
	return &AuthGenerator{
		BaseGenerator: BaseGenerator{
			Seed:     cfg.Seed,
			Rate:     cfg.Rate,
			Burst:    cfg.Burst,
			Format:   cfg.Format,
			Hostname: cfg.Hostname,
			rng:      rand.New(rand.NewSource(cfg.Seed)),
		},
	}
}

func (g *AuthGenerator) GenerateLogin() (*Event, error) {
	users := []string{"admin", "user1", "deploy", "guest"}
	user := users[g.rng.Intn(len(users))]
	results := []string{"success", "failure"}
	result := results[g.rng.Intn(len(results))]
	srcIP := "192.168.1." + fmt.Sprintf("%d", g.rng.Intn(254)+1)
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	if result == "success" {
		payload := fmt.Sprintf("auth: login success user=%s ip=%s mfa=true", user, srcIP)
		return &Event{
			SourceID:  "auth", Hostname: g.Hostname, Timestamp: timestamp,
			Severity: "INFO", Format: "text", Payload: payload,
		}, nil
	}
	payload := fmt.Sprintf("auth: login failure user=%s ip=%s reason=invalid_password", user, srcIP)
	return &Event{
		SourceID:  "auth", Hostname: g.Hostname, Timestamp: timestamp,
		Severity: "WARNING", Format: "text", Payload: payload,
	}, nil
}

func (g *AuthGenerator) GenerateToken() (*Event, error) {
	users := []string{"admin", "deploy"}
	user := users[g.rng.Intn(len(users))]
	tokenOps := []string{"issued", "refreshed", "revoked", "expired"}
	op := tokenOps[g.rng.Intn(len(tokenOps))]
	timestamp := time.Now().Add(-time.Duration(g.rng.Int63n(3600000)) * time.Millisecond)
	payload := fmt.Sprintf("auth: token %s user=%s expires_in=3600", op, user)
	return &Event{
		SourceID:  "auth", Hostname: g.Hostname, Timestamp: timestamp,
		Severity: "INFO", Format: "text", Payload: payload,
	}, nil
}

func (g *AuthGenerator) Generate() (*Event, error) {
	if g.rng.Intn(2) == 0 {
		return g.GenerateLogin()
	}
	return g.GenerateToken()
}
