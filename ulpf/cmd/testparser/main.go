package main

import (
	"fmt"
	"strings"

	"github.com/bashmyhed/ulpf/internal/parser"
)

func main() {
	fmt.Println("=== ULPF Parser Comprehensive Test ===")
	fmt.Println()

	var passed, failed int

	// 1. JSON - Application logs
	test("JSON - Application log", func() (string, bool) {
		p := parser.New(parser.Config{Format: parser.FormatJSON})
		result, err := p.Parse([]byte(`{"@timestamp":"2023-10-11T22:14:15.003Z","level":"error","message":"Connection refused","service":"api","trace_id":"abc123"}`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["level"] != "error" {
			return fmt.Sprintf("level mismatch: %s", result.Fields["level"]), false
		}
		if result.Fields["service"] != "api" {
			return fmt.Sprintf("service mismatch: %s", result.Fields["service"]), false
		}
		return fmt.Sprintf("OK: %d fields extracted", len(result.Fields)), true
	}, &passed, &failed)

	// 2. JSON - Nested with JSONPath
	test("JSON - Nested with JSONPath", func() (string, bool) {
		p := parser.New(parser.Config{
			Format: parser.FormatJSON,
			JSONPaths: map[string]string{
				"username": "$.user.name",
				"user_id":  "$.user.id",
			},
		})
		result, err := p.Parse([]byte(`{"user":{"name":"admin","id":1234},"action":"login"}`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["username"] != "admin" {
			return fmt.Sprintf("username mismatch: %s", result.Fields["username"]), false
		}
		if result.Fields["user_id"] != "1234" {
			return fmt.Sprintf("user_id mismatch: %s", result.Fields["user_id"]), false
		}
		return fmt.Sprintf("OK: username=%s, user_id=%s", result.Fields["username"], result.Fields["user_id"]), true
	}, &passed, &failed)

	// 3. Syslog RFC 3164 - SSH auth
	test("Syslog3164 - SSH auth", func() (string, bool) {
		p := parser.New(parser.Config{Format: parser.FormatSyslog3164})
		result, err := p.Parse([]byte(`<134>Oct 11 22:14:15 server01 sshd: Accepted publickey for admin from 192.168.1.100 port 22`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["priority"] != "134" {
			return fmt.Sprintf("priority mismatch: %s", result.Fields["priority"]), false
		}
		if result.Fields["hostname"] != "server01" {
			return fmt.Sprintf("hostname mismatch: %s", result.Fields["hostname"]), false
		}
		if result.Fields["tag"] != "sshd" {
			return fmt.Sprintf("tag mismatch: %s", result.Fields["tag"]), false
		}
		return fmt.Sprintf("OK: host=%s tag=%s", result.Fields["hostname"], result.Fields["tag"]), true
	}, &passed, &failed)

	// 4. Syslog RFC 5424 - Structured
	test("Syslog5424 - Structured", func() (string, bool) {
		p := parser.New(parser.Config{Format: parser.FormatSyslog5424})
		result, err := p.Parse([]byte(`<165>1 2023-10-11T22:14:15.003Z mymachine evntslog 1234 ID47 [exampleSDID@32473 iut="3"] An event`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["version"] != "1" {
			return fmt.Sprintf("version mismatch: %s", result.Fields["version"]), false
		}
		if result.Fields["app"] != "evntslog" {
			return fmt.Sprintf("app mismatch: %s", result.Fields["app"]), false
		}
		return fmt.Sprintf("OK: version=%s app=%s", result.Fields["version"], result.Fields["app"]), true
	}, &passed, &failed)

	// 5. Key=Value - Firewall
	test("KeyValue - Firewall", func() (string, bool) {
		p := parser.New(parser.Config{Format: parser.FormatKeyValue})
		result, err := p.Parse([]byte(`src=10.0.0.1 dst=8.8.8.8 sport=12345 dport=53 proto=UDP action=ALLOW`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["src"] != "10.0.0.1" {
			return fmt.Sprintf("src mismatch: %s", result.Fields["src"]), false
		}
		if result.Fields["action"] != "ALLOW" {
			return fmt.Sprintf("action mismatch: %s", result.Fields["action"]), false
		}
		return fmt.Sprintf("OK: src=%s action=%s", result.Fields["src"], result.Fields["action"]), true
	}, &passed, &failed)

	// 6. Regex - Apache Combined Log
	test("Regex - Apache Combined Log", func() (string, bool) {
		p := parser.New(parser.Config{
			Format: parser.FormatRegex,
			Regex:  `(?P<client_ip>[\d.]+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<bytes>\d+)`,
		})
		result, err := p.Parse([]byte(`192.168.1.100 - - [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["method"] != "GET" {
			return fmt.Sprintf("method mismatch: %s", result.Fields["method"]), false
		}
		if result.Fields["status"] != "200" {
			return fmt.Sprintf("status mismatch: %s", result.Fields["status"]), false
		}
		return fmt.Sprintf("OK: method=%s status=%s bytes=%s", result.Fields["method"], result.Fields["status"], result.Fields["bytes"]), true
	}, &passed, &failed)

	// 7. Regex - Nginx access log
	test("Regex - Nginx access log", func() (string, bool) {
		p := parser.New(parser.Config{
			Format: parser.FormatRegex,
			Regex:  `(?P<remote_addr>[\d.]+) - (?P<remote_user>\[[^\]]*|\S+) \[(?P<time_local>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<body_bytes_sent>\d+)`,
		})
		result, err := p.Parse([]byte(`10.0.0.1 - - [10/Oct/2023:14:22:10 +0000] "POST /api/login HTTP/1.1" 201 512`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["status"] != "201" {
			return fmt.Sprintf("status mismatch: %s", result.Fields["status"]), false
		}
		if result.Fields["remote_addr"] != "10.0.0.1" {
			return fmt.Sprintf("remote_addr mismatch: %s", result.Fields["remote_addr"]), false
		}
		return fmt.Sprintf("OK: addr=%s status=%s", result.Fields["remote_addr"], result.Fields["status"]), true
	}, &passed, &failed)

	// 8. Regex - PostgreSQL log
	test("Regex - PostgreSQL log", func() (string, bool) {
		p := parser.New(parser.Config{
			Format: parser.FormatRegex,
			Regex:  `(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \w+):(?P<user>\w+)@(?P<database>\w+):(?P<message>.*)`,
		})
		result, err := p.Parse([]byte(`2023-10-11 22:14:15 UTC:admin@mydb:LOG:  connection authorized: user=admin database=mydb host=10.0.0.1 port=5432`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["user"] != "admin" {
			return fmt.Sprintf("user mismatch: %s", result.Fields["user"]), false
		}
		if result.Fields["database"] != "mydb" {
			return fmt.Sprintf("database mismatch: %s", result.Fields["database"]), false
		}
		return fmt.Sprintf("OK: user=%s db=%s", result.Fields["user"], result.Fields["database"]), true
	}, &passed, &failed)

	// 9. Regex - Windows Event (Syslog format)
	test("Regex - Windows Event via Syslog", func() (string, bool) {
		p := parser.New(parser.Config{Format: parser.FormatSyslog3164})
		result, err := p.Parse([]byte(`<134>Oct 11 22:14:15 WIN-SRV01 EventLog: Security: 4624: An account was successfully logged on`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["hostname"] != "WIN-SRV01" {
			return fmt.Sprintf("hostname mismatch: %s", result.Fields["hostname"]), false
		}
		if result.Fields["tag"] != "EventLog" {
			return fmt.Sprintf("tag mismatch: %s", result.Fields["tag"]), false
		}
		return fmt.Sprintf("OK: host=%s tag=%s", result.Fields["hostname"], result.Fields["tag"]), true
	}, &passed, &failed)

	// 10. Regex - CEF (Common Event Format)
	test("Regex - CEF format", func() (string, bool) {
		p := parser.New(parser.Config{
			Format: parser.FormatRegex,
			Regex:  `CEF:(?P<version>\d+)\|(?P<device_vendor>[^|]*)\|(?P<device_product>[^|]*)\|(?P<device_version>[^|]*)\|(?P<signature_id>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>\d+)\|(?P<extensions>.*)`,
		})
		result, err := p.Parse([]byte(`CEF:0|Security|ThreatManager|1.0|100|Port Scan|10|src=10.0.0.1 dst=10.0.0.2 spt=12345 dpt=80`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["device_vendor"] != "Security" {
			return fmt.Sprintf("vendor mismatch: %s", result.Fields["device_vendor"]), false
		}
		if result.Fields["severity"] != "10" {
			return fmt.Sprintf("severity mismatch: %s", result.Fields["severity"]), false
		}
		return fmt.Sprintf("OK: vendor=%s severity=%s", result.Fields["device_vendor"], result.Fields["severity"]), true
	}, &passed, &failed)

	// 11. Regex - LEEF format
	test("Regex - LEEF format", func() (string, bool) {
		p := parser.New(parser.Config{
			Format: parser.FormatRegex,
			Regex:  `LEEF:(?P<version>\d+\.\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<product_version>[^|]*)\|(?P<event_id>[^|]*)\|(?P<attr_count>\d+)\|(?P<attributes>.*)`,
		})
		result, err := p.Parse([]byte(`LEEF:2.0|Microsoft|ATP|1.0|200|1|src=10.0.0.1\tdst=8.8.8.8`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["vendor"] != "Microsoft" {
			return fmt.Sprintf("vendor mismatch: %s", result.Fields["vendor"]), false
		}
		if result.Fields["event_id"] != "200" {
			return fmt.Sprintf("event_id mismatch: %s", result.Fields["event_id"]), false
		}
		return fmt.Sprintf("OK: vendor=%s event_id=%s", result.Fields["vendor"], result.Fields["event_id"]), true
	}, &passed, &failed)

	// 12. Delimiter - CSV
	test("Delimiter - CSV", func() (string, bool) {
		p := parser.New(parser.Config{
			Format:    parser.FormatDelimiter,
			Delimiter: ",",
			Fields:    []string{"timestamp", "level", "service", "message"},
		})
		result, err := p.Parse([]byte(`2023-10-11T22:14:15Z,ERROR,api,Connection refused`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["level"] != "ERROR" {
			return fmt.Sprintf("level mismatch: %s", result.Fields["level"]), false
		}
		if result.Fields["service"] != "api" {
			return fmt.Sprintf("service mismatch: %s", result.Fields["service"]), false
		}
		return fmt.Sprintf("OK: level=%s service=%s", result.Fields["level"], result.Fields["service"]), true
	}, &passed, &failed)

	// 13. Regex - iptables
	test("Regex - iptables log", func() (string, bool) {
		p := parser.New(parser.Config{
			Format: parser.FormatRegex,
			Regex:  `(?P<timestamp>\S+ \d+ \d+:\d+:\d+) (?P<hostname>\S+) kernel:.*IN=(?P<in_iface>\S+).*OUT=(?P<out_iface>\S+).*SRC=(?P<src>[\d.]+).*DST=(?P<dst>[\d.]+).*SPT=(?P<sport>\d+).*DPT=(?P<dport>\d+)`,
		})
		result, err := p.Parse([]byte(`Oct 11 22:14:15 server kernel: IN=eth0 OUT=eth1 SRC=10.0.0.1 DST=8.8.8.8 SPT=12345 DPT=80`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["src"] != "10.0.0.1" {
			return fmt.Sprintf("src mismatch: %s", result.Fields["src"]), false
		}
		if result.Fields["dport"] != "80" {
			return fmt.Sprintf("dport mismatch: %s", result.Fields["dport"]), false
		}
		return fmt.Sprintf("OK: src=%s dst=%s dport=%s", result.Fields["src"], result.Fields["dst"], result.Fields["dport"]), true
	}, &passed, &failed)

	// 14. Regex - sudo
	test("Regex - sudo log", func() (string, bool) {
		p := parser.New(parser.Config{
			Format: parser.FormatRegex,
			Regex:  `(?P<timestamp>\S+ \d+ \d+:\d+:\d+) (?P<hostname>\S+) sudo:\s+(?P<user>\S+) : TTY=(?P<tty>\S+) ; PWD=(?P<pwd>\S+) ; USER=(?P<target_user>\S+) ; COMMAND=(?P<command>.+)`,
		})
		result, err := p.Parse([]byte(`Oct 11 22:14:15 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/ls`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["user"] != "admin" {
			return fmt.Sprintf("user mismatch: %s", result.Fields["user"]), false
		}
		if result.Fields["target_user"] != "root" {
			return fmt.Sprintf("target_user mismatch: %s", result.Fields["target_user"]), false
		}
		return fmt.Sprintf("OK: user=%s target=%s cmd=%s", result.Fields["user"], result.Fields["target_user"], result.Fields["command"]), true
	}, &passed, &failed)

	// 15. JSON - CloudFlare logs
	test("JSON - CloudFlare logs", func() (string, bool) {
		p := parser.New(parser.Config{Format: parser.FormatJSON})
		result, err := p.Parse([]byte(`{"timestamp":"2023-10-11T22:14:15Z","clientIP":"192.168.1.100","clientRequestHost":"example.com","edgeResponseStatus":200,"clientRequestMethod":"GET"}`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["clientIP"] != "192.168.1.100" {
			return fmt.Sprintf("clientIP mismatch: %s", result.Fields["clientIP"]), false
		}
		if result.Fields["edgeResponseStatus"] != "200" {
			return fmt.Sprintf("edgeResponseStatus mismatch: %s", result.Fields["edgeResponseStatus"]), false
		}
		return fmt.Sprintf("OK: ip=%s status=%s", result.Fields["clientIP"], result.Fields["edgeResponseStatus"]), true
	}, &passed, &failed)

	// 16. JSON - AWS CloudTrail
	test("JSON - AWS CloudTrail", func() (string, bool) {
		p := parser.New(parser.Config{
			Format: parser.FormatJSON,
			JSONPaths: map[string]string{
				"event_name": "$.eventName",
				"source_ip":  "$.sourceIPAddress",
				"user_name":  "$.userIdentity.userName",
			},
		})
		result, err := p.Parse([]byte(`{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","userName":"admin"},"eventTime":"2023-10-11T22:14:15Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeInstances","sourceIPAddress":"10.0.0.1","responseElements":null}`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["event_name"] != "DescribeInstances" {
			return fmt.Sprintf("event_name mismatch: %s", result.Fields["event_name"]), false
		}
		if result.Fields["user_name"] != "admin" {
			return fmt.Sprintf("user_name mismatch: %s", result.Fields["user_name"]), false
		}
		return fmt.Sprintf("OK: event=%s user=%s", result.Fields["event_name"], result.Fields["user_name"]), true
	}, &passed, &failed)

	// 17. Regex - DHCP
	test("Regex - DHCP log", func() (string, bool) {
		p := parser.New(parser.Config{
			Format: parser.FormatRegex,
			Regex:  `(?P<timestamp>\w+ \d+ \d+:\d+:\d+) (?P<hostname>\S+) dhcpd: (?P<action>\w+) on (?P<ip>[\d.]+) to (?P<mac>[\da-f:]+) via (?P<interface>\S+)`,
		})
		result, err := p.Parse([]byte(`Oct 11 22:14:15 server dhcpd: DHCPACK on 192.168.1.100 to 00:11:22:33:44:55 via eth0`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["action"] != "DHCPACK" {
			return fmt.Sprintf("action mismatch: %s", result.Fields["action"]), false
		}
		if result.Fields["ip"] != "192.168.1.100" {
			return fmt.Sprintf("ip mismatch: %s", result.Fields["ip"]), false
		}
		if result.Fields["mac"] != "00:11:22:33:44:55" {
			return fmt.Sprintf("mac mismatch: %s", result.Fields["mac"]), false
		}
		return fmt.Sprintf("OK: action=%s ip=%s mac=%s", result.Fields["action"], result.Fields["ip"], result.Fields["mac"]), true
	}, &passed, &failed)

	// 18. Regex - DNS query log
	test("Regex - DNS query log", func() (string, bool) {
		p := parser.New(parser.Config{
			Format: parser.FormatRegex,
			Regex:  `(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) queries: info: client (?P<client>[\d.]+)#(?P<port>\d+): query: (?P<domain>[\w.]+) (?P<class>\w+) (?P<type>\w+)`,
		})
		result, err := p.Parse([]byte(`2023-10-11 22:14:15 queries: info: client 10.0.0.1#12345: query: example.com IN A`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["domain"] != "example.com" {
			return fmt.Sprintf("domain mismatch: %s", result.Fields["domain"]), false
		}
		if result.Fields["type"] != "A" {
			return fmt.Sprintf("type mismatch: %s", result.Fields["type"]), false
		}
		return fmt.Sprintf("OK: client=%s domain=%s type=%s", result.Fields["client"], result.Fields["domain"], result.Fields["type"]), true
	}, &passed, &failed)

	// 19. Regex - IDS/IPS (Suricata)
	test("Regex - Suricata alert", func() (string, bool) {
		p := parser.New(parser.Config{
			Format: parser.FormatRegex,
			Regex:  `(?P<timestamp>\d{2}/\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+).*\[Classification:\s*(?P<classification>[^\]]*)\].*\[Priority:\s*(?P<priority>\d+)\].*\{(?P<proto>\w+)\}\s*(?P<src>[\d.]+):(?P<sport>\d+)\s*->\s*(?P<dst>[\d.]+):(?P<dport>\d+)`,
		})
		result, err := p.Parse([]byte(`10/11/23-22:14:15.123456 [**] [1:2001234:1] ET SCAN Potential SSH Scan [**] [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.0.0.1:12345 -> 10.0.0.2:22`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["classification"] != "Attempted Information Leak" {
			return fmt.Sprintf("classification mismatch: %s", result.Fields["classification"]), false
		}
		return fmt.Sprintf("OK: class=%s proto=%s priority=%s", result.Fields["classification"], result.Fields["proto"], result.Fields["priority"]), true
	}, &passed, &failed)

	// 20. Regex - VPN (OpenVPN)
	test("Regex - OpenVPN log", func() (string, bool) {
		p := parser.New(parser.Config{
			Format: parser.FormatRegex,
			Regex:  `(?P<timestamp>\w+ \d+ \d+:\d+:\d+) (?P<hostname>\S+) (?P<daemon>\S+)\[(?P<pid>\d+)\]: (?P<client>[\d.]+):(?P<port>\d+) (?P<message>.+)`,
		})
		result, err := p.Parse([]byte(`Oct 11 22:14:15 server openvpn[1234]: 10.0.0.1:54321 TLS: Initial packet from [AF_INET]10.0.0.1:54321, sid=abc123`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["client"] != "10.0.0.1" {
			return fmt.Sprintf("client mismatch: %s", result.Fields["client"]), false
		}
		if result.Fields["port"] != "54321" {
			return fmt.Sprintf("port mismatch: %s", result.Fields["port"]), false
		}
		return fmt.Sprintf("OK: client=%s port=%s", result.Fields["client"], result.Fields["port"]), true
	}, &passed, &failed)

	// 21. Regex - auditd (process execution)
	test("Regex - auditd process", func() (string, bool) {
		p := parser.New(parser.Config{
			Format: parser.FormatRegex,
			Regex:  `type=(?P<type>\S+) msg=audit\((?P<audit_id>[^)]+)\): arch=\S+ syscall=(?P<syscall>\d+) success=(?P<success>\w+) exit=(?P<exit>\d+) pid=(?P<pid>\d+) uid=(?P<uid>\d+) comm="(?P<comm>[^"]*)"`,
		})
		result, err := p.Parse([]byte(`type=SYSCALL msg=audit(1234567890.123:12345): arch=c000003e syscall=59 success=yes exit=0 pid=1234 uid=1000 comm="/usr/bin/python3"`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["syscall"] != "59" {
			return fmt.Sprintf("syscall mismatch: %s", result.Fields["syscall"]), false
		}
		if result.Fields["pid"] != "1234" {
			return fmt.Sprintf("pid mismatch: %s", result.Fields["pid"]), false
		}
		if result.Fields["comm"] != "/usr/bin/python3" {
			return fmt.Sprintf("comm mismatch: %s", result.Fields["comm"]), false
		}
		return fmt.Sprintf("OK: syscall=%s pid=%s comm=%s", result.Fields["syscall"], result.Fields["pid"], result.Fields["comm"]), true
	}, &passed, &failed)

	// 22. JSON - Kubernetes audit
	test("JSON - Kubernetes audit", func() (string, bool) {
		p := parser.New(parser.Config{
			Format: parser.FormatJSON,
			JSONPaths: map[string]string{
				"user":      "$.user.username",
				"verb":      "$.verb",
				"resource":  "$.objectRef.resource",
				"namespace": "$.objectRef.namespace",
				"src_ip":    "$.sourceIPs[0]",
			},
		})
		result, err := p.Parse([]byte(`{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Request","auditID":"abc123","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/default/pods","verb":"create","user":{"username":"admin","groups":["system:masters"]},"sourceIPs":["10.0.0.1"],"objectRef":{"resource":"pods","namespace":"default","name":"my-pod"},"responseStatus":{"code":201}}`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["user"] != "admin" {
			return fmt.Sprintf("user mismatch: %s", result.Fields["user"]), false
		}
		if result.Fields["verb"] != "create" {
			return fmt.Sprintf("verb mismatch: %s", result.Fields["verb"]), false
		}
		return fmt.Sprintf("OK: user=%s verb=%s resource=%s ns=%s", result.Fields["user"], result.Fields["verb"], result.Fields["resource"], result.Fields["namespace"]), true
	}, &passed, &failed)

	// 23. Regex - fail2ban
	test("Regex - fail2ban", func() (string, bool) {
		p := parser.New(parser.Config{
			Format: parser.FormatRegex,
			Regex:  `(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+) (?P<service>\S+)\[(?P<pid>\d+)\]: (?P<action>\S+)\s+(?P<ip>[\d.]+)`,
		})
		result, err := p.Parse([]byte(`2023-10-11 22:14:15,123 sshd[1234]: Ban 10.0.0.1`))
		if err != nil {
			return fmt.Sprintf("ERROR: %v", err), false
		}
		if result.Fields["service"] != "sshd" {
			return fmt.Sprintf("service mismatch: %s", result.Fields["service"]), false
		}
		if result.Fields["ip"] != "10.0.0.1" {
			return fmt.Sprintf("ip mismatch: %s", result.Fields["ip"]), false
		}
		return fmt.Sprintf("OK: service=%s action=%s ip=%s", result.Fields["service"], strings.TrimSpace(result.Fields["action"]), result.Fields["ip"]), true
	}, &passed, &failed)

	// Summary
	fmt.Println()
	fmt.Println("=== Results ===")
	fmt.Printf("Passed: %d / %d\n", passed, passed+failed)
	fmt.Printf("Failed: %d / %d\n", failed, passed+failed)
	fmt.Println()

	if failed == 0 {
		fmt.Println("ALL TESTS PASSED!")
	}
}

func test(name string, fn func() (string, bool), passed, failed *int) {
	msg, ok := fn()
	status := "PASS"
	if !ok {
		status = "FAIL"
		(*failed)++
	} else {
		(*passed)++
	}
	fmt.Printf("[%s] %s: %s\n", status, name, msg)
}