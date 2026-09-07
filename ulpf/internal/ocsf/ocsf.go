package ocsf

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/bashmyhed/ulpf/internal/parser"
)

// Config configures the OCSF mapper
type Config struct {
	SchemaVersion string
	Mapping       Mapping
}

// Mapping defines how parser fields map to OCSF fields
type Mapping struct {
	EventClass  string
	Fields      map[string]string // dest -> src
	SeverityMap map[string]string // src_value -> severity
}

// Event is an OCSF event
type Event struct {
	SchemaVersion string
	Class         string
	TypeUid       string
	Time          time.Time
	Severity      string
	ActivityID    string
	SrcEndpoint   Endpoint
	DstEndpoint   Endpoint
	Process       Process
	User          User
	Metadata      Metadata
	Unmapped      map[string]string
}

// Endpoint represents a network endpoint
type Endpoint struct {
	IP   string
	Port int
}

// Process represents a process
type Process struct {
	Name    string
	PID     int
	CmdLine string
}

// User represents a user
type User struct {
	Name string
	UID  int
}

// Metadata is OCSF metadata
type Metadata struct {
	Product Product
	Version string
}

// Product is OCSF product metadata
type Product struct {
	Name string
}

// Mapper maps parsed events to OCSF events
type Mapper struct {
	config Config
}

// NewMapper creates a new OCSF mapper
func NewMapper(config Config) *Mapper {
	return &Mapper{config: config}
}

// Map maps a parsed event to an OCSF event
func (m *Mapper) Map(result *parser.Result) (*Event, error) {
	event := NewEvent(m.config.Mapping.EventClass, m.config.SchemaVersion)

	// Map timestamp
	event.Time = result.Timestamp

	// Map fields
	for dest, src := range m.config.Mapping.Fields {
		if srcVal, ok := result.Fields[src]; ok {
			m.setField(event, dest, srcVal)
		}
	}

	// Apply severity mapping
	if len(m.config.Mapping.SeverityMap) > 0 {
		for srcVal, severity := range m.config.Mapping.SeverityMap {
			for _, v := range result.Fields {
				if v == srcVal {
					event.Severity = severity
					break
				}
			}
		}
	}

	// Set unmapped fields
	event.Unmapped = make(map[string]string)
	for k, v := range result.Fields {
		mapped := false
		for _, src := range m.config.Mapping.Fields {
			if src == k {
				mapped = true
				break
			}
		}
		if !mapped {
			event.Unmapped[k] = v
		}
	}

	return event, nil
}

func (m *Mapper) setField(event *Event, path string, value string) {
	switch path {
	case "src_endpoint.ip":
		event.SrcEndpoint.IP = value
	case "src_endpoint.port":
		if port, err := strconv.Atoi(value); err == nil {
			event.SrcEndpoint.Port = port
		}
	case "dst_endpoint.ip":
		event.DstEndpoint.IP = value
	case "dst_endpoint.port":
		if port, err := strconv.Atoi(value); err == nil {
			event.DstEndpoint.Port = port
		}
	case "process.name":
		event.Process.Name = value
	case "process.pid":
		if pid, err := strconv.Atoi(value); err == nil {
			event.Process.PID = pid
		}
	case "process.cmdline":
		event.Process.CmdLine = value
	case "user.name":
		event.User.Name = value
	case "user.uid":
		if uid, err := strconv.Atoi(value); err == nil {
			event.User.UID = uid
		}
	case "activity_id":
		event.ActivityID = value
	}
}

// NewEvent creates a new OCSF event with metadata
func NewEvent(class string, schemaVersion string) *Event {
	return &Event{
		SchemaVersion: schemaVersion,
		Class:         class,
		Time:          time.Now().UTC(),
		TypeUid:        generateTypeUid(class),
		Severity:      "medium",
		Metadata: Metadata{
			Product: Product{Name: "ULPF"},
			Version: schemaVersion,
		},
	}
}

func generateTypeUid(class string) string {
	typeUids := map[string]string{
		"network_activity": "1",
		"authentication":   "2",
		"process_activity": "3",
		"dns_activity":      "4",
		"http_activity":     "5",
	}
	if uid, ok := typeUids[class]; ok {
		return uid
	}
	return "99"
}

// Validator validates OCSF events
type Validator struct {
	schemaVersion string
}

// NewValidator creates a new OCSF validator
func NewValidator(schemaVersion string) *Validator {
	return &Validator{schemaVersion: schemaVersion}
}

// Validate validates an OCSF event
func (v *Validator) Validate(event *Event) error {
	if event.SrcEndpoint.IP != "" {
		if net.ParseIP(event.SrcEndpoint.IP) == nil {
			return fmt.Errorf("invalid src_endpoint.ip: %s", event.SrcEndpoint.IP)
		}
	}
	if event.DstEndpoint.IP != "" {
		if net.ParseIP(event.DstEndpoint.IP) == nil {
			return fmt.Errorf("invalid dst_endpoint.ip: %s", event.DstEndpoint.IP)
		}
	}
	if event.SrcEndpoint.Port < 0 || event.SrcEndpoint.Port > 65535 {
		return fmt.Errorf("invalid src_endpoint.port: %d", event.SrcEndpoint.Port)
	}
	if event.DstEndpoint.Port < 0 || event.DstEndpoint.Port > 65535 {
		return fmt.Errorf("invalid dst_endpoint.port: %d", event.DstEndpoint.Port)
	}
	return nil
}

// Classifier classifies events based on content
type Classifier struct{}

// NewClassifier creates a new classifier
func NewClassifier(schemaVersion string) *Classifier {
	return &Classifier{}
}

// Classify determines the OCSF class from parsed fields
func (c *Classifier) Classify(result *parser.Result) string {
	for k, v := range result.Fields {
		if k == "src_ip" || k == "dst_ip" || k == "src_endpoint.ip" || k == "dst_endpoint.ip" {
			if net.ParseIP(v) != nil {
				return "network_activity"
			}
		}
	}

	authKeywords := []string{"login", "logout", "auth", "sshd", "password", "publickey"}
	for _, v := range result.Fields {
		for _, kw := range authKeywords {
			if contains(v, kw) {
				return "authentication"
			}
		}
	}

	processKeywords := []string{"process", "exec", "pid", "cmdline", "nginx", "python"}
	for k, v := range result.Fields {
		for _, kw := range processKeywords {
			if contains(k, kw) || contains(v, kw) {
				return "process_activity"
			}
		}
	}

	return "network_activity"
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}