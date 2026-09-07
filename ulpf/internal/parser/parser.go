package parser

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Format identifies the parser format type
type Format string

const (
	FormatJSON      Format = "json"
	FormatSyslog3164 Format = "syslog3164"
	FormatSyslog5424 Format = "syslog5424"
	FormatKeyValue  Format = "keyvalue"
	FormatRegex     Format = "regex"
	FormatDelimiter Format = "delimiter"
)

// Config configures a parser
type Config struct {
	Format          Format
	Regex           string
	Delimiter       string
	Fields          []string
	FieldMap        map[string]string
	JSONPaths       map[string]string
	TimestampField  string
	TimestampFormat string
}

// Result is the output of parsing
type Result struct {
	Raw              string
	Fields           map[string]string
	Timestamp        time.Time
	ParserVersion    string
	ParserConfigHash string
}

// Parser interface
type Parser interface {
	Parse(data []byte) (*Result, error)
	Version() string
	ConfigHash() string
}

// baseParser common functionality
type baseParser struct {
	config  Config
	version string
}

func (p *baseParser) hashConfig() string {
	data := fmt.Sprintf("%s:%s:%s:%s:%v",
		p.config.Format, p.config.Regex, p.config.Delimiter,
		p.config.Fields, p.config.FieldMap)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

func (p *baseParser) parseTimestamp(fields map[string]string) time.Time {
	if p.config.TimestampField == "" {
		return time.Now().UTC()
	}
	tsStr, ok := fields[p.config.TimestampField]
	if !ok {
		return time.Now().UTC()
	}
	format := p.config.TimestampFormat
	if format == "" {
		formats := []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02 15:04:05"}
		for _, f := range formats {
			if t, err := time.Parse(f, tsStr); err == nil {
				return t.UTC()
			}
		}
		return time.Now().UTC()
	}
	t, err := time.Parse(format, tsStr)
	if err != nil {
		return time.Now().UTC()
	}
	return t.UTC()
}

func (p *baseParser) applyFieldMap(fields map[string]string) map[string]string {
	if len(p.config.FieldMap) == 0 {
		return fields
	}
	result := make(map[string]string)
	for k, v := range fields {
		if mapped, ok := p.config.FieldMap[k]; ok {
			result[mapped] = v
		}
		result[k] = v
	}
	return result
}

func (p *baseParser) Version() string  { return p.version }
func (p *baseParser) ConfigHash() string { return p.hashConfig() }

// New creates a parser
func New(config Config) Parser {
	bp := baseParser{config: config, version: "1.0.0"}
	switch config.Format {
	case FormatJSON:
		return &jsonParser{baseParser: bp}
	case FormatSyslog3164:
		return &syslog3164Parser{baseParser: bp}
	case FormatSyslog5424:
		return &syslog5424Parser{baseParser: bp}
	case FormatKeyValue:
		return &keyValueParser{baseParser: bp}
	case FormatRegex:
		return &regexParser{baseParser: bp}
	case FormatDelimiter:
		return &delimiterParser{baseParser: bp}
	default:
		return &jsonParser{baseParser: bp}
	}
}

// JSON Parser
type jsonParser struct{ baseParser }

func (p *jsonParser) Parse(data []byte) (*Result, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	var rawJSON map[string]interface{}
	if err := json.Unmarshal(data, &rawJSON); err != nil {
		return nil, fmt.Errorf("JSON parse error: %w", err)
	}
	fields := make(map[string]string)
	for k, v := range rawJSON {
		fields[k] = fmt.Sprintf("%v", v)
	}
	// JSON path extractions
	for fieldName, path := range p.config.JSONPaths {
		if val := extractJSONPath(rawJSON, path); val != nil {
			fields[fieldName] = fmt.Sprintf("%v", val)
		}
	}
	fields = p.applyFieldMap(fields)
	return &Result{
		Raw:              string(data),
		Fields:           fields,
		Timestamp:        p.parseTimestamp(fields),
		ParserVersion:    p.version,
		ParserConfigHash: p.hashConfig(),
	}, nil
}

// Syslog RFC 3164
type syslog3164Parser struct {
	baseParser
	re *regexp.Regexp
}

func (p *syslog3164Parser) init() {
	if p.re == nil {
		p.re = regexp.MustCompile(`^<(?P<priority>\d+)>(?P<timestamp>\w+ \d+ \d+:\d+:\d+) (?P<hostname>\S+) (?P<tag>\S+?): (?P<content>.*)$`)
	}
}

func (p *syslog3164Parser) Parse(data []byte) (*Result, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	p.init()
	matches := p.re.FindStringSubmatch(string(data))
	if matches == nil {
		return nil, fmt.Errorf("not a valid RFC 3164 syslog message")
	}
	fields := make(map[string]string)
	for i, name := range p.re.SubexpNames() {
		if i > 0 && name != "" {
			fields[name] = matches[i]
		}
	}
	fields = p.applyFieldMap(fields)
	return &Result{Raw: string(data), Fields: fields, Timestamp: p.parseTimestamp(fields), ParserVersion: p.version, ParserConfigHash: p.hashConfig()}, nil
}

// Syslog RFC 5424
type syslog5424Parser struct {
	baseParser
	re *regexp.Regexp
}

func (p *syslog5424Parser) init() {
	if p.re == nil {
		p.re = regexp.MustCompile(`^<(?P<priority>\d+)>(?P<version>\d+) (?P<timestamp>\S+) (?P<hostname>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) (?P<struct_data>\S+) ?(?P<content>.*)$`)
	}
}

func (p *syslog5424Parser) Parse(data []byte) (*Result, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	p.init()
	matches := p.re.FindStringSubmatch(string(data))
	if matches == nil {
		return nil, fmt.Errorf("not a valid RFC 5424 syslog message")
	}
	fields := make(map[string]string)
	for i, name := range p.re.SubexpNames() {
		if i > 0 && name != "" {
			fields[name] = matches[i]
		}
	}
	fields = p.applyFieldMap(fields)
	return &Result{Raw: string(data), Fields: fields, Timestamp: p.parseTimestamp(fields), ParserVersion: p.version, ParserConfigHash: p.hashConfig()}, nil
}

// Key=Value Parser
type keyValueParser struct{ baseParser }

func (p *keyValueParser) Parse(data []byte) (*Result, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	fields := make(map[string]string)
	for _, pair := range strings.Fields(string(data)) {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			fields[parts[0]] = parts[1]
		}
	}
	fields = p.applyFieldMap(fields)
	return &Result{Raw: string(data), Fields: fields, Timestamp: p.parseTimestamp(fields), ParserVersion: p.version, ParserConfigHash: p.hashConfig()}, nil
}

// Regex Parser
type regexParser struct {
	baseParser
	re *regexp.Regexp
}

func (p *regexParser) Parse(data []byte) (*Result, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if p.config.Regex == "" {
		return nil, fmt.Errorf("regex pattern not configured")
	}
	re, err := regexp.Compile(p.config.Regex)
	if err != nil {
		return nil, fmt.Errorf("invalid regex: %w", err)
	}
	matches := re.FindStringSubmatch(string(data))
	if matches == nil {
		return nil, fmt.Errorf("regex did not match")
	}
	fields := make(map[string]string)
	for i, name := range re.SubexpNames() {
		if i > 0 && name != "" {
			fields[name] = matches[i]
		}
	}
	fields = p.applyFieldMap(fields)
	return &Result{Raw: string(data), Fields: fields, Timestamp: p.parseTimestamp(fields), ParserVersion: p.version, ParserConfigHash: p.hashConfig()}, nil
}

// Delimiter Parser
type delimiterParser struct{ baseParser }

func (p *delimiterParser) Parse(data []byte) (*Result, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if p.config.Delimiter == "" {
		return nil, fmt.Errorf("delimiter not configured")
	}
	parts := strings.Split(string(data), p.config.Delimiter)
	fields := make(map[string]string)
	for i, part := range parts {
		if i < len(p.config.Fields) {
			fields[p.config.Fields[i]] = part
		} else {
			fields["field_"+strconv.Itoa(i)] = part
		}
	}
	fields = p.applyFieldMap(fields)
	return &Result{Raw: string(data), Fields: fields, Timestamp: p.parseTimestamp(fields), ParserVersion: p.version, ParserConfigHash: p.hashConfig()}, nil
}

// JSON Path Extraction
func extractJSONPath(data map[string]interface{}, path string) interface{} {
	if !strings.HasPrefix(path, "$.") {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(path, "$."), ".")
	current := data
	for i, part := range parts {
		if i == len(parts)-1 {
			return current[part]
		}
		m, ok := current[part].(map[string]interface{})
		if !ok {
			return nil
		}
		current = m
	}
	return nil
}