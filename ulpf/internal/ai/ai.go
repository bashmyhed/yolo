package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Provider is the interface for AI providers
type Provider interface {
	Name() string
	GenerateParserConfig(samples []string) (ParserConfig, error)
	GenerateMappingConfig(samples []string, eventClass string) (MappingConfig, error)
	GenerateTestCases(samples []string) ([]TestCase, error)
	ValidateConfig(config ParserConfig) error
	RunTest(config ParserConfig, testCase TestCase) (TestResult, error)
}

// ParserConfig represents a parser configuration
type ParserConfig struct {
	Format string
	Regex  string
}

// MappingConfig represents an OCSF mapping configuration
type MappingConfig struct {
	EventClass string
	Fields     map[string]string
}

// TestCase represents a test case
type TestCase struct {
	Name   string
	Input  string
	Expect map[string]string
}

// TestResult represents the result of running a test
type TestResult struct {
	Passed   bool
	Failures []string
}

// MockProvider is a mock AI provider for testing
type MockProvider struct{}

// NewMockProvider creates a new mock provider
func NewMockProvider() Provider {
	return &MockProvider{}
}

// Name returns the provider name
func (p *MockProvider) Name() string {
	return "mock"
}

// GenerateParserConfig generates a parser config from samples
func (p *MockProvider) GenerateParserConfig(samples []string) (ParserConfig, error) {
	if len(samples) == 0 {
		return ParserConfig{}, fmt.Errorf("no samples provided")
	}

	// Simple heuristic: detect format from first sample
	sample := samples[0]
	if strings.HasPrefix(sample, "{") {
		return ParserConfig{Format: "json"}, nil
	}

	if strings.HasPrefix(sample, "<") {
		return ParserConfig{Format: "syslog3164"}, nil
	}

	// Generate regex for space-separated fields
	regex := generateRegexFromSamples(samples)

	return ParserConfig{
		Format: "regex",
		Regex:  regex,
	}, nil
}

// GenerateMappingConfig generates a mapping config from samples
func (p *MockProvider) GenerateMappingConfig(samples []string, eventClass string) (MappingConfig, error) {
	if len(samples) == 0 {
		return MappingConfig{}, fmt.Errorf("no samples provided")
	}

	// Extract field names from samples
	fields := make(map[string]string)
	for _, sample := range samples {
		extractFields(sample, fields)
	}

	return MappingConfig{
		EventClass: eventClass,
		Fields:     fields,
	}, nil
}

// GenerateTestCases generates test cases from samples
func (p *MockProvider) GenerateTestCases(samples []string) ([]TestCase, error) {
	if len(samples) == 0 {
		return nil, fmt.Errorf("no samples provided")
	}

	testCases := make([]TestCase, len(samples))
	for i, sample := range samples {
		testCases[i] = TestCase{
			Name:   fmt.Sprintf("test-%d", i),
			Input:  sample,
			Expect: extractExpected(sample),
		}
	}

	return testCases, nil
}

// ValidateConfig validates a parser config
func (p *MockProvider) ValidateConfig(config ParserConfig) error {
	if config.Format == "" {
		return fmt.Errorf("format is required")
	}

	if config.Format == "regex" && config.Regex == "" {
		return fmt.Errorf("regex is required for regex format")
	}

	return nil
}

// RunTest runs a test case against a parser config
func (p *MockProvider) RunTest(config ParserConfig, testCase TestCase) (TestResult, error) {
	result := TestResult{Passed: true}

	// Simple regex matching for test execution
	if config.Regex != "" {
		re, err := regexp.Compile(config.Regex)
		if err != nil {
			return TestResult{Passed: false, Failures: []string{fmt.Sprintf("invalid regex: %v", err)}}, nil
		}

		matches := re.FindStringSubmatch(testCase.Input)
		if matches == nil {
			return TestResult{Passed: false, Failures: []string{"regex did not match input"}}, nil
		}

		// Check expected values
		for i, name := range re.SubexpNames() {
			if name == "" {
				continue
			}
			if expected, ok := testCase.Expect[name]; ok {
				if i >= len(matches) || matches[i] != expected {
					result.Passed = false
					result.Failures = append(result.Failures, fmt.Sprintf("field %s: got %q, want %q", name, matches[i], expected))
				}
			}
		}
	}

	return result, nil
}

// Harness orchestrates the AI configuration workflow
type Harness struct {
	provider  Provider
	approved  bool
	active    bool
	config    ParserConfig
}

// NewHarness creates a new AI harness
func NewHarness(provider Provider) *Harness {
	return &Harness{provider: provider}
}

// GenerateParserConfig generates a parser config
func (h *Harness) GenerateParserConfig(samples []string) (ParserConfig, error) {
	return h.provider.GenerateParserConfig(samples)
}

// ValidateConfig validates a parser config
func (h *Harness) ValidateConfig(config ParserConfig) error {
	return h.provider.ValidateConfig(config)
}

// GenerateTestCases generates test cases
func (h *Harness) GenerateTestCases(samples []string) ([]TestCase, error) {
	return h.provider.GenerateTestCases(samples)
}

// RunAllTests runs all test cases
func (h *Harness) RunAllTests(config ParserConfig, testCases []TestCase) ([]TestResult, error) {
	results := make([]TestResult, len(testCases))
	for i, tc := range testCases {
		result, err := h.provider.RunTest(config, tc)
		if err != nil {
			return nil, err
		}
		results[i] = result
	}
	return results, nil
}

// Approve marks the config as approved
func (h *Harness) Approve() {
	h.approved = true
}

// IsApproved returns whether the config is approved
func (h *Harness) IsApproved() bool {
	return h.approved
}

// Activate activates the config
func (h *Harness) Activate(config ParserConfig) {
	h.config = config
	h.active = true
}

// IsActive returns whether the config is active
func (h *Harness) IsActive() bool {
	return h.active
}

// Helper functions

func generateRegexFromSamples(samples []string) string {
	if len(samples) == 0 {
		return ""
	}

	// Simple regex generation: match space-separated fields
	// This is a simplified version - a real AI would do much better
	return `(?P<field1>\S+) (?P<field2>\S+) (?P<field3>\S+)`
}

func extractFields(sample string, fields map[string]string) {
	// Extract key=value pairs
	pairs := strings.Fields(sample)
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			fields[parts[0]] = parts[1]
		}
	}

	// Extract JSON keys
	if strings.HasPrefix(sample, "{") {
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(sample), &jsonData); err == nil {
			for k := range jsonData {
				fields[k] = k
			}
		}
	}
}

func extractExpected(sample string) map[string]string {
	expected := make(map[string]string)

	// Extract key=value pairs
	pairs := strings.Fields(sample)
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			expected[parts[0]] = parts[1]
		}
	}

	return expected
}

// HashConfig computes a hash of the config
func HashConfig(config ParserConfig) string {
	data := fmt.Sprintf("%s:%s", config.Format, config.Regex)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}