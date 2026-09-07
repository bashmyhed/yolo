package ai_test

import (
	"testing"

	"github.com/bashmyhed/ulpf/internal/ai"
)

// Test AI provider interface
func TestAIProviderInterface(t *testing.T) {
	provider := ai.NewMockProvider()

	if provider.Name() != "mock" {
		t.Errorf("expected name=mock, got %s", provider.Name())
	}
}

// Test parser config generation
func TestGenerateParserConfig(t *testing.T) {
	provider := ai.NewMockProvider()

	samples := []string{
		`2023-10-11 22:14:15 10.0.0.1 8.8.8.8 ALLOW TCP 80 443`,
		`2023-10-11 22:14:16 10.0.0.2 8.8.8.8 DENY TCP 80 443`,
	}

	config, err := provider.GenerateParserConfig(samples)
	if err != nil {
		t.Fatalf("generate parser config failed: %v", err)
	}

	if config.Format != "regex" {
		t.Errorf("expected format=regex, got %s", config.Format)
	}

	if config.Regex == "" {
		t.Error("expected regex pattern to be set")
	}
}

// Test mapping config generation
func TestGenerateMappingConfig(t *testing.T) {
	provider := ai.NewMockProvider()

	samples := []string{
		`{"src_ip":"10.0.0.1","dst_ip":"8.8.8.8","action":"allow"}`,
	}

	config, err := provider.GenerateMappingConfig(samples, "network_activity")
	if err != nil {
		t.Fatalf("generate mapping config failed: %v", err)
	}

	if config.EventClass != "network_activity" {
		t.Errorf("expected event_class=network_activity, got %s", config.EventClass)
	}

	if len(config.Fields) == 0 {
		t.Error("expected fields to be mapped")
	}
}

// Test test case generation
func TestGenerateTestCases(t *testing.T) {
	provider := ai.NewMockProvider()

	samples := []string{
		`{"src_ip":"10.0.0.1","action":"allow"}`,
		`{"src_ip":"10.0.0.2","action":"deny"}`,
	}

	testCases, err := provider.GenerateTestCases(samples)
	if err != nil {
		t.Fatalf("generate test cases failed: %v", err)
	}

	if len(testCases) != 2 {
		t.Errorf("expected 2 test cases, got %d", len(testCases))
	}
}

// Test config validation
func TestConfigValidation(t *testing.T) {
	provider := ai.NewMockProvider()

	// Valid config
	config := ai.ParserConfig{
		Format: "regex",
		Regex:  `(?P<src_ip>[\d.]+)`,
	}

	if err := provider.ValidateConfig(config); err != nil {
		t.Errorf("expected valid config, got error: %v", err)
	}

	// Invalid config (missing regex)
	invalidConfig := ai.ParserConfig{
		Format: "regex",
	}

	if err := provider.ValidateConfig(invalidConfig); err == nil {
		t.Error("expected error for invalid config")
	}
}

// Test test case execution
func TestTestCaseExecution(t *testing.T) {
	provider := ai.NewMockProvider()

	testCase := ai.TestCase{
		Name:  "test-firewall-allow",
		Input: `2023-10-11 22:14:15 10.0.0.1 8.8.8.8 ALLOW TCP 80 443`,
		Expect: map[string]string{
			"src_ip": "10.0.0.1",
			"action": "ALLOW",
		},
	}

	config := ai.ParserConfig{
		Format: "regex",
		Regex:  `(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<src_ip>[\d.]+) (?P<dst_ip>[\d.]+) (?P<action>\w+)`,
	}

	result, err := provider.RunTest(config, testCase)
	if err != nil {
		t.Fatalf("test execution failed: %v", err)
	}

	if !result.Passed {
		t.Errorf("expected test to pass, got: %v", result.Failures)
	}
}

// Test test case failure
func TestTestCaseFailure(t *testing.T) {
	provider := ai.NewMockProvider()

	testCase := ai.TestCase{
		Name:  "test-fail",
		Input: `test input`,
		Expect: map[string]string{
			"field": "expected_value",
		},
	}

	config := ai.ParserConfig{
		Format: "regex",
		Regex:  `(?P<field>\w+)`,
	}

	result, err := provider.RunTest(config, testCase)
	if err != nil {
		t.Fatalf("test execution failed: %v", err)
	}

	if result.Passed {
		t.Error("expected test to fail")
	}
}

// Test harness workflow
func TestHarnessWorkflow(t *testing.T) {
	provider := ai.NewMockProvider()
	harness := ai.NewHarness(provider)

	samples := []string{
		`{"src_ip":"10.0.0.1","action":"allow"}`,
		`{"src_ip":"10.0.0.2","action":"deny"}`,
	}

	// Generate config
	parserConfig, err := harness.GenerateParserConfig(samples)
	if err != nil {
		t.Fatalf("generate parser config failed: %v", err)
	}

	// Validate config
	if err := harness.ValidateConfig(parserConfig); err != nil {
		t.Errorf("config validation failed: %v", err)
	}

	// Generate test cases
	testCases, err := harness.GenerateTestCases(samples)
	if err != nil {
		t.Fatalf("generate test cases failed: %v", err)
	}

	// Run all tests
	results, err := harness.RunAllTests(parserConfig, testCases)
	if err != nil {
		t.Fatalf("run tests failed: %v", err)
	}

	if len(results) != len(testCases) {
		t.Errorf("expected %d results, got %d", len(testCases), len(results))
	}
}

// Test harness with approval
func TestHarnessApproval(t *testing.T) {
	provider := ai.NewMockProvider()
	harness := ai.NewHarness(provider)

	// Config should not be approved initially
	if harness.IsApproved() {
		t.Error("config should not be approved initially")
	}

	// Approve config
	harness.Approve()

	if !harness.IsApproved() {
		t.Error("config should be approved after Approve()")
	}
}

// Test harness config activation
func TestHarnessActivation(t *testing.T) {
	provider := ai.NewMockProvider()
	harness := ai.NewHarness(provider)

	samples := []string{`{"test":"value"}`}

	config, _ := harness.GenerateParserConfig(samples)

	// Config should not be active initially
	if harness.IsActive() {
		t.Error("config should not be active initially")
	}

	// Activate config
	harness.Activate(config)

	if !harness.IsActive() {
		t.Error("config should be active after Activate()")
	}
}

// Test mock provider determinism
func TestMockProviderDeterminism(t *testing.T) {
	provider := ai.NewMockProvider()

	samples := []string{`test sample`}

	config1, _ := provider.GenerateParserConfig(samples)
	config2, _ := provider.GenerateParserConfig(samples)

	if config1.Format != config2.Format {
		t.Error("mock provider should be deterministic")
	}
}

// Test provider with empty samples
func TestProviderEmptySamples(t *testing.T) {
	provider := ai.NewMockProvider()

	_, err := provider.GenerateParserConfig([]string{})
	if err == nil {
		t.Error("expected error for empty samples")
	}
}

// Test provider with nil samples
func TestProviderNilSamples(t *testing.T) {
	provider := ai.NewMockProvider()

	_, err := provider.GenerateParserConfig(nil)
	if err == nil {
		t.Error("expected error for nil samples")
	}
}