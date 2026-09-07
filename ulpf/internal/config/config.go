package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the ULPF configuration
type Config struct {
	Network NetworkConfig `yaml:"network"`
	Spool   SpoolConfig   `yaml:"spool"`
	Sinks   SinksConfig  `yaml:"sinks"`
}

// NetworkConfig configures network listeners
type NetworkConfig struct {
	TCPListen     string `yaml:"tcp_listen"`
	MetricsListen string `yaml:"metrics_listen"`
}

// SpoolConfig configures the spool
type SpoolConfig struct {
	Path        string `yaml:"path"`
	MaxBytes    int64  `yaml:"max_bytes"`
	SegmentSize int64  `yaml:"segment_size"`
}

// SinksConfig configures output sinks
type SinksConfig struct {
	JSONL      JSONLSinkConfig      `yaml:"jsonl"`
	Syslog     SyslogSinkConfig     `yaml:"syslog"`
	ClickHouse ClickHouseSinkConfig `yaml:"clickhouse"`
}

// JSONLSinkConfig configures JSONL sink
type JSONLSinkConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// SyslogSinkConfig configures syslog sink
type SyslogSinkConfig struct {
	Enabled bool   `yaml:"enabled"`
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
}

// ClickHouseSinkConfig configures ClickHouse sink
type ClickHouseSinkConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Database string `yaml:"database"`
}

// Load loads configuration from a YAML file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Set defaults
	if cfg.Network.TCPListen == "" {
		cfg.Network.TCPListen = "0.0.0.0:5514"
	}
	if cfg.Network.MetricsListen == "" {
		cfg.Network.MetricsListen = "0.0.0.0:9090"
	}
	if cfg.Spool.Path == "" {
		cfg.Spool.Path = "/data/spool"
	}
	if cfg.Spool.MaxBytes == 0 {
		cfg.Spool.MaxBytes = 1024 * 1024 * 1024 // 1GB
	}
	if cfg.Spool.SegmentSize == 0 {
		cfg.Spool.SegmentSize = 64 * 1024 * 1024 // 64MB
	}

	return &cfg, nil
}