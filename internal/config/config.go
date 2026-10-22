package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/egorlepa/netshunt/internal/platform"
)

// Load reads the config from disk. If the file doesn't exist, returns defaults.
func Load() (*Config, error) {
	data, err := os.ReadFile(platform.ConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := Defaults()
			return &cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	return parse(data)
}

// parse decodes YAML over the defaults. Unknown keys (e.g. the dnscrypt
// section of configs written before 1.5.7) are ignored.
func parse(data []byte) (*Config, error) {
	cfg := Defaults()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// Save writes the config to disk.
func Save(cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := platform.WriteFileAtomic(platform.ConfigFile, data, 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
