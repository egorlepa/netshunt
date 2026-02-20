package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/guras256/keenetic-split-tunnel/internal/platform"
)

// Load reads the config from disk. If the file doesn't exist, returns defaults.
func Load() (*Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(platform.ConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// Save writes the config to disk.
func Save(cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(platform.ConfigFile), 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(platform.ConfigFile, data, 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
