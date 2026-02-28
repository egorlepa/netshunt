package config

// Config is the top-level application configuration.
type Config struct {
	Version int `yaml:"version"`

	Routing  RoutingConfig  `yaml:"routing"`
	Network  NetworkConfig  `yaml:"network"`
	DNS      DNSConfig      `yaml:"dns"`
	DNSCrypt DNSCryptConfig `yaml:"dnscrypt"`
	IPSet    IPSetConfig    `yaml:"ipset"`
	Daemon   DaemonConfig   `yaml:"daemon"`

	ExcludedNetworks []string `yaml:"excluded_networks"`
	IPv6             bool     `yaml:"ipv6"`
	SetupFinished    bool     `yaml:"setup_finished"`
}

// RoutingConfig describes how matched traffic is forwarded.
// netshunt does not manage the proxy software itself — the user sets up their own.
type RoutingConfig struct {
	// LocalPort is the port the transparent proxy listens on.
	LocalPort int `yaml:"local_port"`
}

// NetworkConfig holds network interface settings.
type NetworkConfig struct {
	EntwareInterface string `yaml:"entware_interface"`
}

// DNSConfig holds DNS forwarder settings.
type DNSConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

// DNSCryptConfig holds dnscrypt-proxy2 settings.
type DNSCryptConfig struct {
	Port int `yaml:"port"`
}

// IPSetConfig holds ipset table settings.
type IPSetConfig struct {
	TableName string `yaml:"table_name"`
}

// DaemonConfig holds daemon/web UI settings.
type DaemonConfig struct {
	WebListen string `yaml:"web_listen"`
	LogLevel  string `yaml:"log_level"`
}

// Defaults returns a Config with sensible default values.
func Defaults() Config {
	return Config{
		Version: 1,
		Routing: RoutingConfig{
			LocalPort: 1080,
		},
		DNS: DNSConfig{
			ListenAddr: ":53",
		},
		DNSCrypt: DNSCryptConfig{
			Port: 9153,
		},
		IPSet: IPSetConfig{
			TableName: "bypass",
		},
		Daemon: DaemonConfig{
			WebListen: ":8765",
			LogLevel:  "info",
		},
		ExcludedNetworks: []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"fc00::/7",
			"fe80::/10",
			"::1/128",
		},
	}
}
