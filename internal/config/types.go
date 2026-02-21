package config

// Config is the top-level application configuration.
type Config struct {
	Version int `yaml:"version"`

	Proxy    ProxyConfig   `yaml:"proxy"`
	Network  NetworkConfig `yaml:"network"`
	DNS      DNSConfig     `yaml:"dns"`
	DNSCrypt DNSCryptConfig `yaml:"dnscrypt"`
	IPSet    IPSetConfig   `yaml:"ipset"`
	Daemon   DaemonConfig  `yaml:"daemon"`

	ExcludedNetworks []string `yaml:"excluded_networks"`
	SetupFinished    bool     `yaml:"setup_finished"`
}

// ProxyConfig describes how matched traffic is forwarded.
// KST does not manage the proxy software itself — the user sets up their own.
type ProxyConfig struct {
	// Type selects the traffic redirection mechanism:
	//   "redirect" — NAT REDIRECT to a local transparent proxy port (ss-redir, xray, sing-box, …)
	//   "tun"      — MARK + policy routing via a VPN interface (WireGuard, OpenVPN, …)
	Type string `yaml:"type"`

	// LocalPort is the port the transparent proxy listens on. Used when Type == "redirect".
	LocalPort int `yaml:"local_port"`

	// Interface is the VPN tunnel interface name (e.g. wg0, tun0). Used when Type == "tun".
	Interface string `yaml:"interface"`
}

// NetworkConfig holds network interface settings.
type NetworkConfig struct {
	EntwareInterface string `yaml:"entware_interface"`
}

// DNSConfig holds DNS cache settings for dnsmasq.
type DNSConfig struct {
	CacheEnabled bool `yaml:"cache_enabled"`
	CacheSize    int  `yaml:"cache_size"`
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
		Proxy: ProxyConfig{
			Type:      "redirect",
			LocalPort: 1080,
		},
		DNS: DNSConfig{
			CacheEnabled: true,
			CacheSize:    1536,
		},
		DNSCrypt: DNSCryptConfig{
			Port: 9153,
		},
		IPSet: IPSetConfig{
			TableName: "bypass",
		},
		Daemon: DaemonConfig{
			WebListen: ":8080",
			LogLevel:  "info",
		},
		ExcludedNetworks: []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		},
	}
}
