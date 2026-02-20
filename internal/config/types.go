package config


// Config is the top-level application configuration.
type Config struct {
	Version int `yaml:"version"`
	Mode    string `yaml:"mode"` // "shadowsocks" (future: "openvpn", "wireguard")

	Network     NetworkConfig     `yaml:"network"`
	Shadowsocks ShadowsocksConfig `yaml:"shadowsocks"`
	DNS         DNSConfig         `yaml:"dns"`
	DNSCrypt    DNSCryptConfig    `yaml:"dnscrypt"`
	IPSet       IPSetConfig       `yaml:"ipset"`
	Daemon      DaemonConfig      `yaml:"daemon"`

	ExcludedNetworks []string `yaml:"excluded_networks"`
	SetupFinished    bool     `yaml:"setup_finished"`
}

// NetworkConfig holds network interface settings.
type NetworkConfig struct {
	EntwareInterface string `yaml:"entware_interface"`
}

// ShadowsocksConfig holds Shadowsocks proxy settings.
type ShadowsocksConfig struct {
	Server     string `yaml:"server"`
	ServerPort int    `yaml:"server_port"`
	LocalPort  int    `yaml:"local_port"`
	Password   string `yaml:"password"`
	Method     string `yaml:"method"`
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
		Mode:    "shadowsocks",
		Shadowsocks: ShadowsocksConfig{
			LocalPort: 1181,
			Method:    "chacha20-ietf-poly1305",
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
