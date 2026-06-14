package config

// Config is the top-level application configuration.
type Config struct {
	Version int `yaml:"version"`

	Routing   RoutingConfig   `yaml:"routing"`
	Network   NetworkConfig   `yaml:"network"`
	DNS       DNSConfig       `yaml:"dns"`
	DNSCrypt  DNSCryptConfig  `yaml:"dnscrypt"`
	IPSet     IPSetConfig     `yaml:"ipset"`
	Daemon    DaemonConfig    `yaml:"daemon"`
	Blocklist BlocklistConfig `yaml:"blocklist"`
	Geosite   GeositeConfig   `yaml:"geosite"`

	ExcludedNetworks []string `yaml:"excluded_networks"`
	SetupFinished    bool     `yaml:"setup_finished"`
}

// RoutingConfig describes how matched traffic is forwarded.
// netshunt does not manage the proxy software itself — the user sets up their own.
type RoutingConfig struct {
	// LocalPort is the primary transparent proxy port.
	LocalPort int `yaml:"local_port"`
	// BackupPort is an optional secondary proxy port. 0 disables failover.
	BackupPort int `yaml:"backup_port,omitempty"`
	// UseBackup routes traffic to BackupPort when true and BackupPort > 0.
	UseBackup bool `yaml:"use_backup,omitempty"`
}

// ActivePort returns the proxy port currently in use.
func (r RoutingConfig) ActivePort() int {
	if r.UseBackup && r.BackupPort > 0 {
		return r.BackupPort
	}
	return r.LocalPort
}

// BackupConfigured reports whether failover is set up.
func (r RoutingConfig) BackupConfigured() bool {
	return r.BackupPort > 0
}

// NetworkConfig holds network interface settings.
type NetworkConfig struct {
	EntwareInterface string `yaml:"entware_interface"`
	// AdditionalInterfaces are extra ingress interfaces (e.g. a WireGuard TUN
	// like awg0) that receive the same shunt interception as EntwareInterface,
	// so remote VPN clients route through the same bypass list.
	AdditionalInterfaces []string `yaml:"additional_interfaces"`
}

// InterceptInterfaces returns every ingress interface whose traffic should be
// intercepted: EntwareInterface (when set) followed by any AdditionalInterfaces. An
// empty slice means "all interfaces" (PREROUTING jumps added without an -i
// match), preserving the historical behaviour when entware_interface is unset.
func (n NetworkConfig) InterceptInterfaces() []string {
	var ifaces []string
	if n.EntwareInterface != "" {
		ifaces = append(ifaces, n.EntwareInterface)
	}
	ifaces = append(ifaces, n.AdditionalInterfaces...)
	return ifaces
}

// DNSInterfaces is like InterceptInterfaces but falls back to br0 when nothing
// is configured, since DNS DNAT needs a concrete interface to attach to.
func (n NetworkConfig) DNSInterfaces() []string {
	ifaces := n.InterceptInterfaces()
	if len(ifaces) == 0 {
		return []string{"br0"}
	}
	return ifaces
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

// BlocklistResponse is the reply returned for blocklisted queries.
type BlocklistResponse string

const (
	// BlocklistResponseNXDomain replies with RCODE=NXDOMAIN.
	BlocklistResponseNXDomain BlocklistResponse = "nxdomain"
	// BlocklistResponseNoData replies with RCODE=NOERROR and an empty answer.
	BlocklistResponseNoData BlocklistResponse = "nodata"
	// BlocklistResponseZero replies with 0.0.0.0 / :: sinkhole addresses.
	BlocklistResponseZero BlocklistResponse = "zero"
)

// BlocklistConfig holds DNS-level blocklist settings.
type BlocklistConfig struct {
	Enabled    bool              `yaml:"enabled"`
	Response   BlocklistResponse `yaml:"response"`
	AutoUpdate AutoUpdateConfig  `yaml:"auto_update,omitempty"`
}

// GeositeConfig holds geosite database auto-update settings.
type GeositeConfig struct {
	AutoUpdate AutoUpdateConfig `yaml:"auto_update,omitempty"`
}

// AutoUpdateConfig describes a periodic background refresh policy.
// Schedule is a standard 5-field cron expression (minute hour dom mon dow).
// Empty Schedule means "use the source default".
type AutoUpdateConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Schedule string `yaml:"schedule,omitempty"`
}

// Default cron schedules for periodic refresh jobs. Chosen to fall during
// off-peak hours so the daily/weekly download + parse doesn't compete with
// active client traffic.
const (
	DefaultBlocklistSchedule = "0 3 * * *" // every day at 03:00
	DefaultGeositeSchedule   = "0 4 * * 0" // every Sunday at 04:00
)

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
		Blocklist: BlocklistConfig{
			Enabled:  false,
			Response: BlocklistResponseNXDomain,
			AutoUpdate: AutoUpdateConfig{
				Enabled:  true,
				Schedule: DefaultBlocklistSchedule,
			},
		},
		Geosite: GeositeConfig{
			AutoUpdate: AutoUpdateConfig{
				Enabled:  true,
				Schedule: DefaultGeositeSchedule,
			},
		},
		ExcludedNetworks: []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		},
	}
}
