package platform

const (
	// Base directories.
	OptDir    = "/opt"
	ConfigDir = OptDir + "/etc/netshunt"
	BinDir    = OptDir + "/bin"

	// Config files.
	ConfigFile = ConfigDir + "/config.yaml"
	GroupsFile = ConfigDir + "/groups.yaml"

	// dnsmasq integration.
	DnsmasqDir       = OptDir + "/etc/dnsmasq.d"
	DnsmasqIPSetFile = DnsmasqDir + "/netshunt.dnsmasq"
	DnsmasqConfFile  = OptDir + "/etc/dnsmasq.conf"
	DnsmasqPidFile   = "/var/run/opt-dnsmasq.pid"
	DnscryptConfFile = OptDir + "/etc/dnscrypt-proxy.toml"

	// Daemon.
	PidFile       = "/var/run/netshunt.pid"
	DefaultListen = ":8080"

	// NDM directories.
	NDMDir = OptDir + "/etc/ndm"

	// Binary.
	BinaryPath = BinDir + "/netshunt"

	// Init scripts.
	InitScript = OptDir + "/etc/init.d/S96netshunt"
)
