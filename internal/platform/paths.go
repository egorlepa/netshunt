package platform

const (
	// Base directories.
	OptDir    = "/opt"
	ConfigDir = OptDir + "/etc/kst"
	BinDir    = OptDir + "/bin"

	// Config files.
	ConfigFile = ConfigDir + "/config.yaml"
	GroupsFile = ConfigDir + "/groups.yaml"

	// dnsmasq integration.
	DnsmasqDir       = OptDir + "/etc/dnsmasq.d"
	DnsmasqIPSetFile = DnsmasqDir + "/kst.dnsmasq"
	DnsmasqConfFile  = OptDir + "/etc/dnsmasq.conf"
	DnsmasqPidFile   = "/var/run/opt-dnsmasq.pid"
	DnscryptConfFile = OptDir + "/etc/dnscrypt-proxy.toml"

	// Daemon.
	PidFile       = "/var/run/kst.pid"
	DefaultListen = ":8080"

	// NDM directories.
	NDMDir = OptDir + "/etc/ndm"

	// Binary.
	BinaryPath = BinDir + "/kst"

	// Init scripts.
	InitScript = OptDir + "/etc/init.d/S96kst"
)
