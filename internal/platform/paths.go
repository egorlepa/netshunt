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
	DnsmasqDir        = OptDir + "/etc/dnsmasq.d"
	DnsmasqIPSetFile  = DnsmasqDir + "/kst.dnsmasq"
	DnsmasqConfFile   = OptDir + "/etc/dnsmasq.conf"
	DnsmasqPidFile    = "/var/run/opt-dnsmasq.pid"
	DnscryptConfFile  = OptDir + "/etc/dnscrypt-proxy.toml"

	// Shadowsocks.
	ShadowsocksConfig = OptDir + "/etc/shadowsocks.json"

	// ipset / iptables constants.
	DefaultIPSetTable = "bypass"
	DefaultMark       = "0xd1000"
	DefaultRouteTable = 1001
	DefaultPriority   = 1778

	// Daemon.
	PidFile       = "/var/run/kst.pid"
	DefaultListen = ":8080"

	// NDM directories.
	NDMDir = OptDir + "/etc/ndm"

	// Binary.
	BinaryPath = BinDir + "/kst"

	// Init scripts.
	InitScript        = OptDir + "/etc/init.d/S96kst"
	SSRedirInitScript = OptDir + "/etc/init.d/S22shadowsocks"
)
