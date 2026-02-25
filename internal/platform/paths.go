package platform

const (
	// Base directories.
	OptDir    = "/opt"
	ConfigDir = OptDir + "/etc/netshunt"
	BinDir    = OptDir + "/bin"

	// Config files.
	ConfigFile  = ConfigDir + "/config.yaml"
	ShuntsFile  = ConfigDir + "/shunts.yaml"
	GeositeFile = ConfigDir + "/dlc.dat"

	// dnscrypt-proxy.
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
