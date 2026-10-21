package platform

const (
	// Base directories.
	OptDir    = "/opt"
	ConfigDir = OptDir + "/etc/netshunt"
	BinDir    = OptDir + "/bin"

	// Config files.
	ConfigFile    = ConfigDir + "/config.yaml"
	ShuntsFile    = ConfigDir + "/shunts.yaml"
	GeositeFile   = ConfigDir + "/dlc.dat"
	BlocklistFile = ConfigDir + "/blocklist.yaml"
	BlocklistDir  = ConfigDir + "/blocklist-cache"

	// State (survives daemon restarts and reboots, unlike /tmp and the
	// kernel ipset).
	StateDir    = OptDir + "/var/lib/netshunt"
	TrackerFile = StateDir + "/tracker.json"

	// Daemon.
	PidFile       = "/var/run/netshunt.pid"
	LogFile       = OptDir + "/var/log/netshunt.log"
	DefaultListen = ":8080"

	// NDM directories.
	NDMDir = OptDir + "/etc/ndm"

	// Binary.
	BinaryPath = BinDir + "/netshunt"

	// Init scripts.
	InitScript = OptDir + "/etc/init.d/S96netshunt"
)
