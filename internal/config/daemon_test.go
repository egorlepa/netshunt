package config

import "testing"

func TestSyslogDefaultsOnWhenKeyAbsent(t *testing.T) {
	cfg, err := parse([]byte("daemon:\n  web_listen: \":8765\"\n  log_level: warn\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Daemon.Syslog {
		t.Error("syslog off for a config without the key")
	}
	cfg, err = parse([]byte("daemon:\n  syslog: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Daemon.Syslog {
		t.Error("syslog: false ignored")
	}
}
