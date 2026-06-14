package web

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/platform"
	"github.com/egorlepa/netshunt/internal/service"
	"github.com/egorlepa/netshunt/internal/web/templates"
)

func (s *Server) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(r, w, templates.SettingsPage(cfg))
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx := r.Context()

	cfg, err := config.Load()
	if err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Routing.
	if v := r.FormValue("routing_local_port"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &cfg.Routing.LocalPort)
	}
	cfg.Routing.BackupPort = 0
	if v := r.FormValue("routing_backup_port"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &cfg.Routing.BackupPort)
	}
	if cfg.Routing.BackupPort <= 0 {
		cfg.Routing.UseBackup = false
	}

	// DNS.
	if v := r.FormValue("dnscrypt_port"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &cfg.DNSCrypt.Port)
	}
	if v := r.FormValue("dns_listen_addr"); v != "" {
		cfg.DNS.ListenAddr = v
	}

	// IPSet.
	if v := r.FormValue("ipset_table"); v != "" {
		cfg.IPSet.TableName = v
	}

	// Network.
	cfg.Network.EntwareInterface = r.FormValue("net_interface")
	var addlIfaces []string
	for _, line := range strings.Split(r.FormValue("additional_interfaces"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			addlIfaces = append(addlIfaces, line)
		}
	}
	cfg.Network.AdditionalInterfaces = addlIfaces

	// Excluded networks. Only IPv4 CIDRs accepted.
	if v := r.FormValue("excluded_networks"); v != "" {
		var nets []string
		for _, line := range strings.Split(v, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			_, cidr, err := net.ParseCIDR(line)
			if err != nil {
				errorResponse(w, "Invalid CIDR: "+line, http.StatusBadRequest)
				return
			}
			if cidr.IP.To4() == nil {
				errorResponse(w, "IPv6 networks not supported: "+line, http.StatusBadRequest)
				return
			}
			nets = append(nets, line)
		}
		cfg.ExcludedNetworks = nets
	} else {
		cfg.ExcludedNetworks = nil
	}

	// Daemon.
	if v := r.FormValue("web_listen"); v != "" {
		cfg.Daemon.WebListen = v
	}
	if v := r.FormValue("log_level"); v != "" {
		cfg.Daemon.LogLevel = v
	}

	if err := config.Save(cfg); err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update the server's config reference.
	*s.Config = *cfg

	// Apply changes: restart dnscrypt-proxy and reconcile routing rules.
	if service.DNSCrypt.IsInstalled() {
		if err := service.DNSCrypt.Restart(ctx); err != nil {
			s.Logger.Warn("failed to restart dnscrypt-proxy", "error", err)
		}
	}
	if err := s.Reconciler.Reconcile(ctx); err != nil {
		s.Logger.Error("reconcile after settings update failed", "error", err)
		errorResponse(w, "Settings saved but reconcile failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	toastTrigger(w, "Settings saved & applied", "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleActionReconcile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := s.Reconciler.Reconcile(ctx); err != nil {
		s.Logger.Error("reconcile failed", "error", err)
		errorResponse(w, "Reconcile failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	toastTrigger(w, "Reconcile complete", "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleSwitchProxy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cfg, err := config.Load()
	if err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if cfg.Routing.BackupPort <= 0 {
		errorResponse(w, "Backup port not configured", http.StatusBadRequest)
		return
	}

	oldPort := cfg.Routing.ActivePort()
	cfg.Routing.UseBackup = !cfg.Routing.UseBackup
	if err := config.Save(cfg); err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	*s.Config = *cfg

	if err := s.Reconciler.SwitchProxy(ctx); err != nil {
		s.Logger.Error("switch proxy failed", "error", err)
		errorResponse(w, "Switch failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Drop only TCP conntrack entries whose reply source port is the old proxy
	// port — these are the live connections still flowing through it. Other
	// traffic on the router (DNS, LAN-LAN, non-shunted) untouched.
	// --reply-port-src is only available with -p tcp.
	if err := platform.RunSilent(ctx, "conntrack", "-D", "-p", "tcp", "--reply-port-src", fmt.Sprintf("%d", oldPort)); err != nil {
		s.Logger.Debug("conntrack flush returned non-zero (likely no matches)", "old_port", oldPort, "error", err)
	}

	target := "primary"
	if cfg.Routing.UseBackup {
		target = "backup"
	}
	toastTrigger(w, "Switched to "+target+" proxy ("+fmt.Sprintf("%d", cfg.Routing.ActivePort())+")", "success")
	s.render(r, w, templates.ProxySwitch(cfg.Routing))
}

func (s *Server) handleActionRestart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if service.DNSCrypt.IsInstalled() {
		if err := service.DNSCrypt.Restart(ctx); err != nil {
			s.Logger.Warn("failed to restart dnscrypt-proxy", "error", err)
		}
	}

	toastTrigger(w, "Services restarted", "success")
	w.WriteHeader(http.StatusOK)
}
