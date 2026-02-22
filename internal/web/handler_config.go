package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/deploy"
	"github.com/egorlepa/netshunt/internal/service"
	"github.com/egorlepa/netshunt/internal/web/templates"
)

func (s *Server) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	templates.SettingsPage(cfg).Render(r.Context(), w)
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	ctx := r.Context()

	cfg, err := config.Load()
	if err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Routing.
	if v := r.FormValue("routing_local_port"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.Routing.LocalPort)
	}

	// DNS.
	if v := r.FormValue("dnscrypt_port"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.DNSCrypt.Port)
	}
	cfg.DNS.CacheEnabled = r.FormValue("dns_cache_enabled") == "on"
	if v := r.FormValue("dns_cache_size"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.DNS.CacheSize)
	}

	// IPSet.
	if v := r.FormValue("ipset_table"); v != "" {
		cfg.IPSet.TableName = v
	}

	// Network.
	cfg.Network.EntwareInterface = r.FormValue("net_interface")

	// Excluded networks.
	if v := r.FormValue("excluded_networks"); v != "" {
		var nets []string
		for _, line := range strings.Split(v, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				nets = append(nets, line)
			}
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

	// Regenerate dnsmasq.conf from updated settings.
	if err := deploy.WriteDnsmasqConf(cfg); err != nil {
		s.Logger.Warn("failed to write dnsmasq.conf", "error", err)
	}

	// Update the server's config reference.
	*s.Config = *cfg

	// Apply changes: restart services and reconcile routing rules.
	for _, svc := range []service.Service{service.Dnsmasq, service.DNSCrypt} {
		if svc.IsInstalled() {
			if err := svc.Restart(ctx); err != nil {
				s.Logger.Warn("failed to restart service", "service", svc.Name, "error", err)
			}
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

func (s *Server) handleActionRestart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	for _, svc := range []service.Service{service.Dnsmasq, service.DNSCrypt} {
		if svc.IsInstalled() {
			if err := svc.Restart(ctx); err != nil {
				s.Logger.Warn("failed to restart service", "service", svc.Name, "error", err)
			}
		}
	}

	toastTrigger(w, "Services restarted", "success")
	w.WriteHeader(http.StatusOK)
}
