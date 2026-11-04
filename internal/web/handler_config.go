package web

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/egorlepa/netshunt/internal/config"
	"github.com/egorlepa/netshunt/internal/dns"
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

	if err := settingsFromForm(cfg, r); err != nil {
		errorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := config.Save(cfg); err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update the server's config reference.
	s.Config.Store(cfg)

	// Apply changes: swap the forwarder's upstreams, reconcile routing rules.
	if err := s.applyDNSUpstreams(cfg); err != nil {
		s.Logger.Error("apply dns upstreams failed", "error", err)
		errorResponse(w, "Settings saved but DNS upstreams not applied: "+err.Error(), http.StatusInternalServerError)
		return
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

// handleExportConfig downloads config.yaml as it is on disk (the live
// config, marshalled, when the file cannot be read).
func (s *Server) handleExportConfig(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(s.configFile)
	if err != nil {
		data, err = yaml.Marshal(s.Config.Load())
		if err != nil {
			errorResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", "attachment; filename=netshunt-config.yaml")
	_, _ = w.Write(data)
}

// applyDNSUpstreams hands cfg's upstream list to the running forwarder,
// which swaps it in without a restart.
func (s *Server) applyDNSUpstreams(cfg *config.Config) error {
	if s.Forwarder == nil {
		return nil
	}
	return s.Forwarder.SetUpstreams(dns.ConfigUpstreams(cfg.DNS))
}

// settingsFromForm applies the settings form in r (already parsed) to cfg.
// The returned error is user-facing and nothing has been saved yet.
func settingsFromForm(cfg *config.Config, r *http.Request) error {
	// Routing.
	if v := r.FormValue("routing_local_port"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &cfg.Routing.LocalPort)
	}
	// backup_port is no longer edited here; a value in config.yaml is kept.

	// DNS.
	if v := r.FormValue("dns_listen_addr"); v != "" {
		cfg.DNS.ListenAddr = v
	}
	upstreams, err := config.ParseDNSUpstreams(r.FormValue("dns_upstreams"))
	if err != nil {
		return fmt.Errorf("invalid DNS upstreams: %w", err)
	}
	cfg.DNS.Upstreams = upstreams

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
				return fmt.Errorf("invalid CIDR: %s", line)
			}
			if cidr.IP.To4() == nil {
				return fmt.Errorf("IPv6 networks not supported: %s", line)
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
	// The form sends a hidden syslog=0 before the checkbox, so an unchecked
	// box is told apart from a request without the field (kept as is).
	if vs := r.Form["syslog"]; len(vs) > 0 {
		cfg.Daemon.Syslog = vs[len(vs)-1] == "1"
	}
	return nil
}
