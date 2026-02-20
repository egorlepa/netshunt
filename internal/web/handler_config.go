package web

import (
	"fmt"
	"net/http"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	"github.com/guras256/keenetic-split-tunnel/internal/deploy"
	"github.com/guras256/keenetic-split-tunnel/internal/service"
	"github.com/guras256/keenetic-split-tunnel/internal/web/templates"
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

	cfg, err := config.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Shadowsocks.
	if v := r.FormValue("ss_server"); v != "" {
		cfg.Shadowsocks.Server = v
	}
	if v := r.FormValue("ss_server_port"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.Shadowsocks.ServerPort)
	}
	if v := r.FormValue("ss_local_port"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.Shadowsocks.LocalPort)
	}
	if v := r.FormValue("ss_password"); v != "" {
		cfg.Shadowsocks.Password = v
	}
	if v := r.FormValue("ss_method"); v != "" {
		cfg.Shadowsocks.Method = v
	}

	// DNS.
	if v := r.FormValue("dnscrypt_port"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.DNSCrypt.Port)
	}

	// Network.
	cfg.Network.EntwareInterface = r.FormValue("net_interface")

	// Daemon.
	if v := r.FormValue("web_listen"); v != "" {
		cfg.Daemon.WebListen = v
	}
	if v := r.FormValue("log_level"); v != "" {
		cfg.Daemon.LogLevel = v
	}

	if err := config.Save(cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Regenerate shadowsocks.json and dnsmasq.conf from updated config.
	if err := deploy.WriteShadowsocksConfig(cfg); err != nil {
		s.Logger.Warn("failed to write shadowsocks.json", "error", err)
	}
	if err := deploy.WriteDnsmasqConf(cfg); err != nil {
		s.Logger.Warn("failed to write dnsmasq.conf", "error", err)
	}

	// Update the server's config reference.
	*s.Config = *cfg

	w.Header().Set("HX-Trigger", "settings-saved")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleActionUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := s.Reconciler.Reconcile(ctx); err != nil {
		s.Logger.Error("reconcile failed", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleActionRestart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	for _, svc := range []service.Service{service.Dnsmasq, service.DNSCrypt, service.Shadowsocks} {
		if svc.IsInstalled() {
			if err := svc.Restart(ctx); err != nil {
				s.Logger.Warn("failed to restart service", "service", svc.Name, "error", err)
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}
