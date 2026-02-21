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

	// Mode.
	if v := r.FormValue("mode"); v == "xray" || v == "shadowsocks" {
		cfg.Mode = v
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

	// Xray.
	if v := r.FormValue("xray_server"); v != "" {
		cfg.Xray.Server = v
	}
	if v := r.FormValue("xray_server_port"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.Xray.ServerPort)
	}
	if v := r.FormValue("xray_local_port"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.Xray.LocalPort)
	}
	if v := r.FormValue("xray_uuid"); v != "" {
		cfg.Xray.UUID = v
	}
	if v := r.FormValue("xray_public_key"); v != "" {
		cfg.Xray.PublicKey = v
	}
	if v := r.FormValue("xray_short_id"); v != "" {
		cfg.Xray.ShortID = v
	}
	if v := r.FormValue("xray_sni"); v != "" {
		cfg.Xray.SNI = v
	}
	if v := r.FormValue("xray_fingerprint"); v != "" {
		cfg.Xray.Fingerprint = v
	}
	if v := r.FormValue("xray_flow"); v != "" {
		cfg.Xray.Flow = v
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

	// Regenerate proxy config file from updated settings.
	switch cfg.Mode {
	case "xray":
		if err := deploy.WriteXrayConfig(cfg); err != nil {
			s.Logger.Warn("failed to write xray config", "error", err)
		}
	default:
		if err := deploy.WriteShadowsocksConfig(cfg); err != nil {
			s.Logger.Warn("failed to write shadowsocks.json", "error", err)
		}
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

	proxySvc := service.Shadowsocks
	if s.Config.Mode == "xray" {
		proxySvc = service.Xray
	}
	for _, svc := range []service.Service{service.Dnsmasq, service.DNSCrypt, proxySvc} {
		if svc.IsInstalled() {
			if err := svc.Restart(ctx); err != nil {
				s.Logger.Warn("failed to restart service", "service", svc.Name, "error", err)
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}
