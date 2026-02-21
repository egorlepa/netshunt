package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	"github.com/guras256/keenetic-split-tunnel/internal/service"
)

// daemonBaseURL returns the daemon's HTTP base URL from config, or an error if
// the daemon is not running or config cannot be loaded.
func daemonBaseURL() (string, error) {
	if !service.Daemon.IsRunning(context.Background()) {
		return "", fmt.Errorf("daemon not running")
	}
	cfg, err := config.Load()
	if err != nil {
		return "", fmt.Errorf("load config: %w", err)
	}
	listen := cfg.Daemon.WebListen
	if strings.HasPrefix(listen, ":") {
		listen = "127.0.0.1" + listen
	}
	return "http://" + listen, nil
}

func daemonAddEntry(ctx context.Context, groupName, value string) error {
	base, err := daemonBaseURL()
	if err != nil {
		return err
	}
	u := base + "/groups/" + url.PathEscape(groupName) + "/entries"
	body := strings.NewReader(url.Values{"value": {value}}.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return doRequest(req)
}

func daemonRemoveEntry(ctx context.Context, groupName, value string) error {
	base, err := daemonBaseURL()
	if err != nil {
		return err
	}
	u := base + "/groups/" + url.PathEscape(groupName) + "/entries/" + url.PathEscape(value)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	return doRequest(req)
}

func daemonImportGroups(ctx context.Context, data []byte) error {
	base, err := daemonBaseURL()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/groups/import", bytes.NewReader(data))
	if err != nil {
		return err
	}
	return doRequest(req)
}

func doRequest(req *http.Request) error {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("daemon unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("daemon error %d: %s", resp.StatusCode, bytes.TrimSpace(b))
}
