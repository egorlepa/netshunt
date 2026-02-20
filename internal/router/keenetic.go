package router

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const rciBaseURL = "http://localhost:79/rci"

// Client talks to the Keenetic RCI API (localhost:79).
type Client struct {
	http *http.Client
}

// NewClient creates a Keenetic RCI client.
func NewClient() *Client {
	return &Client{
		http: &http.Client{Timeout: 5 * time.Second},
	}
}

// rciGet performs a GET request to the RCI API and returns the parsed JSON.
func (c *Client) rciGet(ctx context.Context, path string) (map[string]any, error) {
	url := rciBaseURL + "/" + strings.TrimPrefix(path, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rci request %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("rci read %s: %w", path, err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("rci parse %s: %w", path, err)
	}
	return result, nil
}

// Interface holds information about a router network interface.
type Interface struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Connected   bool   `json:"connected"`
	Link        string `json:"link"`   // "up" or "down"
	SystemName  string `json:"system-name"`
}

// GetInterfaces returns all router interfaces from RCI.
func (c *Client) GetInterfaces(ctx context.Context) ([]Interface, error) {
	data, err := c.rciGet(ctx, "show/interface")
	if err != nil {
		return nil, err
	}

	var ifaces []Interface
	for id, val := range data {
		m, ok := val.(map[string]any)
		if !ok {
			continue
		}
		iface := Interface{ID: id}
		if v, ok := m["type"].(string); ok {
			iface.Type = v
		}
		if v, ok := m["description"].(string); ok {
			iface.Description = v
		}
		if v, ok := m["connected"].(string); ok {
			iface.Connected = v == "yes"
		}
		if v, ok := m["link"].(string); ok {
			iface.Link = v
		}
		if v, ok := m["system-name"].(string); ok {
			iface.SystemName = v
		}
		ifaces = append(ifaces, iface)
	}
	return ifaces, nil
}

// GetFirmwareVersion returns the router firmware version string.
func (c *Client) GetFirmwareVersion(ctx context.Context) (string, error) {
	data, err := c.rciGet(ctx, "show/version")
	if err != nil {
		return "", err
	}
	if v, ok := data["title"].(string); ok {
		return v, nil
	}
	if v, ok := data["release"].(string); ok {
		return v, nil
	}
	return "", fmt.Errorf("firmware version not found in response")
}

// IsDNSOverrideEnabled checks if opkg DNS override is active.
func (c *Client) IsDNSOverrideEnabled(ctx context.Context) (bool, error) {
	url := rciBaseURL + "/opkg/dns-override"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return false, fmt.Errorf("rci dns-override: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	// The response is a bare boolean: true or false.
	return strings.TrimSpace(string(body)) == "true", nil
}

// EnableDNSOverride enables opkg dns-override so Entware dnsmasq can take over port 53.
func (c *Client) EnableDNSOverride(ctx context.Context) error {
	url := rciBaseURL + "/opkg/dns-override"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("rci enable dns-override: %w", err)
	}
	resp.Body.Close()

	// Save config.
	saveURL := rciBaseURL + "/system/configuration/save"
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, saveURL, nil)
	if err != nil {
		return err
	}
	resp2, err := c.http.Do(req2)
	if err != nil {
		return fmt.Errorf("rci save config: %w", err)
	}
	resp2.Body.Close()
	return nil
}

// IsInternetConnected checks if the router has internet connectivity.
func (c *Client) IsInternetConnected(ctx context.Context) (bool, error) {
	data, err := c.rciGet(ctx, "show/internet/status")
	if err != nil {
		return false, err
	}
	if v, ok := data["internet"].(string); ok {
		return v == "connected", nil
	}
	return false, nil
}
