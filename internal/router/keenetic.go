package router

import (
	"bytes"
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

// rciPost sends a POST request to /rci/ with a JSON body for configuration changes.
func (c *Client) rciPost(ctx context.Context, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rciBaseURL+"/", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("rci post: status %d: %s", resp.StatusCode, bytes.TrimSpace(b))
	}
	return nil
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
// Equivalent to: opkg dns-override && system configuration save
func (c *Client) EnableDNSOverride(ctx context.Context) error {
	if err := c.rciPost(ctx, map[string]any{
		"opkg": map[string]any{"dns-override": true},
	}); err != nil {
		return fmt.Errorf("rci enable dns-override: %w", err)
	}
	return c.saveConfig(ctx)
}

// DisableDNSOverride disables opkg dns-override, returning DNS control to Keenetic.
// Equivalent to: no opkg dns-override && system configuration save
func (c *Client) DisableDNSOverride(ctx context.Context) error {
	if err := c.rciPost(ctx, map[string]any{
		"opkg": map[string]any{"dns-override": false},
	}); err != nil {
		return fmt.Errorf("rci disable dns-override: %w", err)
	}
	return c.saveConfig(ctx)
}

func (c *Client) saveConfig(ctx context.Context) error {
	if err := c.rciPost(ctx, map[string]any{
		"system": map[string]any{
			"configuration": map[string]any{"save": true},
		},
	}); err != nil {
		return fmt.Errorf("rci save config: %w", err)
	}
	return nil
}

