package config

import (
	"reflect"
	"testing"
)

func TestInterceptInterfaces(t *testing.T) {
	tests := []struct {
		name       string
		entware    string
		additional []string
		want       []string
	}{
		{"primary only", "br0", nil, []string{"br0"}},
		{"primary plus additional", "br0", []string{"awg0"}, []string{"br0", "awg0"}},
		{"primary plus several additional", "br0", []string{"awg0", "wg1"}, []string{"br0", "awg0", "wg1"}},
		{"additional only", "", []string{"awg0"}, []string{"awg0"}},
		{"none means all interfaces", "", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NetworkConfig{EntwareInterface: tt.entware, AdditionalInterfaces: tt.additional}
			if got := n.InterceptInterfaces(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("InterceptInterfaces() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDNSInterfaces(t *testing.T) {
	tests := []struct {
		name       string
		entware    string
		additional []string
		want       []string
	}{
		{"primary only", "br0", nil, []string{"br0"}},
		{"primary plus additional", "br0", []string{"awg0"}, []string{"br0", "awg0"}},
		{"additional only", "", []string{"awg0"}, []string{"awg0"}},
		{"none falls back to br0", "", nil, []string{"br0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NetworkConfig{EntwareInterface: tt.entware, AdditionalInterfaces: tt.additional}
			if got := n.DNSInterfaces(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DNSInterfaces() = %v, want %v", got, tt.want)
			}
		})
	}
}
