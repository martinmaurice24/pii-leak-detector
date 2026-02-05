package piileakdetector

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIPv4Detector_Match(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		threatLevel ThreatLevel
		category    DetectionCategory
		want        []Detection
	}{
		{
			name:        "empty string",
			line:        "",
			threatLevel: CriticalLevel,
			category:    IpDetection,
			want:        []Detection{},
		},
		{
			name:        "no IP address",
			line:        "This is just a regular text without any IP",
			threatLevel: CriticalLevel,
			category:    IpDetection,
			want:        []Detection{},
		},
		{
			name:        "single valid IP address",
			line:        "Server IP: 192.168.1.1",
			threatLevel: CriticalLevel,
			category:    IpDetection,
			want: []Detection{
				{
					DetectionCategory: IpDetection,
					Leak:              "192.168.1.1",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:        "multiple IP addresses",
			line:        "Connection from 10.0.0.5 to 172.16.0.100",
			threatLevel: CriticalLevel,
			category:    IpDetection,
			want: []Detection{
				{
					DetectionCategory: IpDetection,
					Leak:              "10.0.0.5",
					ThreatLevel:       CriticalLevel,
				},
				{
					DetectionCategory: IpDetection,
					Leak:              "172.16.0.100",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:        "IP in URL",
			line:        "https://8.8.8.8/api/endpoint",
			threatLevel: CriticalLevel,
			category:    IpDetection,
			want: []Detection{
				{
					DetectionCategory: IpDetection,
					Leak:              "8.8.8.8",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:        "localhost IP",
			line:        "Connecting to 127.0.0.1:8080",
			threatLevel: CriticalLevel,
			category:    IpDetection,
			want: []Detection{
				{
					DetectionCategory: IpDetection,
					Leak:              "127.0.0.1",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:        "broadcast address",
			line:        "Broadcast: 255.255.255.255",
			threatLevel: CriticalLevel,
			category:    IpDetection,
			want: []Detection{
				{
					DetectionCategory: IpDetection,
					Leak:              "255.255.255.255",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:        "zero address",
			line:        "Default route: 0.0.0.0",
			threatLevel: CriticalLevel,
			category:    IpDetection,
			want: []Detection{
				{
					DetectionCategory: IpDetection,
					Leak:              "0.0.0.0",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:        "IP-like pattern with out of range values",
			line:        "Invalid: 999.999.999.999",
			threatLevel: CriticalLevel,
			category:    IpDetection,
			want: []Detection{
				{
					DetectionCategory: IpDetection,
					Leak:              "999.999.999.999",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:        "partial IP should not match",
			line:        "Incomplete IP: 192.168.1",
			threatLevel: CriticalLevel,
			category:    IpDetection,
			want:        []Detection{},
		},
		{
			name:        "IP in log format",
			line:        "[2024-01-15] ERROR: Failed to connect to 203.0.113.42 - timeout",
			threatLevel: CriticalLevel,
			category:    IpDetection,
			want: []Detection{
				{
					DetectionCategory: IpDetection,
					Leak:              "203.0.113.42",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:        "multiple IPs in comma-separated list",
			line:        "DNS servers: 1.1.1.1, 8.8.4.4, 9.9.9.9",
			threatLevel: CriticalLevel,
			category:    IpDetection,
			want: []Detection{
				{
					DetectionCategory: IpDetection,
					Leak:              "1.1.1.1",
					ThreatLevel:       CriticalLevel,
				},
				{
					DetectionCategory: IpDetection,
					Leak:              "8.8.4.4",
					ThreatLevel:       CriticalLevel,
				},
				{
					DetectionCategory: IpDetection,
					Leak:              "9.9.9.9",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewIPv4Detector()
			assert.Equalf(t, tt.want, d.Match(tt.line), "Match(%v)", tt.line)
		})
	}
}
