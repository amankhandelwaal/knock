package core

import (
	"net"
	"testing"
)

func TestIsExpectedPunch(t *testing.T) {
	peer := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 49000}

	tests := []struct {
		name    string
		payload []byte
		from    *net.UDPAddr
		want    bool
	}{
		{
			name:    "expected probe from peer",
			payload: []byte(punchProbe),
			from:    &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 49000},
			want:    true,
		},
		{
			name:    "wrong payload",
			payload: []byte("unrelated"),
			from:    &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 49000},
			want:    false,
		},
		{
			name:    "wrong source port",
			payload: []byte(punchProbe),
			from:    &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 49001},
			want:    false,
		},
		{
			name:    "wrong source IP",
			payload: []byte(punchProbe),
			from:    &net.UDPAddr{IP: net.ParseIP("203.0.113.8"), Port: 49000},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isExpectedPunch(tt.payload, tt.from, peer); got != tt.want {
				t.Fatalf("isExpectedPunch() = %v, want %v", got, tt.want)
			}
		})
	}
}
