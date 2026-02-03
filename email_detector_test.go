package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEmailDetector_Match(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		lineNumber int
		want       []Detection
	}{
		{
			name:       "An email leak",
			line:       "I found john@test.com email on this line.",
			lineNumber: 12,
			want: []Detection{
				{
					DetectionCategory: EmailDetection,
					Leak:              "john@test.com",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:       "Two emails leak",
			line:       "I found john@test.com and jane@test.com emails on this line.",
			lineNumber: 3,
			want: []Detection{
				{
					DetectionCategory: EmailDetection,
					Leak:              "john@test.com",
					ThreatLevel:       CriticalLevel,
				},
				{
					DetectionCategory: EmailDetection,
					Leak:              "jane@test.com",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:       "No email leak",
			line:       "I found no email on this line.",
			lineNumber: 3,
			want:       []Detection{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			em := NewEmailDetector()
			assert.Equalf(t, tt.want, em.Match(tt.line), "Match(%v, %v)", tt.line, tt.lineNumber)
		})
	}
}
