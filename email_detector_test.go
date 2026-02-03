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
		{
			name:       "Empty string",
			line:       "",
			lineNumber: 1,
			want:       []Detection{},
		},
		{
			name:       "Email with dots in local part",
			line:       "Contact: john.doe@example.com",
			lineNumber: 5,
			want: []Detection{
				{
					DetectionCategory: EmailDetection,
					Leak:              "john.doe@example.com",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:       "Email with plus sign",
			line:       "Send to: user+tag@gmail.com for testing",
			lineNumber: 10,
			want: []Detection{
				{
					DetectionCategory: EmailDetection,
					Leak:              "user+tag@gmail.com",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:       "Email with underscore",
			line:       "Admin email: admin_user@company.org",
			lineNumber: 2,
			want: []Detection{
				{
					DetectionCategory: EmailDetection,
					Leak:              "admin_user@company.org",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:       "Email with numbers",
			line:       "User123: user123@test456.com",
			lineNumber: 7,
			want: []Detection{
				{
					DetectionCategory: EmailDetection,
					Leak:              "user123@test456.com",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:       "Email with subdomain",
			line:       "Mail server: support@mail.example.co.uk",
			lineNumber: 15,
			want: []Detection{
				{
					DetectionCategory: EmailDetection,
					Leak:              "support@mail.example.co.uk",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:       "Email in log format",
			line:       "[2024-01-15 10:30:45] INFO: User alice@domain.net logged in successfully",
			lineNumber: 100,
			want: []Detection{
				{
					DetectionCategory: EmailDetection,
					Leak:              "alice@domain.net",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:       "Email in JSON",
			line:       `{"user": "bob@company.io", "role": "admin"}`,
			lineNumber: 25,
			want: []Detection{
				{
					DetectionCategory: EmailDetection,
					Leak:              "bob@company.io",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:       "Multiple emails comma-separated",
			line:       "Recipients: alice@test.com, bob@example.org, charlie@mail.net",
			lineNumber: 8,
			want: []Detection{
				{
					DetectionCategory: EmailDetection,
					Leak:              "alice@test.com",
					ThreatLevel:       CriticalLevel,
				},
				{
					DetectionCategory: EmailDetection,
					Leak:              "bob@example.org",
					ThreatLevel:       CriticalLevel,
				},
				{
					DetectionCategory: EmailDetection,
					Leak:              "charlie@mail.net",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:       "Email with hyphen in domain",
			line:       "Contact: info@my-company.com",
			lineNumber: 4,
			want: []Detection{
				{
					DetectionCategory: EmailDetection,
					Leak:              "info@my-company.com",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:       "Email with percent sign",
			line:       "Special: user%name@domain.com",
			lineNumber: 6,
			want: []Detection{
				{
					DetectionCategory: EmailDetection,
					Leak:              "user%name@domain.com",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:       "Invalid email missing TLD",
			line:       "Not an email: user@domain",
			lineNumber: 9,
			want:       []Detection{},
		},
		{
			name:       "Invalid email missing at sign",
			line:       "Not an email: userdomain.com",
			lineNumber: 11,
			want:       []Detection{},
		},
		{
			name:       "Email in angle brackets",
			line:       "From: John Doe <john.doe@example.com>",
			lineNumber: 20,
			want: []Detection{
				{
					DetectionCategory: EmailDetection,
					Leak:              "john.doe@example.com",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:       "Multiple emails in different formats",
			line:       "CC: admin@site.com, support+help@service.org, user_123@test.co.uk",
			lineNumber: 30,
			want: []Detection{
				{
					DetectionCategory: EmailDetection,
					Leak:              "admin@site.com",
					ThreatLevel:       CriticalLevel,
				},
				{
					DetectionCategory: EmailDetection,
					Leak:              "support+help@service.org",
					ThreatLevel:       CriticalLevel,
				},
				{
					DetectionCategory: EmailDetection,
					Leak:              "user_123@test.co.uk",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:       "Email in URL parameter",
			line:       "https://example.com/reset?email=user@example.com&token=abc123",
			lineNumber: 45,
			want: []Detection{
				{
					DetectionCategory: EmailDetection,
					Leak:              "user@example.com",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
		{
			name:       "Long TLD email",
			line:       "International: contact@company.international",
			lineNumber: 50,
			want: []Detection{
				{
					DetectionCategory: EmailDetection,
					Leak:              "contact@company.international",
					ThreatLevel:       CriticalLevel,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			em := NewEmailDetector()
			assert.Equalf(t, tt.want, em.Match(tt.line), "Match(%v, %v)", tt.line, tt.lineNumber)
		})
	}
}
