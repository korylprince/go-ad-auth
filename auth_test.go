package auth

import "testing"

func TestGetDomain(t *testing.T) {
	tests := []string{"dc=example,dc=com",
		"ou=test,dc=example,dc=com",
		"dc=example, dc=com",
		"DC=example,DC=com",
		"OU=test,dc=example,DC=com"}
	for _, test := range tests {
		if domain, err := getDomain(test); domain != "example.com" {
			if err != nil {
				t.Error("Failed Test:", test, "\n\tError:", err)
			} else {
				t.Error("Failed Test:", test, "\n\tOutput:", domain)
			}
		}
	}
	error_tests := []string{"",
		"com",
		"ou=test",
		"OU=test"}
	for _, test := range error_tests {
		if _, err := getDomain(test); err == nil {
			t.Error("Failed Test:", test, "\n\tError: err not nil")
		}
	}
}
