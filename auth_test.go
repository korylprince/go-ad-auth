package auth

import "testing"

func TestGetDomain(t *testing.T) {
    tests := []string{"dc=example,dc=com", "ou=test,dc=example,dc=com", "dc=example, dc=com"}
    for _, test := range tests {
        if getDomain(test) != "example.com" {
            t.Error("Failed Test:", test, "\n\tOutput:", getDomain(test))
        }
    }
}
