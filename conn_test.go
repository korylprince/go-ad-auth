package auth

import (
	"testing"
)

func TestConfigConnect(t *testing.T) {
	if _, err := (&Config{Server: "127.0.0.1", Port: 1, Security: SecurityNone}).Connect(); err == nil {
		t.Error("SecurityNone: Expected connect error but got nil")
	}
	if _, err := (&Config{Server: "127.0.0.1", Port: 1, Security: SecurityTLS}).Connect(); err == nil {
		t.Error("SecurityTLS: Expected connect error but got nil")
	}
	if _, err := (&Config{Server: "127.0.0.1", Port: 1, Security: SecurityStartTLS}).Connect(); err == nil {
		t.Error("SecurityStartTLS: Expected connect error but got nil")
	}

	if _, err := (&Config{Server: "127.0.0.1", Port: 1, Security: SecurityType(100)}).Connect(); err == nil {
		t.Error("Invalid Security: Expected configuration error but got nil")
	}

	if testConfig.Server == "" {
		t.Skip("ADTEST_SERVER not set")
		return
	}

	if _, err := (&Config{Server: testConfig.Server, Port: testConfig.Port, Security: SecurityNone}).Connect(); err != nil {
		t.Error("SecurityNone: Expected connect error to be nil but got:", err)
	}

	if _, err := (&Config{Server: testConfig.Server, Port: testConfig.TLSPort, Security: SecurityTLS}).Connect(); err != nil {
		t.Error("SecurityTLS: Expected connect error to be nil but got:", err)
	}
	if _, err := (&Config{Server: testConfig.Server, Port: testConfig.Port, Security: SecurityStartTLS}).Connect(); err != nil {
		t.Error("SecurityStartTLS: Expected connect error to be nil but got:", err)
	}
}

func TestConnBind(t *testing.T) {
	if testConfig.Server == "" {
		t.Skip("ADTEST_SERVER not set")
		return
	}

	config := &Config{Server: testConfig.Server, Port: testConfig.Port, Security: testConfig.BindSecurity}
	conn, err := config.Connect()
	if err != nil {
		t.Fatal("Error connecting to server:", err)
	}
	defer conn.Conn.Close()

	if status, _ := conn.Bind("test", ""); status {
		t.Error("Empty password: Expected authentication status to be false")
	}

	if status, _ := conn.Bind("go-ad-auth", "invalid_password"); status {
		t.Error("Invalid credentials: Expected authentication status to be false")
	}

	if testConfig.BindUPN == "" || testConfig.BindPass == "" {
		t.Skip("ADTEST_BIND_UPN or ADTEST_BIND_PASS not set")
		return
	}

	if status, _ := conn.Bind(testConfig.BindUPN, testConfig.BindPass); !status {
		t.Error("Valid credentials: Expected authentication status to be true")
	}
}
