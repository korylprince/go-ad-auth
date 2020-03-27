package auth

import (
	"os"
	"strconv"
)

var testConfig struct {
	Server       string
	Port         int
	TLSPort      int
	BindUPN      string
	BindPass     string
	BindSecurity SecurityType
	BaseDN       string
	PasswordUPN  string
}

func init() {
	testConfig.Server = os.Getenv("ADTEST_SERVER")

	if port, err := strconv.Atoi(os.Getenv("ADTEST_PORT")); err == nil {
		testConfig.Port = port
	} else {
		testConfig.Port = 389
	}

	if port, err := strconv.Atoi(os.Getenv("ADTEST_TLS_PORT")); err == nil {
		testConfig.TLSPort = port
	} else {
		testConfig.TLSPort = 636
	}

	testConfig.BindUPN = os.Getenv("ADTEST_BIND_UPN")
	testConfig.BindPass = os.Getenv("ADTEST_BIND_PASS")

	switch os.Getenv("ADTEST_BIND_SECURITY") {
	case "NONE":
		testConfig.BindSecurity = SecurityNone
	case "TLS":
		testConfig.BindSecurity = SecurityTLS
	case "INSECURETLS":
		testConfig.BindSecurity = SecurityInsecureTLS
	case "INSECURESTARTTLS":
		testConfig.BindSecurity = SecurityInsecureStartTLS
	default:
		testConfig.BindSecurity = SecurityStartTLS
	}

	testConfig.BaseDN = os.Getenv("ADTEST_BASEDN")
	testConfig.PasswordUPN = os.Getenv("ADTEST_PASSWORD_UPN")
}
