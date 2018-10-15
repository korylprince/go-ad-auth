package auth

import (
	"sort"
	"strings"
	"testing"
)

func TestAuthenticate(t *testing.T) {
	if testConfig.Server == "" {
		t.Skip("ADTEST_SERVER not set")
		return
	}

	if testConfig.BaseDN == "" {
		t.Skip("ADTEST_BASEDN not set")
		return
	}

	config := &Config{Server: testConfig.Server, Port: testConfig.Port, Security: testConfig.BindSecurity, BaseDN: testConfig.BaseDN}

	status, err := Authenticate(config, "go-ad-auth", "invalid password")
	if err != nil {
		t.Fatal("Invalid credentials: Expected err to be nil but got:", err)
	}
	if status {
		t.Error("Invalid credentials: Expected authenticate status to be false")
	}

	badConfig := &Config{Server: testConfig.Server, Port: testConfig.Port, Security: testConfig.BindSecurity, BaseDN: "Bad BaseDN"}
	if _, err = Authenticate(badConfig, "go-ad-auth", "invalid password"); !strings.Contains(err.Error(), "invalid BaseDN") {
		t.Error("Invalid configuration: Expected invalid BaseDN error but got:", err)
	}

	badConfig = &Config{Server: "127.0.0.1", Port: 1, Security: testConfig.BindSecurity, BaseDN: testConfig.BaseDN}
	if _, err = Authenticate(badConfig, "go-ad-auth", "invalid password"); !strings.Contains(err.Error(), "Connection error") {
		t.Error("Connect error: Expected connection error but got:", err)
	}

	if testConfig.BindUPN == "" || testConfig.BindPass == "" {
		t.Skip("ADTEST_BIND_UPN or ADTEST_BIND_PASS not set")
		return
	}

	status, err = Authenticate(config, testConfig.BindUPN, testConfig.BindPass)
	if err != nil {
		t.Fatal("Valid UPN: Expected err to be nil but got:", err)
	}
	if !status {
		t.Error("Valid UPN: Expected authenticate status to be true")
	}

	var username string

	if splits := strings.Split(testConfig.BindUPN, "@"); len(splits) == 2 {
		username = splits[0]
	} else {
		t.Fatalf("Expected BIND_UPN (%s) to be splittable", testConfig.BindUPN)
	}

	status, err = Authenticate(config, username, testConfig.BindPass)
	if err != nil {
		t.Fatal("Valid username: Expected err to be nil but got:", err)
	}
	if !status {
		t.Error("Valid username: Expected authenticate status to be true")
	}
}

func TestAuthenticateExtended(t *testing.T) {
	if testConfig.Server == "" {
		t.Skip("ADTEST_SERVER not set")
		return
	}

	if testConfig.BaseDN == "" {
		t.Skip("ADTEST_BASEDN not set")
		return
	}

	config := &Config{Server: testConfig.Server, Port: testConfig.Port, Security: testConfig.BindSecurity, BaseDN: testConfig.BaseDN}

	status, _, _, err := AuthenticateExtended(config, "go-ad-auth", "invalid password", nil, nil)
	if err != nil {
		t.Fatal("Invalid credentials: Expected err to be nil but got:", err)
	}
	if status {
		t.Error("Invalid credentials: Expected authenticate status to be false")
	}

	badConfig := &Config{Server: testConfig.Server, Port: testConfig.Port, Security: testConfig.BindSecurity, BaseDN: "Bad BaseDN"}
	if _, _, _, err = AuthenticateExtended(badConfig, "go-ad-auth", "invalid password", nil, nil); !strings.Contains(err.Error(), "invalid BaseDN") {
		t.Error("Invalid configuration: Expected invalid BaseDN error but got:", err)
	}

	badConfig = &Config{Server: "127.0.0.1", Port: 1, Security: testConfig.BindSecurity, BaseDN: testConfig.BaseDN}
	if _, _, _, err = AuthenticateExtended(badConfig, "go-ad-auth", "invalid password", nil, nil); !strings.Contains(err.Error(), "Connection error") {
		t.Error("Connect error: Expected connection error but got:", err)
	}

	if testConfig.BindUPN == "" || testConfig.BindPass == "" {
		t.Skip("ADTEST_BIND_UPN or ADTEST_BIND_PASS not set")
		return
	}

	status, _, _, err = AuthenticateExtended(config, testConfig.BindUPN, testConfig.BindPass, nil, nil)
	if err != nil {
		t.Fatal("Valid UPN: Expected err to be nil but got:", err)
	}
	if !status {
		t.Error("Valid UPN: Expected authenticate status to be true")
	}

	var username string

	if splits := strings.Split(testConfig.BindUPN, "@"); len(splits) == 2 {
		username = splits[0]
	} else {
		t.Fatalf("Expected BIND_UPN (%s) to be splittable", testConfig.BindUPN)
	}

	status, _, _, err = AuthenticateExtended(config, username, testConfig.BindPass, nil, nil)
	if err != nil {
		t.Fatal("Valid username: Expected err to be nil but got:", err)
	}
	if !status {
		t.Error("Valid username: Expected authenticate status to be true")
	}

	status, attrs, _, err := AuthenticateExtended(config, testConfig.BindUPN, testConfig.BindPass, []string{"memberOf"}, nil)
	if err != nil {
		t.Fatal("memberOf attrs: Expected err to be nil but got:", err)
	}
	if !status {
		t.Error("memberOf attrs: Expected authenticate status to be true")
	}

	dnGroups := attrs["memberOf"]
	var cnGroups []string
	for _, group := range dnGroups {
		cn := dnToCN(group)
		if cn != "" {
			cnGroups = append(cnGroups, cn)
		}
	}

	status, _, userDNGroups, err := AuthenticateExtended(config, testConfig.BindUPN, testConfig.BindPass, nil, cnGroups)
	if err != nil {
		t.Fatal("memberOf attrs: Expected err to be nil but got:", err)
	}
	if !status {
		t.Error("memberOf attrs: Expected authenticate status to be true")
	}

	var userCNGroups []string
	for _, group := range userDNGroups {
		cn := dnToCN(group)
		if cn != "" {
			userCNGroups = append(userCNGroups, cn)
		}
	}

	sort.Strings(cnGroups)
	sort.Strings(userCNGroups)

	if len(cnGroups) != len(userCNGroups) {
		t.Fatalf("Expected returned group count (%d) to be equal to searched group count (%d)", len(userCNGroups), len(cnGroups))
	}

	for i := range cnGroups {
		if cnGroups[i] != userCNGroups[i] {
			t.Fatalf("Expected returned group (%s) to be equal to searched group (%s):", userCNGroups[i], cnGroups[i])
		}
	}
}
