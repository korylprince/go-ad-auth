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

	status, entry, _, err := AuthenticateExtended(config, testConfig.BindUPN, testConfig.BindPass, []string{"memberOf"}, nil)
	if err != nil {
		t.Fatal("memberOf attrs: Expected err to be nil but got:", err)
	}
	if !status {
		t.Error("memberOf attrs: Expected authenticate status to be true")
	}

	//use dn for even groups and cn for odd groups
	dnGroups := entry.GetAttributeValues("memberOf")
	var checkGroups []string
	for i, group := range dnGroups {
		if i%2 == 0 {
			checkGroups = append(checkGroups, group)
		} else {
			cn := dnToCN(group)
			if cn != "" {
				checkGroups = append(checkGroups, cn)
			}
		}
	}

	status, entry, userGroups, err := AuthenticateExtended(config, testConfig.BindUPN, testConfig.BindPass, nil, checkGroups)
	if err != nil {
		t.Fatal("memberOf attrs: Expected err to be nil but got:", err)
	}
	if !status {
		t.Error("memberOf attrs: Expected authenticate status to be true")
	}

	sort.Strings(checkGroups)
	sort.Strings(userGroups)

	if len(checkGroups) != len(userGroups) {
		t.Fatalf("Expected returned group count (%d) to be equal to searched group count (%d)", len(userGroups), len(checkGroups))
	}

	for i := range checkGroups {
		if checkGroups[i] != userGroups[i] {
			t.Fatalf("Expected returned group (%s) to be equal to searched group (%s):", userGroups[i], checkGroups[i])
		}
	}

	for _, attr := range entry.Attributes {
		if attr.Name == "memberOf" {
			t.Error("memberOf check: Expected memberOf to not be present")
		}
	}
}
