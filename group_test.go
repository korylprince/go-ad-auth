package auth

import (
	"sort"
	"strings"
	"testing"
)

func dnToCN(dn string) string {
	if splits := strings.Split(dn, ","); len(splits) >= 1 {
		if splits2 := strings.Split(splits[0], "="); len(splits2) >= 2 {
			return splits2[1]
		}
	}

	return ""
}

func TestConnGroupDN(t *testing.T) {
	if testConfig.Server == "" {
		t.Skip("ADTEST_SERVER not set")
		return
	}

	if testConfig.BindUPN == "" || testConfig.BindPass == "" {
		t.Skip("ADTEST_BIND_UPN or ADTEST_BIND_PASS not set")
		return
	}

	if testConfig.BaseDN == "" {
		t.Skip("ADTEST_BASEDN not set")
		return
	}

	config := &Config{Server: testConfig.Server, Port: testConfig.Port, Security: testConfig.BindSecurity, BaseDN: testConfig.BaseDN}
	conn, err := config.Connect()
	if err != nil {
		t.Fatal("Error connecting to server:", err)
	}
	defer conn.Conn.Close()

	status, err := conn.Bind(testConfig.BindUPN, testConfig.BindPass)
	if err != nil {
		t.Fatal("Error binding to server:", err)
	}

	if !status {
		t.Fatal("Error binding to server: invalid credentials")
	}

	attrs, err := conn.GetAttributes("userPrincipalName", testConfig.BindUPN, []string{"memberOf"})
	if err != nil {
		t.Fatal("Error getting user groups:", err)
	}

	dnGroups := attrs["memberOf"]

	if len(dnGroups) == 0 {
		t.Skip("BIND_UPN user not member of any groups")
		return
	}

	groupDN, err := conn.GroupDN(dnGroups[0])
	if err != nil {
		t.Error("Expected err to be nil but got:", err)
	}
	if dnGroups[0] != groupDN {
		t.Errorf("Expected returned group (%s) to be equal to the searched group (%s)", groupDN, dnGroups[0])
	}

	cn := dnToCN(dnGroups[0])
	if cn == "" {
		t.Fatal("Error getting group cn: cn not found")
	}

	groupDN, err = conn.GroupDN(cn)
	if err != nil {
		t.Error("Expected err to be nil but got:", err)
	}

	if dnGroups[0] != groupDN {
		t.Errorf(`Expected DN to be "%s" but got "%s"`, dnGroups[0], groupDN)
	}
}

func TestConnObjectGroups(t *testing.T) {
	if testConfig.Server == "" {
		t.Skip("ADTEST_SERVER not set")
		return
	}

	if testConfig.BindUPN == "" || testConfig.BindPass == "" {
		t.Skip("ADTEST_BIND_UPN or ADTEST_BIND_PASS not set")
		return
	}

	if testConfig.BaseDN == "" {
		t.Skip("ADTEST_BASEDN not set")
		return
	}

	config := &Config{Server: testConfig.Server, Port: testConfig.Port, Security: testConfig.BindSecurity, BaseDN: testConfig.BaseDN}
	conn, err := config.Connect()
	if err != nil {
		t.Fatal("Error connecting to server:", err)
	}
	defer conn.Conn.Close()

	status, err := conn.Bind(testConfig.BindUPN, testConfig.BindPass)
	if err != nil {
		t.Fatal("Error binding to server:", err)
	}

	if !status {
		t.Fatal("Error binding to server: invalid credentials")
	}

	attrs, err := conn.GetAttributes("userPrincipalName", testConfig.BindUPN, []string{"memberOf"})
	if err != nil {
		t.Fatal("Error getting user groups:", err)
	}

	dnGroups := attrs["memberOf"]

	if len(dnGroups) == 0 {
		t.Skip("BIND_UPN user not member of any groups")
		return
	}

	if _, err = conn.ObjectGroups("objectClass", "false", dnGroups); !strings.HasSuffix(err.Error(), "no entries returned") {
		t.Error("No entries: Expected no entries search error but got:", err)
	}

	userGroups, err := conn.ObjectGroups("userPrincipalName", testConfig.BindUPN, dnGroups)
	if err != nil {
		t.Fatal("Expected err to be nil but got:", err)
	}

	sort.Strings(dnGroups)
	sort.Strings(userGroups)

	if len(dnGroups) != len(userGroups) {
		t.Errorf("Expected returned group count (%d) to be equal to searched group count (%d)", len(userGroups), len(dnGroups))
	}

	for i := range dnGroups {
		if dnGroups[i] != userGroups[i] {
			t.Fatalf("Expected returned group (%s) to be equal to searched group (%s):", userGroups[i], dnGroups[i])
		}
	}
}
