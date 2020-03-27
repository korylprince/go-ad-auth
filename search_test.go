package auth

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func init() {
	testConfig.BaseDN = os.Getenv("ADTEST_BASEDN")
}

func TestConnSearch(t *testing.T) {
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

	if _, err := conn.Search("invalid filter", []string{""}, 100); !strings.Contains(err.Error(), "Filter Compile Error") {
		t.Error("Invalid filter: Expected invalid filter search error but got:", err)
	}

	if _, err := conn.Search(fmt.Sprintf("(userPrincipalName=%s)", testConfig.BindUPN), []string{""}, 0); err != nil {
		t.Error("Valid search: Expected err to be nil but got:", err)
	}
}

func TestConnSearchOne(t *testing.T) {
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

	if _, err = conn.SearchOne("invalid filter", []string{""}); !strings.Contains(err.Error(), "Filter Compile Error") {
		t.Error("SearchOne: invalid filter: Expected invalid filter search error but got:", err)
	}

	if _, err = conn.SearchOne("(objectClass=false)", []string{""}); !strings.HasSuffix(err.Error(), "no entries returned") {
		t.Error("SearchOne: no entries: Expected no entries search error but got:", err)
	}

	if _, err = conn.SearchOne("(objectClass=person)", []string{""}); !strings.HasSuffix(err.Error(), "more than one entries returned") {
		t.Error("SearchOne: multiple entries: Expected multiple entries search error but got:", err)
	}

	if _, err = conn.SearchOne(fmt.Sprintf("(userPrincipalName=%s)", testConfig.BindUPN), []string{""}); err != nil {
		t.Error("SearchOne: valid search: Expected err to be nil but got:", err)
	}

	if _, err = conn.GetDN("objectClass", "false"); !strings.HasSuffix(err.Error(), "no entries returned") {
		t.Error("GetDN: no entries: Expected no entries search error but got:", err)
	}

	if _, err = conn.GetDN("objectClass", "person"); !strings.HasSuffix(err.Error(), "more than one entries returned") {
		t.Error("GetDN: multiple entries: Expected multiple entries search error but got:", err)
	}

	if _, err = conn.GetAttributes("objectClass", "false", []string{""}); !strings.HasSuffix(err.Error(), "no entries returned") {
		t.Error("GetAttributes: no entries: Expected no entries search error but got:", err)
	}

	if _, err = conn.GetAttributes("objectClass", "person", []string{""}); !strings.HasSuffix(err.Error(), "more than one entries returned") {
		t.Error("GetAttributes: multiple entries: Expected multiple entries search error but got:", err)
	}

	entry, err := conn.GetAttributes("userPrincipalName", testConfig.BindUPN, []string{"cn"})
	if err != nil {
		t.Fatal("GetAttributes: expected err to be nil but got:", err)
	}

	if _, err = conn.GetDN("cn", entry.GetAttributeValue("cn")); err != nil {
		t.Fatal("GetDN: expected err to be nil but got:", err)
	}
}
