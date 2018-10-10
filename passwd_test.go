package auth

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func TestConnModifyDNPassword(t *testing.T) {
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

	if err = conn.ModifyDNPassword("CN=Invalid User,"+testConfig.BaseDN, "TestPassword123!"); !strings.Contains(err.Error(), "Password error") {
		t.Error("Invalid DN: Expected password error but got:", err)
	}

	if testConfig.PasswordUPN == "" {
		t.Skip("ADTEST_PASSWORD_UPN not set")
		return
	}

	dn, err := conn.GetDN("userPrincipalName", testConfig.PasswordUPN)
	if err != nil {
		t.Fatal("Error finding test user:", err)
	}

	var long = "A123!aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err = conn.ModifyDNPassword(dn, long); !strings.Contains(err.Error(), "Password error") {
		t.Fatal("Long password: Expected password error but got:", err)
	}

	//set password 1
	if err = conn.ModifyDNPassword(dn, "Random123!"); err != nil {
		t.Fatal("ModifyDNPassword 1: Expected err to be nil but got:", err)
	}

	//authenticate 1
	status, err = Authenticate(config, testConfig.PasswordUPN, "Random123!")
	if err != nil {
		t.Fatal("Authenticate 1: Expected err to be nil but got:", err)
	}

	if !status {
		t.Fatal("Authenticate 1: Expected status to be true")
	}

	//set password 2
	if err = conn.ModifyDNPassword(dn, "Random321!"); err != nil {
		t.Fatal("ModifyDNPassword 2: Expected err to be nil but got:", err)
	}

	//authenticate 2
	status, err = Authenticate(config, testConfig.PasswordUPN, "Random321!")
	if err != nil {
		t.Fatal("Authenticate 2: Expected err to be nil but got:", err)
	}

	if !status {
		t.Fatal("Authenticate 2: Expected status to be true")
	}
}

func TestUpdatePassword(t *testing.T) {
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

	if testConfig.PasswordUPN == "" {
		t.Skip("ADTEST_PASSWORD_UPN not set")
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

	dn, err := conn.GetDN("userPrincipalName", testConfig.PasswordUPN)
	if err != nil {
		t.Fatal("Error finding test user:", err)
	}

	if err = conn.ModifyDNPassword(dn, "Random456!"); err != nil {
		t.Fatal("ModifyDNPassword: Expected err to be nil but got:", err)
	}

	if err = UpdatePassword(config, testConfig.PasswordUPN, "invalid password", "Random654!"); !strings.Contains(err.Error(), "Password error") {
		t.Fatal("Invalid password: Expected password error but got:", err)
	}

	//choose random password to get around AD password history
	rand.Seed(time.Now().Unix())
	randPass := fmt.Sprintf("Random%d!", rand.Int31())

	if err = UpdatePassword(config, testConfig.PasswordUPN, "Random456!", randPass); err != nil {
		t.Fatal("Valid password: Expected err to be nil but got:", err)
	}

	status, err = Authenticate(config, testConfig.PasswordUPN, randPass)
	if err != nil {
		t.Fatal("Authenticate: Expected err to be nil but got:", err)
	}

	if !status {
		t.Fatal("Authenticate: Expected status to be true")
	}
}
