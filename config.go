package auth

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

//SecurityType specifies the type of security to use when connecting to an Active Directory Server.
type SecurityType int

//Security will default to SecurityNone if not given.
const (
	SecurityNone SecurityType = iota
	SecurityTLS
	SecurityStartTLS
)

//Config contains settings for connecting to an Active Directory server.
type Config struct {
	Server   string
	Port     int
	BaseDN   string
	Security SecurityType
}

//Domain returns the domain derived from BaseDN or an error if misconfigured.
func (c *Config) Domain() (string, error) {
	domain := ""
	for _, v := range strings.Split(strings.ToLower(c.BaseDN), ",") {
		if trimmed := strings.TrimSpace(v); strings.HasPrefix(trimmed, "dc=") {
			domain = domain + "." + trimmed[3:]
		}
	}
	if len(domain) <= 1 {
		return "", errors.New("Configuration error: invalid BaseDN")
	}
	return domain[1:], nil
}

//UPN returns the userPrincipalName for the given username or an error if misconfigured.
func (c *Config) UPN(username string) (string, error) {
	if _, err := mail.ParseAddress(username); err == nil {
		return username, nil
	}

	domain, err := c.Domain()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s@%s", username, domain), nil
}
