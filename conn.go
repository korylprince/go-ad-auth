package auth

import (
	"crypto/tls"
	"errors"
	"fmt"

	ldap "gopkg.in/ldap.v3"
)

//Conn represents an Active Directory connection.
type Conn struct {
	Conn   *ldap.Conn
	Config *Config
}

//Connect returns an open connection to an Active Directory server or an error if one occurred.
func (c *Config) Connect() (*Conn, error) {
	switch c.Security {
	case SecurityNone:
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port))
		if err != nil {
			return nil, fmt.Errorf("Connection error: %v", err)
		}
		return &Conn{Conn: conn, Config: c}, nil
	case SecurityTLS:
		conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port), &tls.Config{ServerName: c.Server})
		if err != nil {
			return nil, fmt.Errorf("Connection error: %v", err)
		}
		return &Conn{Conn: conn, Config: c}, nil
	case SecurityStartTLS:
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port))
		if err != nil {
			return nil, fmt.Errorf("Connection error: %v", err)
		}
		err = conn.StartTLS(&tls.Config{ServerName: c.Server})
		if err != nil {
			return nil, fmt.Errorf("Connection error: %v", err)
		}
		return &Conn{Conn: conn, Config: c}, nil
	default:
		return nil, errors.New("Configuration error: invalid SecurityType")
	}
}

//Bind authenticates the connection with the given userPrincipalName and password
//and returns the result or an error if one occurred.
func (c *Conn) Bind(upn, password string) (bool, error) {
	if password == "" {
		return false, nil
	}

	err := c.Conn.Bind(upn, password)
	if err != nil {
		if e, ok := err.(*ldap.Error); ok {
			if e.ResultCode == ldap.LDAPResultInvalidCredentials {
				return false, nil
			}
		}
		return false, fmt.Errorf("Bind error (%s): %v", upn, err)
	}

	return true, nil
}
