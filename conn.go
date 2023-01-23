package auth

import (
	"crypto/tls"
	"errors"
	"fmt"

	ldap "github.com/go-ldap/ldap/v3"
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
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		return &Conn{Conn: conn, Config: c}, nil
	case SecurityTLS:
		conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port), &tls.Config{ServerName: c.Server, RootCAs: c.RootCAs})
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		return &Conn{Conn: conn, Config: c}, nil
	case SecurityStartTLS:
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port))
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		err = conn.StartTLS(&tls.Config{ServerName: c.Server, RootCAs: c.RootCAs})
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		return &Conn{Conn: conn, Config: c}, nil
	case SecurityInsecureTLS:
		conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port), &tls.Config{ServerName: c.Server, InsecureSkipVerify: true})
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		return &Conn{Conn: conn, Config: c}, nil
	case SecurityInsecureStartTLS:
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port))
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
		}
		err = conn.StartTLS(&tls.Config{ServerName: c.Server, InsecureSkipVerify: true})
		if err != nil {
			return nil, fmt.Errorf("Connection error: %w", err)
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
			return false, e
		}
		return false, fmt.Errorf("Bind error (%s): %w", upn, err)
	}

	return true, nil
}
