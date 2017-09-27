package auth

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/mail"
	"strings"

	"gopkg.in/ldap.v2"
)

//SecurityType specifies how to connect to an Active Directory server
type SecurityType int

//Security will default to SecurityNone if not given.
const (
	SecurityNone SecurityType = iota
	SecurityTLS
	SecurityStartTLS
)

//ConfigError is an error resulting from a bad Config
type ConfigError string

func (c ConfigError) Error() string {
	return string(c)
}

//LDAPError is a generic LDAP error
type LDAPError string

func (l LDAPError) Error() string {
	return string(l)
}

//Config contains settings for connecting to an Active Directory server
type Config struct {
	Server    string
	Port      int
	BaseDN    string
	Security  SecurityType
	TLSConfig *tls.Config
	Debug     bool //debug messages are written to stdout
}

//Connect returns an open connection to an Active Directory server specified by the given config
func (c *Config) Connect() (*ldap.Conn, error) {
	if c.TLSConfig == nil {
		c.TLSConfig = &tls.Config{
			ServerName: c.Server,
		}
	}

	switch c.Security {
	case SecurityNone:
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port))
		if err != nil {
			if c.Debug {
				log.Printf("DEBUG: LDAP Error %v\n", err)
			}
			return nil, err
		}
		return conn, nil
	case SecurityTLS:
		conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port), c.TLSConfig)
		if err != nil {
			if c.Debug {
				log.Printf("DEBUG: LDAP Error %v\n", err)
			}
			return nil, err
		}
		return conn, nil
	case SecurityStartTLS:
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port))
		if err != nil {
			if c.Debug {
				log.Printf("DEBUG: LDAP Error %v\n", err)
			}
			return nil, err
		}
		err = conn.StartTLS(c.TLSConfig)
		if err != nil {
			if c.Debug {
				log.Printf("DEBUG: LDAP Error %v\n", err)
			}
			return nil, err
		}
		return conn, nil
	default:
		return nil, ConfigError("Invalid Security setting")
	}
}

func getDomain(BaseDN string) (string, error) {
	domain := ""
	for _, v := range strings.Split(strings.ToLower(BaseDN), ",") {
		if trimmed := strings.TrimSpace(v); strings.HasPrefix(trimmed, "dc=") {
			domain = domain + "." + trimmed[3:]
		}
	}
	if len(domain) <= 1 {
		return "", ConfigError("Invalid BaseDN")
	}
	return domain[1:], nil
}

func getDN(cn string, config *Config, conn *ldap.Conn) (string, error) {
	search := ldap.NewSearchRequest(
		config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.DerefAlways,
		1, 0,
		false,
		fmt.Sprintf("(cn=%s)", cn),
		nil,
		nil,
	)
	result, err := conn.Search(search)
	if err != nil {
		if config.Debug {
			log.Printf("DEBUG: LDAP Error %v\n", err)
		}
		return "", err
	}
	if len(result.Entries) > 0 {
		return result.Entries[0].DN, nil
	}
	return "", ConfigError(fmt.Sprintf("No DN found for: %s", cn))
}

func attrsToMap(entry *ldap.Entry) map[string][]string {
	m := make(map[string][]string)
	for _, attr := range entry.Attributes {
		m[attr.Name] = attr.Values
	}
	return m
}

func inGroup(upn, group string, config *Config, conn *ldap.Conn, attrs []string) (bool, map[string][]string, error) {
	groupDN, err := getDN(group, config, conn)
	if err != nil {
		if config.Debug {
			log.Printf("DEBUG: Error: %s\n", err)
		}
		return false, nil, err
	}
	search := ldap.NewSearchRequest(
		config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.DerefAlways,
		1, 0,
		false,
		fmt.Sprintf("(userPrincipalName=%s)", upn),
		append(attrs, "memberOf"),
		nil,
	)
	result, lErr := conn.Search(search)
	if lErr != nil {
		if config.Debug {
			log.Printf("DEBUG: LDAP Error %v\n", lErr)
		}
		return false, nil, lErr
	}
	if len(result.Entries) == 1 {
		entryAttrs := attrsToMap(result.Entries[0])
		if groups, ok := entryAttrs["memberOf"]; ok {
			for _, g := range groups {
				if groupDN == g {
					for _, key := range attrs {
						if key == "memberOf" {
							return true, entryAttrs, nil
						}
					}
					delete(entryAttrs, "memberOf")
					return true, entryAttrs, nil
				}
			}
		}
		return false, entryAttrs, nil
	}
	return false, nil, LDAPError("Amount of Entries returned was not one")
}

func getAttrs(upn string, config *Config, conn *ldap.Conn, attrs []string) (map[string][]string, error) {
	search := ldap.NewSearchRequest(
		config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.DerefAlways,
		1, 0,
		false,
		fmt.Sprintf("(userPrincipalName=%s)", upn),
		attrs,
		nil,
	)
	result, lErr := conn.Search(search)
	if lErr != nil {
		if config.Debug {
			log.Printf("DEBUG: LDAP Error %v\n", lErr)
		}
		return nil, lErr
	}
	if len(result.Entries) == 1 {
		return attrsToMap(result.Entries[0]), nil
	}
	return nil, LDAPError("Amount of Entries returned was not one")
}

/*
Login will check if the given username and password authenticate
correctly with server given by config.
username can be in the sAMAccountName or userPrincipalName format.
If group is not an empty string then Login will verify that the user
is in the Active Directory Group with the Common Name group.
error will be non-nil if some sort of server error occurred.
*/
func Login(username, password, group string, config *Config) (bool, error) {
	ok, _, err := LoginWithAttrs(username, password, group, config, nil)
	return ok, err
}

/*
LoginWithAttrs will function exectly like Login, but will return a given
list of attributes for the user if login is successful.
*/
func LoginWithAttrs(username, password, group string, config *Config, attrs []string) (bool, map[string][]string, error) {
	if password == "" {
		return false, nil, nil
	}
	conn, err := config.Connect()
	if err != nil {
		return false, nil, err
	}
	defer conn.Close()

	domain, err := getDomain(config.BaseDN)
	if err != nil {
		return false, nil, err
	}

	var upn string
	if _, err := mail.ParseAddress(username); err == nil {
		upn = username
	} else {
		upn = fmt.Sprintf("%s@%s", username, domain)
	}

	lErr := conn.Bind(upn, password)
	if lErr != nil {
		if config.Debug {
			log.Printf("DEBUG: LDAP Error %v\n", lErr)
		}
		if e, ok := lErr.(*ldap.Error); ok {
			if e.ResultCode == ldap.LDAPResultInvalidCredentials {
				return false, nil, nil
			}
		}
		return false, nil, lErr
	}
	if group != "" {
		return inGroup(upn, group, config, conn, attrs)
	}
	entryAttrs, err := getAttrs(upn, config, conn, attrs)
	if err != nil {
		return false, nil, err
	}
	return true, entryAttrs, nil
}
