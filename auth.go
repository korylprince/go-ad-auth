package auth

import (
	"fmt"
	"github.com/mmitton/ldap"
	"strings"
)

const (
	SEC_NONE = iota
	SEC_SSL
	SEC_TLS
)

type Config struct {
	Server   string
	Port     int
	BaseDN   string
	Security int
	Debug    bool //debug messages are written to stdout
}

func NewConfig(Server string, Port int, BaseDN string, Security int, Debug bool) *Config {
	return &Config{Server, Port, BaseDN, Security, Debug}
}

func (c *Config) Connect() (*ldap.Conn, error) {
	switch c.Security {
	case SEC_NONE:
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port))
		if err != nil {
			if c.Debug {
				fmt.Printf("DEBUG: LDAP Error %d: %s", err.ResultCode, err.Err.Error())
			}
			return nil, err.Err
		}
		return conn, nil
	case SEC_SSL:
		conn, err := ldap.DialSSL("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port))
		if err != nil {
			if c.Debug {
				fmt.Printf("DEBUG: LDAP Error %d: %s", err.ResultCode, err.Err.Error())
			}
			return nil, err.Err
		}
		return conn, nil
	case SEC_TLS:
		conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", c.Server, c.Port))
		if err != nil {
			if c.Debug {
				fmt.Printf("DEBUG: LDAP Error %d: %s", err.ResultCode, err.Err.Error())
			}
			return nil, err.Err
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("Invalid Security setting")
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
		return "", fmt.Errorf("Invalid BaseDN")
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
			fmt.Printf("DEBUG: LDAP Error %d: %s", err.ResultCode, err.Err.Error())
		}
		return "", err.Err
	}
	if len(result.Entries) > 0 {
		return result.Entries[0].DN, nil
	}
	return "", fmt.Errorf("No DN found for: %s", cn)
}

func attrsToMap(entry *ldap.Entry) map[string][]string {
	m := make(map[string][]string)
	for _, attr := range entry.Attributes {
		m[attr.Name] = attr.Values
	}
	return m
}

func inGroup(username, group string, config *Config, conn *ldap.Conn, attrs []string) (bool, map[string][]string, error) {
	groupDN, err := getDN(group, config, conn)
	if err != nil {
		if config.Debug {
			fmt.Printf("DEBUG: Error: %s", err)
		}
		return false, nil, err
	}
	search := ldap.NewSearchRequest(
		config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.DerefAlways,
		1, 0,
		false,
		fmt.Sprintf("(sAMAccountName=%s)", username),
		append(attrs, "memberOf"),
		nil,
	)
	result, lErr := conn.Search(search)
	if lErr != nil {
		if config.Debug {
			fmt.Printf("DEBUG: LDAP Error %d: %s", lErr.ResultCode, lErr.Err.Error())
		}
		return false, nil, lErr.Err
	}
	if len(result.Entries) == 1 {
		entry_attrs := attrsToMap(result.Entries[0])
		if groups, ok := entry_attrs["memberOf"]; ok {
			for _, group := range groups {
				if groupDN == group {
					for _, key := range attrs {
						if key == "memberOf" {
							return true, entry_attrs, nil
						}
					}
					delete(entry_attrs, "memberOf")
					return true, entry_attrs, nil
				}
			}
		}

	}
	return false, nil, fmt.Errorf("Amount of Entries returned was not one")
}

func getAttrs(username string, config *Config, conn *ldap.Conn, attrs []string) (map[string][]string, error) {
	search := ldap.NewSearchRequest(
		config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.DerefAlways,
		1, 0,
		false,
		fmt.Sprintf("(sAMAccountName=%s)", username),
		attrs,
		nil,
	)
	result, lErr := conn.Search(search)
	if lErr != nil {
		if config.Debug {
			fmt.Printf("DEBUG: LDAP Error %d: %s", lErr.ResultCode, lErr.Err.Error())
		}
		return nil, lErr.Err
	}
	if len(result.Entries) == 1 {
		return attrsToMap(result.Entries[0]), nil
	}
	return nil, fmt.Errorf("Amount of Entries returned was not one")
}

/*
Login will check if the given username and password authenticate
correctly with server given by config. If group is not an empty string
then Login will verify that the user is in the Active Directory Group
with the Common Name group. error will be non-nil if some sort of server
error occurred.
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
	lErr := conn.Bind(fmt.Sprintf("%s@%s", username, domain), password)
	if lErr != nil {
		if config.Debug {
			fmt.Printf("DEBUG: LDAP Error %d: %s", lErr.ResultCode, lErr.Err.Error())
		}
		return false, nil, lErr.Err
	}
	if group != "" {
		return inGroup(username, group, config, conn, attrs)
	}
	entry_attrs, err := getAttrs(username, config, conn, attrs)
	if err != nil {
		return false, nil, err
	}
	return true, entry_attrs, nil
}
