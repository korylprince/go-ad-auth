package auth

import (
    "fmt"
    "github.com/baris/ldap"
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

func getDomain(BaseDN string) string {
    domain := ""
    for _, v := range strings.Split(BaseDN, ",") {
        if trimmed := strings.TrimSpace(v); strings.HasPrefix(trimmed, "dc=") {
            domain = domain + "." + trimmed[3:]
        }
    }
    return domain[1:]
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

func inGroup(username, group string, config *Config, conn *ldap.Conn) (bool, error) {
    groupDN, err := getDN(group, config, conn)
    if err != nil {
        if config.Debug {
            fmt.Printf("DEBUG: Error: %s", err)
        }
        return false, err
    }
    search := ldap.NewSearchRequest(
        config.BaseDN,
        ldap.ScopeWholeSubtree,
        ldap.DerefAlways,
        1, 0,
        false,
        fmt.Sprintf("(sAMAccountName=%s)", username),
        []string{"memberOf"},
        nil,
    )
    result, lErr := conn.Search(search)
    if lErr != nil {
        if config.Debug {
            fmt.Printf("DEBUG: LDAP Error %d: %s", lErr.ResultCode, lErr.Err.Error())
        }
        return false, lErr.Err
    }
    if len(result.Entries) > 0 {
        if attrs := result.Entries[0].Attributes; len(attrs) > 0 {
            if attrs[0].Name == "memberOf" {
                for _, v := range attrs[0].Values {
                    if groupDN == v {
                        return true, nil
                    }
                }
            }
        }
    }
    return false, nil
}

/*
Login will check if the given username and password authenticate
correctly with server given by config. If group is not an empty string
then Login will verify that the user is in the Active Directory Group
with the Common Name group. error will be non-nil if some sort of server
error occurred.
*/
func Login(username, password, group string, config *Config) (bool, error) {
    if password == "" {
        return false, nil
    }
    conn, err := config.Connect()
    if err != nil {
        return false, err
    }
    domain := getDomain(config.BaseDN)
    lErr := conn.Bind(fmt.Sprintf("%s@%s", username, domain), password)
    if lErr != nil {
        if config.Debug {
            fmt.Printf("DEBUG: LDAP Error %d: %s", lErr.ResultCode, lErr.Err.Error())
        }
        return false, lErr.Err
    }
    if group != "" {
        return inGroup(username, group, config, conn)
    }
    return true, nil
}
