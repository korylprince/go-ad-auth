package auth

import (
	"fmt"

	ldap "gopkg.in/ldap.v2"
)

//Search returns the entries for the given search criteria or an error if one occurred.
func (c *Conn) Search(filter string, attrs []string, sizeLimit int) ([]*ldap.Entry, error) {
	search := ldap.NewSearchRequest(
		c.Config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.DerefAlways,
		sizeLimit,
		0,
		false,
		filter,
		attrs,
		nil,
	)
	result, err := c.Conn.Search(search)
	if err != nil {
		return nil, fmt.Errorf(`Search error "%s": %v`, filter, err)
	}

	return result.Entries, nil
}

//SearchOne returns the single entry for the given search criteria or an error if one occurred.
//An error is returned if exactly one entry is not returned.
func (c *Conn) SearchOne(filter string, attrs []string) (*ldap.Entry, error) {
	search := ldap.NewSearchRequest(
		c.Config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.DerefAlways,
		1,
		0,
		false,
		filter,
		attrs,
		nil,
	)

	result, err := c.Conn.Search(search)
	if err != nil {
		if e, ok := err.(*ldap.Error); ok {
			if e.ResultCode == ldap.LDAPResultSizeLimitExceeded {
				return nil, fmt.Errorf(`Search error "%s": more than one entries returned`, filter)
			}
		}

		return nil, fmt.Errorf(`Search error "%s": %v`, filter, err)
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf(`Search error "%s": no entries returned`, filter)
	}

	return result.Entries[0], nil
}

//GetDN returns the DN for the object with the given attribute value or an error if one occurred.
func (c *Conn) GetDN(attr, value string) (string, error) {
	entry, err := c.SearchOne(fmt.Sprintf("(%s=%s)", attr, value), nil)
	if err != nil {
		return "", err
	}

	return entry.DN, nil
}

func attrsToMap(attrs []*ldap.EntryAttribute) map[string][]string {
	m := make(map[string][]string)
	for _, attr := range attrs {
		m[attr.Name] = attr.Values
	}
	return m
}

//GetAttributes returns the given attributes for the object with the given attribute value or an error if one occurred.
func (c *Conn) GetAttributes(attr, value string, attrs []string) (map[string][]string, error) {
	entry, err := c.SearchOne(fmt.Sprintf("(%s=%s)", attr, value), attrs)
	if err != nil {
		return nil, err
	}

	return attrsToMap(entry.Attributes), nil
}