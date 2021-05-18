package auth

import (
	"strings"
)

const LDAPMatchingRuleInChain = "1.2.840.113556.1.4.1941"

//GroupDN returns the DN of the group with the given cn or an error if one occurred.
func (c *Conn) GroupDN(group string) (string, error) {
	if strings.HasSuffix(group, c.Config.BaseDN) {
		return group, nil
	}

	return c.GetDN("cn", group)
}

//ObjectGroups returns which of the given groups (referenced by DN) the object with the given attribute value is in,
//if any, or an error if one occurred.
//Setting attr to "dn" and value to the DN of an object will avoid an extra LDAP search to get the object's DN.
func (c *Conn) ObjectGroups(attr, value string, groups []string) ([]string, error) {
	dn := value
	if attr != "dn" {
		entry, err := c.GetAttributes(attr, value, []string{""})
		if err != nil {
			return nil, err
		}
		dn = entry.DN
	}

	objectGroups, err := c.getGroups(dn)
	if err != nil {
		return nil, err
	}

	var matchedGroups []string

	for _, objectGroup := range objectGroups {
		for _, parentGroup := range groups {
			if objectGroup.DN == parentGroup {
				matchedGroups = append(matchedGroups, parentGroup)
				continue
			}
		}
	}

	return matchedGroups, nil
}
