package auth

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
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

//ObjectPrimaryGroup returns the DN of the primary group of the object with the given attribute value
//or an error if one occurred. Not all LDAP objects have a primary group.
func (c *Conn) ObjectPrimaryGroup(attr, value string) (string, error) {
	entry, err := c.GetAttributes(attr, value, []string{"objectSid", "primaryGroupID"})
	if err != nil {
		return "", err
	}

	gidStr := entry.GetAttributeValue("primaryGroupID")
	if gidStr == "" {
		return "", errors.New("Search error: primaryGroupID not found")
	}

	gid, err := strconv.Atoi(entry.GetAttributeValue("primaryGroupID"))
	if err != nil {
		return "", fmt.Errorf(`Parse error: invalid primaryGroupID ("%s"): %w`, gidStr, err)
	}

	uSID := entry.GetRawAttributeValue("objectSid")
	gSID := make([]byte, len(uSID))
	copy(gSID, uSID)
	binary.LittleEndian.PutUint32(gSID[len(gSID)-4:], uint32(gid))

	encoded := ""
	for _, b := range gSID {
		encoded += fmt.Sprintf(`\%02x`, b)
	}

	entry, err = c.SearchOne(fmt.Sprintf("(objectSid=%s)", encoded), nil)
	if err != nil {
		return "", fmt.Errorf("Search error: primary group not found: %w", err)
	}

	return entry.DN, nil
}
