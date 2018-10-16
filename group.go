package auth

import (
	"strings"
)

//GroupDN returns the DN of the group with the given cn or an error if one occurred.
func (c *Conn) GroupDN(group string) (string, error) {
	if strings.HasSuffix(group, c.Config.BaseDN) {
		return group, nil
	}

	return c.GetDN("cn", group)
}

//ObjectGroups returns which of the given groups (referenced by DN) the object with the given attribute value is in,
//if any, or an error if one occurred.
func (c *Conn) ObjectGroups(attr, value string, groups []string) ([]string, error) {
	entry, err := c.GetAttributes(attr, value, []string{"memberOf"})
	if err != nil {
		return nil, err
	}
	var objectGroups []string

	for _, objectGroup := range entry.GetAttributeValues("memberOf") {
		for _, parentGroup := range groups {
			if objectGroup == parentGroup {
				objectGroups = append(objectGroups, parentGroup)
				continue
			}
		}
	}

	return objectGroups, nil
}
