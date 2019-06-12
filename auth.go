package auth

import ldap "gopkg.in/ldap.v3"

//Authenticate checks if the given credentials are valid, or returns an error if one occurred.
//username may be either the sAMAccountName or the userPrincipalName.
func Authenticate(config *Config, username, password string) (bool, error) {
	upn, err := config.UPN(username)
	if err != nil {
		return false, err
	}

	conn, err := config.Connect()
	if err != nil {
		return false, err
	}
	defer conn.Conn.Close()

	return conn.Bind(upn, password)
}

//AuthenticateExtended checks if the given credentials are valid, or returns an error if one occurred.
//username may be either the sAMAccountName or the userPrincipalName.
//entry is the *ldap.Entry that holds the DN and any request attributes of the user.
//If groups is non-empty, userGroups will hold which of those groups the user is a member of.
//groups can be a list of groups referenced by DN or cn and the format provided will be the format returned.
func AuthenticateExtended(config *Config, username, password string, attrs, groups []string) (status bool, entry *ldap.Entry, userGroups []string, err error) {
	upn, err := config.UPN(username)
	if err != nil {
		return false, nil, nil, err
	}

	conn, err := config.Connect()
	if err != nil {
		return false, nil, nil, err
	}
	defer conn.Conn.Close()

	//bind
	status, err = conn.Bind(upn, password)
	if err != nil {
		return false, nil, nil, err
	}
	if !status {
		return false, nil, nil, nil
	}

	//add memberOf attribute if necessary
	memberOfPresent := false
	for _, a := range attrs {
		if a == "memberOf" {
			memberOfPresent = true
			break
		}
	}
	if !memberOfPresent && len(groups) > 0 {
		attrs = append(attrs, "memberOf")
	}

	//get entry
	entry, err = conn.GetAttributes("userPrincipalName", upn, attrs)
	if err != nil {
		return false, nil, nil, err
	}

	if len(groups) > 0 {
		for _, group := range groups {
			groupDN, err := conn.GroupDN(group)
			if err != nil {
				return false, nil, nil, err
			}

			for _, userGroup := range entry.GetAttributeValues("memberOf") {
				if userGroup == groupDN {
					userGroups = append(userGroups, group)
					break
				}
			}
		}
	}

	//remove memberOf if it wasn't requested
	if !memberOfPresent && len(groups) > 0 {
		var entryAttrs []*ldap.EntryAttribute
		for _, e := range entry.Attributes {
			if e.Name != "memberOf" {
				entryAttrs = append(entryAttrs, e)
			}
		}
		entry.Attributes = entryAttrs
	}

	return status, entry, userGroups, nil
}
