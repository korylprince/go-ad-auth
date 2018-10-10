package auth

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
//If attrs is non-empty, userAttrs will hold the requested LDAP attributes.
//If groups is non-empty, userGroups will hold which of those groups the user is a member of.
//groups can be a list of groups referenced by DN or cn.
func AuthenticateExtended(config *Config, username, password string, attrs, groups []string) (status bool, userAttrs map[string][]string, userGroups []string, err error) {
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

	//get attributes
	userAttrs, err = conn.GetAttributes("userPrincipalName", upn, attrs)
	if err != nil {
		return false, nil, nil, err
	}

	if len(groups) > 0 {
		//get group DNs
		var parentGroups []string
		for _, group := range groups {
			parentGroup, err := conn.GroupDN(group)
			if err != nil {
				return false, nil, nil, err
			}
			parentGroups = append(parentGroups, parentGroup)
		}

		//check which groups user is part of
		for _, userGroup := range userAttrs["memberOf"] {
			for _, parentGroup := range parentGroups {
				if userGroup == parentGroup {
					userGroups = append(userGroups, parentGroup)
					continue
				}
			}
		}
	}

	//remove memberOf if it wasn't requested
	if !memberOfPresent && len(groups) > 0 {
		delete(userAttrs, "memberOf")
	}

	return status, userAttrs, userGroups, nil
}
