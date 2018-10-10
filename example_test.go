package auth

import auth "gopkg.in/korylprince/go-ad-auth.v2"

func ExampleAuthenticate() {
	config := &auth.Config{
		Server:   "ldap.example.com",
		Port:     389,
		BaseDN:   "OU=Users,DC=example,DC=com",
		Security: auth.SecurityStartTLS,
	}

	username := "user"
	password := "pass"

	status, err := auth.Authenticate(config, username, password)

	if err != nil {
		//handle err
		return
	}

	if !status {
		//handle failed authentication
		return
	}

}

func ExampleAuthenticateExtended() {
	config := &auth.Config{
		Server:   "ldap.example.com",
		Port:     389,
		BaseDN:   "OU=Users,DC=example,DC=com",
		Security: auth.SecurityStartTLS,
	}

	username := "user"
	password := "pass"

	status, attrs, groups, err := auth.AuthenticateExtended(config, username, password, []string{"cn"}, []string{"Domain Admins"})

	if err != nil {
		//handle err
		return
	}

	if !status {
		//handle failed authentication
		return
	}

	if len(groups) == 0 {
		//handle user not being in any groups
		return
	}

	//get attributes
	cn := attrs["cn"][0]
}

func ExampleUpdatePassword() {
	config := &auth.Config{
		Server:   "ldap.example.com",
		Port:     389,
		BaseDN:   "OU=Users,DC=example,DC=com",
		Security: auth.SecurityStartTLS,
	}

	username := "user"
	password := "pass"
	newPassword := "Super$ecret"

	if err := auth.UpdatePassword(config, username, password, newPassword); err != nil {
		//handle err
	}
}
