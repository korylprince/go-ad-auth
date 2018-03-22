[go-ad-auth](https://github.com/korylprince/go-ad-auth)

Simple Active Directory Authentication for Go.

The API is considered stable.

[![GoDoc](https://godoc.org/gopkg.in/korylprince/go-ad-auth.v1?status.svg)](https://godoc.org/gopkg.in/korylprince/go-ad-auth.v1)

# Installing

`go get gopkg.in/korylprince/go-ad-auth.v1`

**Dependencies:**

[github.com/go-ldap/ldap](https://github.com/go-ldap/ldap)

If you have any issues or questions, email the email address below, or open an issue at:
https://github.com/korylprince/go-ad-auth/issues

# Usage

`godoc gopkg.in/korylprince/go-ad-auth.v1`

Or read the source. It's pretty simple and readable.

Example:

	config := &auth.Config{
		Server:   "ad.example.com",
		Port:     389,
		BaseDN:   "OU=Users,DC=example,DC=com",
		Security: auth.SecurityNone,
		Debug:    false,
	}
    status, err := auth.Login("kory.prince", "Super$ecret", "Domain Admins", config)
    //status is true if "Super$ecret" is the password for user "kory.prince" and that user is in the "Domain Admins" group.


# Copyright Information

All other code is Copyright 2018 Kory Prince (korylprince at gmail dot com.)

This code is licensed under the same license go is licensed under (with slight modification.) If you'd like another license please email me.
