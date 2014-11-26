go-ad-auth
https://github.com/korylprince/go-ad-auth

Simple Active Directory Authentication for Go.

The API is not set in stone, and will probably change in the future. This is more of a proof of concept.

[![GoDoc](https://godoc.org/github.com/korylprince/go-ad-auth?status.svg)](https://godoc.org/github.com/korylprince/go-ad-auth)

#Installing#

`go get github.com/korylprince/go-ad-auth`

**Dependencies:**

[github.com/baris/ldap](https://github.com/baris/ldap)

If you have any issues or questions, email the email address below, or open an issue at:
https://github.com/korylprince/go-ad-auth/issues

#Usage#

`godoc github.com/korylprince/go-ad-auth`

Or read the source. It's pretty simple and readable.

Example:

    config := auth.NewConfig("ad.example.com", 389, "ou=default,dc=example,dc=com", auth.SEC_NONE, false)
    status, err := auth.Login("kory.prince", "Super$ecret", "Domain Admins", config)
    //status is true if "Super$ecret" is the password for user "kory.prince" and that user is in the "Domain Admins" group.


#Copyright Information#

All other code is Copyright 2014 Kory Prince (korylprince at gmail dot com.)

This code is licensed under the same license go is licensed under (with slight modification.) If you'd like another license please email me.
