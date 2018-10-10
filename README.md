[![GoDoc](https://godoc.org/gopkg.in/korylprince/go-ad-auth.v2?status.svg)](https://godoc.org/gopkg.in/korylprince/go-ad-auth.v2)

# About

`go-ad-auth` is a simple wrapper around the great [ldap](https://github.com/go-ldap/ldap) library to help with Active Directory authentication.

# Installing

`go get gopkg.in/korylprince/go-ad-auth.v2`

**Dependencies:**

* [github.com/go-ldap/ldap](https://github.com/go-ldap/ldap)
* [golang.org/x/text/encoding/unicode](https://godoc.org/golang.org/x/text/encoding/unicode)

If you have any issues or questions [create an issue](https://github.com/korylprince/go-ad-auth/issues).

# New API

The `v2` API is almost a complete rewrite of the older [`gopkg.in/korylprince/go-ad-auth.v1`](https://godoc.org/gopkg.in/korylprince/go-ad-auth.v1) API. There are similarities, but `v2` is not backwards-compatible. 

The new API is cleaner, more idiomatic, exposes a lot more functionality and is fully testable.

One notable difference to be careful of is that while `v1`'s `Login` will return `false` if the user is not in the specified group, `v2`'s `AuthenticateExtended` will return `true` if the user authenticated successfully, regardless if they were in any of the specified groups or not.

# Usage

`godoc gopkg.in/korylprince/go-ad-auth.v2`

Example:

```go
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
```

See more examples on [GoDoc](https://godoc.org/gopkg.in/korylprince/go-ad-auth.v2).

# Testing

`go test -v`

Most tests will be skipped unless you supply the following environment variables to connect to an Active Directory server:

| Name                    | Description |
| ----------------------- | ------------- |
| ADTEST_SERVER           | Hostname or IP Address of an Active Directory server |
| ADTEST_PORT             | Port to use - defaults to 389 |
| ADTEST_BIND_UPN         | userPrincipalName (user@domain.tld) of admin user |
| ADTEST_BIND_PASS        | Password of admin user |
| ADTEST_BIND_SECURITY    | `NONE` \|\| `TLS` \|\| `STARTTLS` - defaults to `STARTTLS` |
| ADTEST_BASEDN           | LDAP Base DN - for testing the root DN is recommended, e.g. `DC=example,DC=com` |
| ADTEST_PASSWORD_UPN     | userPrincipalName of a test user that will be used to test password changing functions |
