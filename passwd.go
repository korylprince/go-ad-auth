package auth

import (
	"errors"
	"fmt"

	"golang.org/x/text/encoding/unicode"
	ldap "gopkg.in/ldap.v3"
)

//ModifyDNPassword sets a new password for the given user or returns an error if one occurred.
//ModifyDNPassword is used for resetting user passwords using administrative privileges.
func (c *Conn) ModifyDNPassword(dn, newPasswd string) error {
	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	encoded, err := utf16.NewEncoder().String(fmt.Sprintf(`"%s"`, newPasswd))
	if err != nil {
		return fmt.Errorf("Password error: Unable to encode password: %v", err)
	}

	req := ldap.NewModifyRequest(dn, nil)
	req.Replace("unicodePwd", []string{encoded})

	err = c.Conn.Modify(req)
	if err != nil {
		return fmt.Errorf("Password error: Unable to modify password: %v", err)
	}

	return nil
}

//UpdatePassword checks if the given credentials are valid and updates the password if they are,
//or returns an error if one occurred. UpdatePassword is used for users resetting their own password.
func UpdatePassword(config *Config, username, oldPasswd, newPasswd string) error {
	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	oldEncoded, err := utf16.NewEncoder().String(fmt.Sprintf(`"%s"`, oldPasswd))
	if err != nil {
		return fmt.Errorf("Password error: Unable to encode old password: %v", err)
	}

	newEncoded, err := utf16.NewEncoder().String(fmt.Sprintf(`"%s"`, newPasswd))
	if err != nil {
		return fmt.Errorf("Password error: Unable to encode new password: %v", err)
	}

	upn, err := config.UPN(username)
	if err != nil {
		return err
	}

	conn, err := config.Connect()
	if err != nil {
		return err
	}
	defer conn.Conn.Close()

	//bind
	status, err := conn.Bind(upn, oldPasswd)
	if err != nil {
		return err
	}
	if !status {
		return errors.New("Password error: credentials not valid")
	}

	dn, err := conn.GetDN("userPrincipalName", upn)
	if err != nil {
		return err
	}

	req := ldap.NewModifyRequest(dn, nil)
	req.Delete("unicodePwd", []string{oldEncoded})
	req.Add("unicodePwd", []string{newEncoded})

	err = conn.Conn.Modify(req)
	if err != nil {
		return fmt.Errorf("Password error: Unable to modify password: %v", err)
	}

	return nil
}
