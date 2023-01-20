package auth

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The only valid SID revision is 1
const (
	SIDRevision    = 1
	SIDRevisionStr = "1"
)

var (
	ErrInvalidSIDHeader = errors.New("invalid sid header")
	ErrInvalidSID       = errors.New("invalid sid")
)

// SID represents the structure of a security identifier, described at https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid
type SID struct {
	Revision            byte
	SubAuthorityLength  byte
	IdentifierAuthority uint64   // 6 bytes, big endian
	SubAuthoritys       []uint32 // little endian
}

// RID returns the relative identifier for sid. If RID returns 0, the caller should verify sid actually has sub authorities before using 0 as an actual RID
func (sid *SID) RID() uint32 {
	if len(sid.SubAuthoritys) > 0 {
		return sid.SubAuthoritys[len(sid.SubAuthoritys)-1]
	}
	return 0
}

// Equal returns true if sid == other
func (sid *SID) Equal(other *SID) bool {
	if sid.Revision != other.Revision ||
		sid.SubAuthorityLength != other.SubAuthorityLength ||
		sid.IdentifierAuthority != other.IdentifierAuthority ||
		len(sid.SubAuthoritys) != len(other.SubAuthoritys) {
		return false
	}
	for idx, sub := range sid.SubAuthoritys {
		if sub != other.SubAuthoritys[idx] {
			return false
		}
	}
	return true
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface
func (sid *SID) UnmarshalBinary(buf []byte) error {
	if l := len(buf); l < 8 || buf[0] != SIDRevision { // check static header
		return ErrInvalidSIDHeader
	} else if l != 8+(4*int(buf[1])) { //
		return ErrInvalidSID
	}

	sid.Revision = buf[0]
	sid.SubAuthorityLength = buf[1]
	sid.IdentifierAuthority = binary.BigEndian.Uint64(append([]byte{0, 0}, buf[2:8]...))
	sid.SubAuthoritys = make([]uint32, int(buf[1]))

	for idx := 0; idx < int(buf[1]); idx++ {
		sid.SubAuthoritys[idx] = binary.LittleEndian.Uint32(buf[8+4*idx : 8+4*idx+4])
	}

	return nil
}

// MarshalBinary implements the encoding.BinaryMarshaler interface
func (sid *SID) MarshalBinary() ([]byte, error) {
	return sid.marshalBinary(), nil
}

func (sid *SID) marshalBinary() []byte {
	buf := make([]byte, 8+4*int(sid.SubAuthorityLength))
	binary.BigEndian.PutUint64(buf, sid.IdentifierAuthority)
	buf[0] = sid.Revision
	buf[1] = sid.SubAuthorityLength
	for idx := 0; idx < int(sid.SubAuthorityLength); idx++ {
		binary.LittleEndian.PutUint32(buf[8+4*idx:8+4*idx+4], sid.SubAuthoritys[idx])
	}

	return buf
}

// String returns the string representation of sid, e.g. "S-1-5-..."
func (sid *SID) String() string {
	subs := make([]string, len(sid.SubAuthoritys))
	for idx, sub := range sid.SubAuthoritys {
		subs[idx] = strconv.FormatUint(uint64(sub), 10)
	}
	header := fmt.Sprintf("S-%d-%d", sid.Revision, sid.IdentifierAuthority)
	return strings.Join([]string{header, strings.Join(subs, "-")}, "-")
}

// ParseSID parses a string representation of an SID, e.g. what *SID.String returns
func ParseSID(s string) (*SID, error) {
	strs := strings.Split(s, "-")
	if len(strs) < 3 || strs[0] != "S" || strs[1] != SIDRevisionStr {
		return nil, ErrInvalidSIDHeader
	}

	sid := &SID{
		Revision: 1,
	}
	var err error
	sid.IdentifierAuthority, err = strconv.ParseUint(strs[2], 10, 48)
	if err != nil {
		return nil, fmt.Errorf("invalid identifier authority: %w", err)
	}

	subs := make([]uint32, len(strs)-3)
	for idx, str := range strs[3:] {
		sub, err := strconv.ParseUint(str, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid sub authority (%s): %w", str, err)
		}
		subs[idx] = uint32(sub)
	}

	sid.SubAuthorityLength = byte(len(subs))
	sid.SubAuthoritys = subs

	return sid, nil
}

// FilterString returns an escaped binary representation of sid suitable for use in ldap filters.
// e.g. filter := fmt.Sprintf("(objectSid=%s)", sid.FilterString())
func (sid *SID) FilterString() string {
	buf := sid.marshalBinary()

	var filter strings.Builder
	for _, b := range buf {
		filter.WriteString(fmt.Sprintf(`\%02x`, b))
	}

	return filter.String()
}
