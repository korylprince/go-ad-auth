package auth

import (
	"bytes"
	"testing"
)

var ErrSIDTests = []string{
	"1-5-21-50",                 // no "S-"
	"S-2-5-21-50",               // revision 2
	"S-1-562949953421312-21-50", // overflow identifier authority
	"S-1-5-8589934592-50",       // overflow sub authority
}

var ErrSIDBinaryTests = [][]byte{
	{2, 0, 0, 0, 0, 0, 0, 5},                         // revision 2
	{1, 1, 5},                                        // malformed header
	{1, 1, 0, 0, 0, 0, 0, 5, 1, 2},                   // malformed length
	{1, 1, 0, 0, 0, 0, 0, 5},                         // mismatch sub authority length (1 != 0)
	{1, 1, 0, 0, 0, 0, 0, 5, 1, 2, 3, 4, 5, 6, 7, 8}, // mismatch sub authority length (1 != 2)
}

func TestSID(t *testing.T) {
	// taken from https://ldapwiki.com/wiki/ObjectSID
	start := "S-1-5-21-2562418665-3218585558-1813906818-1576"
	startbin := []byte{1, 5, 0, 0, 0, 0, 0, 5, 0x15, 0, 0, 0, 0xe9, 0x67, 0xbb, 0x98, 0xd6, 0xb7, 0xd7, 0xbf, 0x82, 5, 0x1e, 0x6c, 0x28, 6, 0, 0}
	startfilter := `\01\05\00\00\00\00\00\05\15\00\00\00\e9\67\bb\98\d6\b7\d7\bf\82\05\1e\6c\28\06\00\00`

	sid, err := ParseSID(start)
	if err != nil {
		t.Fatalf("could not parse sid: %v", err)
	}

	if start != sid.String() {
		t.Error("expected parsed string to be equal")
	}

	if rid := sid.RID(); rid != 1576 {
		t.Errorf("expected rid to be equal: want: 1576, have: %d", rid)
	}

	if sid.FilterString() != startfilter {
		t.Error("expected filter string to be equal")
	}

	buf, err := sid.MarshalBinary()
	if err != nil {
		t.Fatalf("could not marshal sid: %v", err)
	}

	if !bytes.Equal(startbin, buf) {
		t.Error("expected marshaled sid to be equal")
	}

	sid2 := new(SID)
	if err = sid2.UnmarshalBinary(buf); err != nil {
		t.Fatalf("could not unmarshal sid: %v", err)
	}

	if !sid.Equal(sid2) {
		t.Error("expected unmarshaled sid to be equal")
	}

	sid2.IdentifierAuthority = 6
	if sid.Equal(sid2) {
		t.Error("expected sid not to be equal")
	}

	sid2.IdentifierAuthority = 5
	sid2.SubAuthoritys[0] = 0
	if sid.Equal(sid2) {
		t.Error("expected sid not to be equal")
	}

	for _, test := range ErrSIDTests {
		if _, err = ParseSID(test); err == nil {
			t.Errorf("expected test to fail: %s", test)
		}
	}

	for _, test := range ErrSIDBinaryTests {
		if err = sid2.UnmarshalBinary(test); err == nil {
			t.Errorf("expected test to fail: %s", test)
		}
	}
}
