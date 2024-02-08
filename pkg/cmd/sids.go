package cmd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type SidIdentifierAuthority struct {
	Value [6]byte
}

type Sid struct {
	Revision            byte
	SubAuthorityCount   byte
	IdentifierAuthority SidIdentifierAuthority
	SubAuthority        []uint32
}

func (sid *Sid) ToString() string {
	return fmt.Sprintf("S-%d-%d-%d-%d-%d-%d-%d", sid.Revision, sid.IdentifierAuthority.Value[5], sid.SubAuthority[0], sid.SubAuthority[1], sid.SubAuthority[2], sid.SubAuthority[3], sid.SubAuthority[4])
}

func ParseSid(sidBytes []byte) (sid Sid, err error) {

	subAuthorityCount := uint(sidBytes[1])
	sidSize := 8 + (int(subAuthorityCount) * 4)

	if len(sidBytes) < sidSize {
		return sid, errors.New("insufficient number of bytes to parse SID")
	}

	var idAuthBytes [6]byte
	copy(idAuthBytes[:], sidBytes[2:])

	subAuthority := make([]uint32, subAuthorityCount)
	subAuthorityBytes := sidBytes[8 : (4*subAuthorityCount)+8]

	err = binary.Read(bytes.NewReader(subAuthorityBytes), binary.LittleEndian, &subAuthority)
	if err != nil {
		return sid, fmt.Errorf("failed to parse the SubAuthority property of the SID: %s", err)
	}

	sid.Revision = sidBytes[0]
	sid.SubAuthorityCount = sidBytes[1]
	sid.IdentifierAuthority = SidIdentifierAuthority{
		Value: idAuthBytes,
	}
	sid.SubAuthority = subAuthority

	return sid, nil
}
