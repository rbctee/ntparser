package cmd

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	AccessAllowedAceType               = "AccessAllowedAceType"
	AccessDeniedAceType                = "AccessDeniedAceType"
	SystemAuditAceType                 = "SystemAuditAceType"
	SystemAlarmAceType                 = "SystemAlarmAceType"
	AccessAllowedCompoundAceType       = "AccessAllowedCompoundAceType"
	AccessAllowedObjectAceType         = "AccessAllowedObjectAceType"
	AccessDeniedObjectAceType          = "AccessDeniedObjectAceType"
	SystemAuditObjectAceType           = "SystemAuditObjectAceType"
	SystemAlarmObjectAceType           = "SystemAlarmObjectAceType"
	AccessAllowedCallbackAceType       = "AccessAllowedCallbackAceType"
	AccessDeniedCallbackAceType        = "AccessDeniedCallbackAceType"
	AccessAllowedCallbackObjectAceType = "AccessAllowedCallbackObjectAceType"
	AccessDeniedCallbackObjectAceType  = "AccessDeniedCallbackObjectAceType"
	SystemAuditCallbackAceType         = "SystemAuditCallbackAceType"
	SystemAlarmCallbackAceType         = "SystemAlarmCallbackAceType"
	SystemAuditCallbackObjectAceType   = "SystemAuditCallbackObjectAceType"
	SystemAlarmCallbackObjectAceType   = "SystemAlarmCallbackObjectAceType"
	SystemMandatoryLabelAceType        = "SystemMandatoryLabelAceType"
	SystemResourceAttributeAceType     = "SystemResourceAttributeAceType"
	SystemScopedPolicyIdAceType        = "SystemScopedPolicyIdAceType"
)

var AceType = map[string]uint8{
	AccessAllowedAceType:               0x00,
	AccessDeniedAceType:                0x01,
	SystemAuditAceType:                 0x02,
	SystemAlarmAceType:                 0x03,
	AccessAllowedCompoundAceType:       0x04,
	AccessAllowedObjectAceType:         0x05,
	AccessDeniedObjectAceType:          0x06,
	SystemAuditObjectAceType:           0x07,
	SystemAlarmObjectAceType:           0x08,
	AccessAllowedCallbackAceType:       0x09,
	AccessDeniedCallbackAceType:        0x0a,
	AccessAllowedCallbackObjectAceType: 0x0b,
	AccessDeniedCallbackObjectAceType:  0x0c,
	SystemAuditCallbackAceType:         0x0d,
	SystemAlarmCallbackAceType:         0x0e,
	SystemAuditCallbackObjectAceType:   0x0f,
	SystemAlarmCallbackObjectAceType:   0x10,
	SystemMandatoryLabelAceType:        0x11,
	SystemResourceAttributeAceType:     0x12,
	SystemScopedPolicyIdAceType:        0x13,
}

type AceHeader struct {
	AceType  byte
	AceFlags byte
	AceSize  uint16
}

const (
	ContainerInheritAce     = "ContainerInheritAce"
	FailedAccessAceFlag     = "FailedAccessAceFlag"
	InheritOnlyAce          = "InheritOnlyAce"
	InheritedAce            = "InheritedAce"
	NoPropagateInheritAce   = "NoPropagateInheritAce"
	ObjectInheritAce        = "ObjectInheritAce"
	SuccessfulAccessAceFlag = "SuccessfulAccessAceFlag"
)

var AceHeaderFlags = map[string]uint8{
	ContainerInheritAce:     0x02,
	FailedAccessAceFlag:     0x80,
	InheritOnlyAce:          0x08,
	InheritedAce:            0x10,
	NoPropagateInheritAce:   0x04,
	ObjectInheritAce:        0x01,
	SuccessfulAccessAceFlag: 0x40,
}

func (header *AceHeader) GetAceHeaderEnabledFlags() map[string]uint8 {
	flags := make(map[string]uint8)

	isFlagSet := func(value uint8, flag uint8) bool {
		return value&flag != 0
	}

	for k, v := range AceHeaderFlags {
		if isFlagSet(header.AceFlags, v) {
			flags[k] = v
		}
	}

	return flags
}

type GenericAce interface {
	GetType() uint8
	GetData() interface{}
}

func (ace AccessAllowedObjectAce) GetType() uint8 {
	return AceType[AccessAllowedObjectAceType]
}

func (ace AccessAllowedObjectAce) GetMask() [4]byte {
	return ace.Mask
}

func (ace AccessAllowedObjectAce) GetData() interface{} {
	return ace
}

type AccessAllowedObjectAce struct {
	Header              AceHeader
	Mask                [4]byte
	Flags               [4]byte
	ObjectType          [16]byte
	InheritedObjectType [16]byte
	Sid                 Sid
}

const (
	AdsRightDsControlAccess = 0x100
	AdsRightDsCreateChild   = 0x1
	AdsRightDsDeleteChild   = 0x2
	AdsRightDsReadProp      = 0x10
	AdsRightDsWriteProp     = 0x20
	AdsRightDsSelf          = 0x8
)

var AccessAllowedObjectAceMask = map[string]uint32{
	"AdsRightDsControlAccess": AdsRightDsControlAccess,
	"AdsRightDsCreateChild":   AdsRightDsCreateChild,
	"AdsRightDsDeleteChild":   AdsRightDsDeleteChild,
	"AdsRightDsReadProp":      AdsRightDsReadProp,
	"AdsRightDsWriteProp":     AdsRightDsWriteProp,
	"AdsRightDsSelf":          AdsRightDsSelf,
}

const (
	Null                          = 0x00000000
	AceObjectTypePresent          = 0x00000001
	AceInheritedObjectTypePresent = 0x00000002
)

var AccessAllowedObjectAceFlags = map[string]uint32{
	"Null":                          Null,
	"AceObjectTypePresent":          AceObjectTypePresent,
	"AceInheritedObjectTypePresent": AceInheritedObjectTypePresent,
}

func (ace *AccessAllowedObjectAce) IncludesObjectType() bool {
	return ace.Header.AceFlags&1 == 1
}

func (ace *AccessAllowedObjectAce) IncludesInheritedObjectType() bool {
	return (ace.Header.AceFlags>>1)&1 == 1
}

func (ace *AccessAllowedObjectAce) GetAceMaskValues() map[string]uint32 {
	maskValues := make(map[string]uint32)

	isFlagSet := func(value uint32, flag uint32) bool {
		return value&flag != 0
	}

	for k, v := range AccessAllowedObjectAceMask {
		if isFlagSet(binary.LittleEndian.Uint32(ace.Mask[:]), v) {
			maskValues[k] = v
		}
	}

	return maskValues
}

func (ace *AccessAllowedObjectAce) GetAceFlags() map[string]uint32 {
	flags := make(map[string]uint32)

	isFlagSet := func(value uint32, flag uint32) bool {
		return value&flag != 0
	}

	for k, v := range AccessAllowedObjectAceFlags {
		if isFlagSet(binary.LittleEndian.Uint32(ace.Flags[:]), v) {
			flags[k] = v
		}
	}

	return flags
}

type Acl struct {
	AclRevision byte
	Sbz1        byte
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
	AceList     []GenericAce
}

type NtSecurityDescriptor struct {
	Revision    byte
	Sbz1        byte
	Control     uint16
	OffsetOwner uint32
	OffsetGroup uint32
	OffsetSacl  uint32
	OffsetDacl  uint32
	OwnerSid    Sid
	GroupSid    Sid
	Sacl        Acl
	Dacl        Acl
}

func NewDescriptor(descBytes []byte) (descriptor *NtSecurityDescriptor, err error) {
	if len(descBytes) < 20 {
		return nil, errors.New("incorrect length, can't even map the header values")
	}

	descriptor = &NtSecurityDescriptor{
		Revision:    descBytes[0],
		Sbz1:        descBytes[1],
		Control:     binary.LittleEndian.Uint16(descBytes[2:4]),
		OffsetOwner: binary.LittleEndian.Uint32(descBytes[4:8]),
		OffsetGroup: binary.LittleEndian.Uint32(descBytes[8:12]),
		OffsetSacl:  binary.LittleEndian.Uint32(descBytes[12:16]),
		OffsetDacl:  binary.LittleEndian.Uint32(descBytes[16:20]),
	}

	if len(descBytes) < (int(descriptor.OffsetOwner) + 2) {
		return nil, errors.New("incorrect length, can't map the OwnerSid property")
	}

	if descriptor.OffsetOwner != 0 {
		sid, err := ParseSid(descBytes[descriptor.OffsetOwner:])
		if err != nil {
			return descriptor, fmt.Errorf("failed to parse SID bytes: %s", err)
		} else {
			descriptor.OwnerSid = sid
		}
	}

	if descriptor.OffsetGroup != 0 {
		sid, err := ParseSid(descBytes[descriptor.OffsetGroup:])
		if err != nil {
			return descriptor, fmt.Errorf("failed to parse SID bytes: %s", err)
		} else {
			descriptor.GroupSid = sid
		}
	}

	if IsBitSet(int(descriptor.Control), 4) {
		// TODO: SACL is present, parse it
		fmt.Printf("[TODO] SACL is present: parse it\n")
	}

	if IsBitSet(int(descriptor.Control), 2) {
		aclBytes := descBytes[descriptor.OffsetDacl:]

		descriptor.Dacl = Acl{
			AclRevision: aclBytes[0],
			Sbz1:        aclBytes[1],
			AclSize:     binary.LittleEndian.Uint16(aclBytes[2:4]),
			AceCount:    binary.LittleEndian.Uint16(aclBytes[4:6]),
			Sbz2:        binary.LittleEndian.Uint16(aclBytes[6:8]),
		}

		if len(aclBytes) < int(descriptor.Dacl.AclSize) {
			return descriptor, errors.New("insufficient bytes to parse DACL")
		}

		aceList := make([]GenericAce, descriptor.Dacl.AceCount)
		aceListBytes := aclBytes[8:]

		offset := 0
		for i := 0; i < int(descriptor.Dacl.AceCount); i++ {
			aceSize := binary.LittleEndian.Uint16(aceListBytes[offset+2 : offset+4])
			aceType := uint8(aceListBytes[offset+0])

			if aceType != AceType[AccessAllowedObjectAceType] {
				return descriptor, fmt.Errorf("ACE type %d not yet supported", aceType)
			}

			if len(aceListBytes[offset:]) < int(aceSize) {
				return descriptor, errors.New("insufficient number of bytes to parse ACE")
			}

			var newAce GenericAce
			switch aceType {
			case AceType[AccessAllowedObjectAceType]:
				aceFlags := binary.LittleEndian.Uint32(aceListBytes[8:12])

				// AceObjectTypePresent
				offset := 12
				var aceObjectType [16]byte
				if aceFlags&1 == 1 {
					aceObjectType = [16]byte(aceListBytes[offset : offset+16])
					offset += 16
				}

				// AceInheritedObjectTypePresent
				var aceInheritedObjectType [16]byte
				if (aceFlags>>1)&1 == 1 {
					aceInheritedObjectType = [16]byte(aceListBytes[offset : offset+16])
					offset += 16
				}

				aceSid, err := ParseSid(aceListBytes[offset:])
				if err != nil {
					return descriptor, fmt.Errorf("failed to parse SID in Access Control Entry: %s", err)
				}

				newAce = AccessAllowedObjectAce{
					Header: AceHeader{
						AceType:  aceListBytes[offset+0],
						AceFlags: aceListBytes[offset+1],
						AceSize:  aceSize,
					},
					Mask:                [4]byte(aceListBytes[4:8]),
					Flags:               [4]byte(aceListBytes[8:12]),
					ObjectType:          aceObjectType,
					InheritedObjectType: aceInheritedObjectType,
					Sid:                 aceSid,
				}
			}
			aceList[i] = newAce
		}

		descriptor.Dacl.AceList = aceList
	}

	return descriptor, nil
}
