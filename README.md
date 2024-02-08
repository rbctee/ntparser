# Read me

## Usage

```txt
Usage of ./out/ntparser:
  -file string
        File containing raw bytes of the ntSecurityDescriptor to parse
```

## Example

Send the following commands:

```bash
tmpFile=$(mktemp)
echo 0100049c34010000500100000000000014000000040020010700000005003800300100000100000068c9100efb78d21190d400c04f79dc55010500000000000515000000897285c6d42f0d4fddbfae250002000005003800300100000100000068c9100efb78d21190d400c04f79dc55010500000000000515000000897285c6d42f0d4fddbfae250702000005002800000100000100000068c9100efb78d21190d400c04f79dc5501010000000000050b00000000002400ff000f00010500000000000515000000897285c6d42f0d4fddbfae250002000000002400ff000f00010500000000000515000000897285c6d42f0d4fddbfae250702000000002400ff000f00010500000000000515000000897285c6d42f0d4fddbfae25f4010000000014009400020001010000000000050b000000010500000000000515000000897285c6d42f0d4fddbfae25f4010000010500000000000515000000897285c6d42f0d4fddbfae2507020000 | xxd -r -p > $tmpFile

./out/ntparser -file $tmpFile
```

You should receive the following output:

```txt
[+] List of ACEs in the DACL:
[0]:
        Type: AccessAllowedObjectAceType (0x05)
        ACE Size: 56 bytes
        ACE Header Flags: 0x05
                - ObjectInheritAce (0x01)
                - NoPropagateInheritAce (0x04)
        ACE Flags: 1
                - AceObjectTypePresent (0x01)
        Mask: 00000130
                - AdsRightDsReadProp (0x10)
                - AdsRightDsWriteProp (0x20)
                - AdsRightDsControlAccess (0x100)
        Object type GUID: 0e10c968-78fb-11d2-90d4-00c04f79dc55 (Certificate-Enrollment)
        SID: S-1-5-21-3330634377-1326264276-632209373-512
[1]:
        Type: AccessAllowedObjectAceType (0x05)
        ACE Size: 56 bytes
        ACE Header Flags: 0x05
                - NoPropagateInheritAce (0x04)
                - ObjectInheritAce (0x01)
        ACE Flags: 1
                - AceObjectTypePresent (0x01)
        Mask: 00000130
                - AdsRightDsReadProp (0x10)
                - AdsRightDsWriteProp (0x20)
                - AdsRightDsControlAccess (0x100)
        Object type GUID: 0e10c968-78fb-11d2-90d4-00c04f79dc55 (Certificate-Enrollment)
        SID: S-1-5-21-3330634377-1326264276-632209373-512
[2]:
        Type: AccessAllowedObjectAceType (0x05)
        ACE Size: 56 bytes
        ACE Header Flags: 0x05
                - NoPropagateInheritAce (0x04)
                - ObjectInheritAce (0x01)
        ACE Flags: 1
                - AceObjectTypePresent (0x01)
        Mask: 00000130
                - AdsRightDsControlAccess (0x100)
                - AdsRightDsReadProp (0x10)
                - AdsRightDsWriteProp (0x20)
        Object type GUID: 0e10c968-78fb-11d2-90d4-00c04f79dc55 (Certificate-Enrollment)
        SID: S-1-5-21-3330634377-1326264276-632209373-512
[3]:
        Type: AccessAllowedObjectAceType (0x05)
        ACE Size: 56 bytes
        ACE Header Flags: 0x05
                - ObjectInheritAce (0x01)
                - NoPropagateInheritAce (0x04)
        ACE Flags: 1
                - AceObjectTypePresent (0x01)
        Mask: 00000130
                - AdsRightDsWriteProp (0x20)
                - AdsRightDsControlAccess (0x100)
                - AdsRightDsReadProp (0x10)
        Object type GUID: 0e10c968-78fb-11d2-90d4-00c04f79dc55 (Certificate-Enrollment)
        SID: S-1-5-21-3330634377-1326264276-632209373-512
[4]:
        Type: AccessAllowedObjectAceType (0x05)
        ACE Size: 56 bytes
        ACE Header Flags: 0x05
                - NoPropagateInheritAce (0x04)
                - ObjectInheritAce (0x01)
        ACE Flags: 1
                - AceObjectTypePresent (0x01)
        Mask: 00000130
                - AdsRightDsWriteProp (0x20)
                - AdsRightDsControlAccess (0x100)
                - AdsRightDsReadProp (0x10)
        Object type GUID: 0e10c968-78fb-11d2-90d4-00c04f79dc55 (Certificate-Enrollment)
        SID: S-1-5-21-3330634377-1326264276-632209373-512
[5]:
        Type: AccessAllowedObjectAceType (0x05)
        ACE Size: 56 bytes
        ACE Header Flags: 0x05
                - NoPropagateInheritAce (0x04)
                - ObjectInheritAce (0x01)
        ACE Flags: 1
                - AceObjectTypePresent (0x01)
        Mask: 00000130
                - AdsRightDsReadProp (0x10)
                - AdsRightDsWriteProp (0x20)
                - AdsRightDsControlAccess (0x100)
        Object type GUID: 0e10c968-78fb-11d2-90d4-00c04f79dc55 (Certificate-Enrollment)
        SID: S-1-5-21-3330634377-1326264276-632209373-512
[6]:
        Type: AccessAllowedObjectAceType (0x05)
        ACE Size: 56 bytes
        ACE Header Flags: 0x05
                - NoPropagateInheritAce (0x04)
                - ObjectInheritAce (0x01)
        ACE Flags: 1
                - AceObjectTypePresent (0x01)
        Mask: 00000130
                - AdsRightDsWriteProp (0x20)
                - AdsRightDsControlAccess (0x100)
                - AdsRightDsReadProp (0x10)
        Object type GUID: 0e10c968-78fb-11d2-90d4-00c04f79dc55 (Certificate-Enrollment)
        SID: S-1-5-21-3330634377-1326264276-632209373-512
```

## References

Mainly these:

- <https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-DTYP/%5bMS-DTYP%5d.pdf>
- <https://itinsights.org/Process-low-level-NtSecurityDescriptor/#Security-identifier-SID>

## Author

Robert C. Raducioiu (rbct)
