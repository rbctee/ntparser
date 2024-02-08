package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"

	"rbct.it/ntparser/pkg/cmd"
)

func main() {
	ntSecFilePath := flag.String("file", "", "File containing raw bytes of the ntSecurityDescriptor to parse")

	flag.Parse()

	if *ntSecFilePath == "" {
		flag.Usage()
		return
	}

	descBytes, err := os.ReadFile(*ntSecFilePath)
	if err != nil {
		fmt.Printf("[!] Failed to open file")
		os.Exit(1)
	}

	// fmt.Printf("ntSecurity Descriptor: %x\n", descBytes)
	descriptor, err := cmd.NewDescriptor(descBytes)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(2)
	}

	fmt.Println("[+] List of ACEs in the DACL:")
	for i, ace := range descriptor.Dacl.AceList {
		aceTypeStr := cmd.MapKey(cmd.AceType, ace.GetType())
		fmt.Printf("[%d]:\n\tType: %s (0x%02x)\n", i, aceTypeStr, ace.GetType())

		specificAce := ace.GetData()
		switch aceType := specificAce.(type) {
		case cmd.AccessAllowedObjectAce:
			fmt.Printf("\tACE Size: %d bytes\n", aceType.Header.AceSize)

			fmt.Printf("\tACE Header Flags: 0x%02x\n", aceType.Header.AceFlags)
			for k, v := range aceType.Header.GetAceHeaderEnabledFlags() {
				fmt.Printf("\t\t- %s (0x%02x)\n", k, v)
			}

			aceFlags := binary.LittleEndian.Uint32(aceType.Flags[:])
			fmt.Printf("\tACE Flags: %x\n", aceFlags)
			for k, v := range aceType.GetAceFlags() {
				fmt.Printf("\t\t- %s (0x%02x)\n", k, v)
			}

			aceMask := binary.LittleEndian.Uint32(aceType.Mask[:])
			fmt.Printf("\tMask: %08x\n", aceMask)
			for k, v := range aceType.GetAceMaskValues() {
				fmt.Printf("\t\t- %s (0x%02x)\n", k, v)
			}

			if aceType.IncludesObjectType() {
				guid, err := cmd.ParseGuid(aceType.ObjectType[:])
				if err != nil {
					fmt.Printf("Failed to parse object type GUID: %s\n", err)
				}
				guidString := guid.ToString()
				guidCn, found := cmd.GetAccessRightByGuid(guidString)
				if found {
					fmt.Printf("\tObject type GUID: %s (%s)\n", guidString, guidCn)
				} else {
					fmt.Printf("\tObject type GUID: %s (unknown)\n", guidString)
				}

			}

			if aceType.IncludesInheritedObjectType() {
				guid, err := cmd.ParseGuid(aceType.InheritedObjectType[:])
				if err != nil {
					fmt.Printf("Failed to parse object type GUID: %s\n", err)
				}

				guidString := guid.ToString()
				guidCn, found := cmd.GetAccessRightByGuid(guidString)
				if found {
					fmt.Printf("\tInherited object type GUID: %s (%s)\n", guidString, guidCn)
				} else {
					fmt.Printf("\tInherited object type GUID: %s (unknown)\n", guidString)
				}
			}

			fmt.Printf("\tSID: %s\n", aceType.Sid.ToString())
		}
	}
}
