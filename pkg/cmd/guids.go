package cmd

import (
	"encoding/binary"
	"fmt"
)

const (
	PublicInformation                        = "Public-Information"
	AbandonReplication                       = "Abandon-Replication"
	UpdatePasswordNotRequiredBit             = "Update-Password-Not-Required-Bit"
	EnablePerUserReversiblyEncryptedPassword = "Enable-Per-User-Reversibly-Encrypted-Password"
	UserLogon                                = "User-Logon"
	UserChangePassword                       = "User-Change-Password"
	MsmqPeekComputerJournal                  = "msmq-Peek-computer-Journal"
	TerminalServerLicenseServer              = "Terminal-Server-License-Server"
	MsTsGatewayaccess                        = "MS-TS-GatewayAccess"
	ChangeRidMaster                          = "Change-Rid-Master"
	WebInformation                           = "Web-Information"
	ReceiveAs                                = "Receive-As"
	MigrateSidHistory                        = "Migrate-SID-History"
	DsQuerySelfQuota                         = "DS-Query-Self-Quota"
	SelfMembership                           = "Self-Membership"
	DsReplicationGetChangesAll               = "DS-Replication-Get-Changes-All"
	DomainPassword                           = "Domain-Password"
	ChangePdc                                = "Change-PDC"
	ChangeSchemaMaster                       = "Change-Schema-Master"
	AddGuid                                  = "Add-GUID"
	DnsHostNameAttributes                    = "DNS-Host-Name-Attributes"
	ReanimateTombstones                      = "Reanimate-Tombstones"
	MsmqOpenConnector                        = "msmq-Open-Connector"
	DomainAdministerServer                   = "Domain-Administer-Server"
	ChangeInfrastructureMaster               = "Change-Infrastructure-Master"
	DsReplicationGetChanges                  = "DS-Replication-Get-Changes"
	CertificateEnrollment                    = "Certificate-Enrollment"
	DsReplicationGetChangesInFilteredSet     = "DS-Replication-Get-Changes-In-Filtered-Set"
	DsCheckStalePhantoms                     = "DS-Check-Stale-Phantoms"
	PrivateInformation                       = "Private-Information"
	DsCloneDomainController                  = "DS-Clone-Domain-Controller"
	ReloadSslCertificate                     = "Reload-SSL-Certificate"
	MsmqReceive                              = "msmq-Receive"
	RunProtectAdminGroupsTask                = "Run-Protect-Admin-Groups-Task"
	UnexpirePassword                         = "Unexpire-Password"
	ReadOnlyReplicationSecretSynchronization = "Read-Only-Replication-Secret-Synchronization"
	DomainOtherParameters                    = "Domain-Other-Parameters"
	MsmqReceiveComputerJournal               = "msmq-Receive-computer-Journal"
	RecalculateSecurityInheritance           = "Recalculate-Security-Inheritance"
	MsmqPeekDeadLetter                       = "msmq-Peek-Dead-Letter"
	DsExecuteIntentionsScript                = "DS-Execute-Intentions-Script"
	DoGarbageCollection                      = "Do-Garbage-Collection"
	DsReplicationManageTopology              = "DS-Replication-Manage-Topology"
	ValidatedSpn                             = "Validated-SPN"
	SendAs                                   = "Send-As"
	SendTo                                   = "Send-To"
	DsInstallReplica                         = "DS-Install-Replica"
	ChangeDomainMaster                       = "Change-Domain-Master"
	ValidatedMsDsBehaviorVersion             = "Validated-MS-DS-Behavior-Version"
	UserAccountRestrictions                  = "User-Account-Restrictions"
	ManageOptionalFeatures                   = "Manage-Optional-Features"
	UserForceChangePassword                  = "User-Force-Change-Password"
	GeneralInformation                       = "General-Information"
	AllowedToAuthenticate                    = "Allowed-To-Authenticate"
	MsmqReceiveJournal                       = "msmq-Receive-journal"
	DsReplicationSynchronize                 = "DS-Replication-Synchronize"
	ValidatedMsDsAdditionalDnsHostName       = "Validated-MS-DS-Additional-DNS-Host-Name"
	PersonalInformation                      = "Personal-Information"
	CreateInboundForestTrust                 = "Create-Inbound-Forest-Trust"
	Membership                               = "Membership"
	AllocateRids                             = "Allocate-Rids"
	OpenAddressBook                          = "Open-Address-Book"
	MsmqReceiveDeadLetter                    = "msmq-Receive-Dead-Letter"
	GenerateRsopLogging                      = "Generate-RSoP-Logging"
	MsmqSend                                 = "msmq-Send"
	MsmqPeek                                 = "msmq-Peek"
	DsReplicationMonitorTopology             = "DS-Replication-Monitor-Topology"
	GenerateRsopPlanning                     = "Generate-RSoP-Planning"
	UpdateSchemaCache                        = "Update-Schema-Cache"
	SamEnumerateEntireDomain                 = "SAM-Enumerate-Entire-Domain"
	ValidatedDnsHostName                     = "Validated-DNS-Host-Name"
	RefreshGroupCache                        = "Refresh-Group-Cache"
	RasInformation                           = "RAS-Information"
	EmailInformation                         = "Email-Information"
	ApplyGroupPolicy                         = "Apply-Group-Policy"
	RecalculateHierarchy                     = "Recalculate-Hierarchy"
)

var AccessRights = map[string]string{
	PublicInformation:                        "e48d0154-bcf8-11d1-8702-00c04fb96050",
	AbandonReplication:                       "ee914b82-0a98-11d1-adbb-00c04fd8d5cd",
	UpdatePasswordNotRequiredBit:             "280f369c-67c7-438e-ae98-1d46f3c6f541",
	EnablePerUserReversiblyEncryptedPassword: "05c74c5e-4deb-43b4-bd9f-86664c2a7fd5",
	UserLogon:                                "5f202010-79a5-11d0-9020-00c04fc2d4cf",
	UserChangePassword:                       "ab721a53-1e2f-11d0-9819-00aa0040529b",
	MsmqPeekComputerJournal:                  "4b6e08c3-df3c-11d1-9c86-006008764d0e",
	TerminalServerLicenseServer:              "5805bc62-bdc9-4428-a5e2-856a0f4c185e",
	MsTsGatewayaccess:                        "ffa6f046-ca4b-4feb-b40d-04dfee722543",
	ChangeRidMaster:                          "d58d5f36-0a98-11d1-adbb-00c04fd8d5cd",
	WebInformation:                           "e45795b3-9455-11d1-aebd-0000f80367c1",
	ReceiveAs:                                "ab721a56-1e2f-11d0-9819-00aa0040529b",
	MigrateSidHistory:                        "ba33815a-4f93-4c76-87f3-57574bff8109",
	DsQuerySelfQuota:                         "4ecc03fe-ffc0-4947-b630-eb672a8a9dbc",
	SelfMembership:                           "bf9679c0-0de6-11d0-a285-00aa003049e2",
	DsReplicationGetChangesAll:               "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
	DomainPassword:                           "c7407360-20bf-11d0-a768-00aa006e0529",
	ChangePdc:                                "bae50096-4752-11d1-9052-00c04fc2d4cf",
	ChangeSchemaMaster:                       "e12b56b6-0a95-11d1-adbb-00c04fd8d5cd",
	AddGuid:                                  "440820ad-65b4-11d1-a3da-0000f875ae0d",
	DnsHostNameAttributes:                    "72e39547-7b18-11d1-adef-00c04fd8d5cd",
	ReanimateTombstones:                      "45ec5156-db7e-47bb-b53f-dbeb2d03c40f",
	MsmqOpenConnector:                        "b4e60130-df3f-11d1-9c86-006008764d0e",
	DomainAdministerServer:                   "ab721a52-1e2f-11d0-9819-00aa0040529b",
	ChangeInfrastructureMaster:               "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd",
	DsReplicationGetChanges:                  "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
	CertificateEnrollment:                    "0e10c968-78fb-11d2-90d4-00c04f79dc55",
	DsReplicationGetChangesInFilteredSet:     "89e95b76-444d-4c62-991a-0facbeda640c",
	DsCheckStalePhantoms:                     "69ae6200-7f46-11d2-b9ad-00c04f79f805",
	PrivateInformation:                       "91e647de-d96f-4b70-9557-d63ff4f3ccd8",
	DsCloneDomainController:                  "3e0f7e18-2c7a-4c10-ba82-4d926db99a3e",
	ReloadSslCertificate:                     "1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8",
	MsmqReceive:                              "06bd3200-df3e-11d1-9c86-006008764d0e",
	RunProtectAdminGroupsTask:                "7726b9d5-a4b4-4288-a6b2-dce952e80a7f",
	UnexpirePassword:                         "ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501",
	ReadOnlyReplicationSecretSynchronization: "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2",
	DomainOtherParameters:                    "b8119fd0-04f6-4762-ab7a-4986c76b3f9a",
	MsmqReceiveComputerJournal:               "4b6e08c2-df3c-11d1-9c86-006008764d0e",
	RecalculateSecurityInheritance:           "62dd28a8-7f46-11d2-b9ad-00c04f79f805",
	MsmqPeekDeadLetter:                       "4b6e08c1-df3c-11d1-9c86-006008764d0e",
	DsExecuteIntentionsScript:                "2f16c4a5-b98e-432c-952a-cb388ba33f2e",
	DoGarbageCollection:                      "fec364e0-0a98-11d1-adbb-00c04fd8d5cd",
	DsReplicationManageTopology:              "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2",
	ValidatedSpn:                             "f3a64788-5306-11d1-a9c5-0000f80367c1",
	SendAs:                                   "ab721a54-1e2f-11d0-9819-00aa0040529b",
	SendTo:                                   "ab721a55-1e2f-11d0-9819-00aa0040529b",
	DsInstallReplica:                         "9923a32a-3607-11d2-b9be-0000f87a36b2",
	ChangeDomainMaster:                       "014bf69c-7b3b-11d1-85f6-08002be74fab",
	ValidatedMsDsBehaviorVersion:             "d31a8757-2447-4545-8081-3bb610cacbf2",
	UserAccountRestrictions:                  "4c164200-20c0-11d0-a768-00aa006e0529",
	ManageOptionalFeatures:                   "7c0e2a7c-a419-48e4-a995-10180aad54dd",
	UserForceChangePassword:                  "00299570-246d-11d0-a768-00aa006e0529",
	GeneralInformation:                       "59ba2f42-79a2-11d0-9020-00c04fc2d3cf",
	AllowedToAuthenticate:                    "68b1d179-0d15-4d4f-ab71-46152e79a7bc",
	MsmqReceiveJournal:                       "06bd3203-df3e-11d1-9c86-006008764d0e",
	DsReplicationSynchronize:                 "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2",
	ValidatedMsDsAdditionalDnsHostName:       "80863791-dbe9-4eb8-837e-7f0ab55d9ac7",
	PersonalInformation:                      "77b5b886-944a-11d1-aebd-0000f80367c1",
	CreateInboundForestTrust:                 "e2a36dc9-ae17-47c3-b58b-be34c55ba633",
	Membership:                               "bc0ac240-79a9-11d0-9020-00c04fc2d4cf",
	AllocateRids:                             "1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd",
	OpenAddressBook:                          "a1990816-4298-11d1-ade2-00c04fd8d5cd",
	MsmqReceiveDeadLetter:                    "4b6e08c0-df3c-11d1-9c86-006008764d0e",
	GenerateRsopLogging:                      "b7b1b3de-ab09-4242-9e30-9980e5d322f7",
	MsmqSend:                                 "06bd3202-df3e-11d1-9c86-006008764d0e",
	MsmqPeek:                                 "06bd3201-df3e-11d1-9c86-006008764d0e",
	DsReplicationMonitorTopology:             "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96",
	GenerateRsopPlanning:                     "b7b1b3dd-ab09-4242-9e30-9980e5d322f7",
	UpdateSchemaCache:                        "be2bb760-7f46-11d2-b9ad-00c04f79f805",
	SamEnumerateEntireDomain:                 "91d67418-0135-4acc-8d79-c08e857cfbec",
	ValidatedDnsHostName:                     "72e39547-7b18-11d1-adef-00c04fd8d5cd",
	RefreshGroupCache:                        "9432c620-033c-4db7-8b58-14ef6d0bf477",
	RasInformation:                           "037088f8-0ae1-11d2-b422-00a0c968f939",
	EmailInformation:                         "e45795b2-9455-11d1-aebd-0000f80367c1",
	ApplyGroupPolicy:                         "edacfd8f-ffb3-11d1-b41d-00a0c968f939",
	RecalculateHierarchy:                     "0bc1554e-0a99-11d1-adbb-00c04fd8d5cd",
}

func GetAccessRightByGuid(guid string) (cn string, found bool) {
	for k, v := range AccessRights {
		if v == guid {
			return k, true
		}
	}

	return "", false
}

type Guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func ParseGuid(guidBytes []byte) (guid Guid, err error) {
	return Guid{
		Data1: binary.LittleEndian.Uint32(guidBytes[:4]),
		Data2: binary.LittleEndian.Uint16(guidBytes[4:6]),
		Data3: binary.LittleEndian.Uint16(guidBytes[6:8]),
		Data4: [8]byte(guidBytes[8:16]),
	}, nil
}

func (guid *Guid) ToString() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", guid.Data1, guid.Data2, guid.Data3, guid.Data4[:2], guid.Data4[2:])
}
