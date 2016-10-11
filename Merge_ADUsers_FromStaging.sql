BEGIN
	SET NOCOUNT ON;
MERGE INTO dbo.ADUsers AS T
USING 
--(Select Top 10 *  FROM dbo.ADUsersStaging) 
dbo.ADUsersStaging
AS S
ON S.ObjectGUID = T.ObjectGUID
WHEN MATCHED THEN
	UPDATE SET
		T.ExpectedAzureADImmutableID = S.ExpectedAzureADImmutableID,
		T.AccountExpirationDate = S.AccountExpirationDate,
		T.altRecipient = S.altRecipient,
		T.c = S.c,
		T.CanonicalName = S.CanonicalName,
		T.city = S.city,
		T.cn = S.cn,
		T.co = S.co,
		T.country = S.country,
		T.company = S.company,
		T.createTimeStamp = S.createTimeStamp,		
		T.deliverandRedirect = S.deliverandRedirect,
		T.department = S.department,
		T.displayName = S.displayName,
		T.DistinguishedName = S.DistinguishedName,
		T.employeeID = S.employeeID,
		T.employeeNumber = S.employeeNumber,
		T.[enabled] = S.[enabled],
		T.extensionattribute1 = S.extensionattribute1,
		T.extensionattribute10 = S.extensionattribute10,
		T.extensionattribute11 = S.extensionattribute11,
		T.extensionattribute12 = S.extensionattribute12,
		T.extensionattribute13 = S.extensionattribute13,
		T.extensionattribute14 = S.extensionattribute14,
		T.extensionattribute15 = S.extensionattribute15,
		T.extensionattribute2 = S.extensionattribute2,
		T.extensionattribute3 = S.extensionattribute3,
		T.extensionattribute4 = S.extensionattribute4,
		T.extensionattribute5 = S.extensionattribute5,
		T.extensionattribute6 = S.extensionattribute6,
		T.extensionattribute7 = S.extensionattribute7,
		T.extensionattribute8 = S.extensionattribute8,
		T.extensionattribute9 = S.extensionattribute9,
		T.forwardingAddress = S.forwardingAddress,
		T.GivenName = S.GivenName,
		T.homeMDB = S.homeMDB,
		T.homeMTA = S.homeMTA,
		T.LastLogonDate = S.LastLogonDate,
		T.legacyExchangeDN = S.legacyExchangeDN,
		T.Mail = S.Mail,
		T.mailNickname = S.mailNickname,
		T.memberof = S.memberof,
		T.modifyTimeStamp = S.modifyTimeStamp,
		T.[mS-DS-ConsistencyGuid] = S.[mS-DS-ConsistencyGuid],
		T.msExchArchiveGUID = S.msExchArchiveGUID,
		T.msExchArchiveName = S.msExchArchiveName,
		T.msexchextensioncustomattribute1 = S.msexchextensioncustomattribute1,
		T.msexchextensioncustomattribute2 = S.msexchextensioncustomattribute2,
		T.msexchextensioncustomattribute3 = S.msexchextensioncustomattribute3,
		T.msexchextensioncustomattribute4 = S.msexchextensioncustomattribute4,
		T.msexchextensioncustomattribute5 = S.msexchextensioncustomattribute5,
		T.msExchGenericForwardingAddress = S.msExchGenericForwardingAddress,
		T.msExchHideFromAddressLists = S.msExchHideFromAddressLists,
		T.msExchHomeServerName = S.msExchHomeServerName,
		T.msExchMailboxGUID = S.msExchMailboxGUID,
		T.msExchMasterAccountSID = S.msExchMasterAccountSID,
		T.msExchPoliciesExcluded = S.msExchPoliciesExcluded,
		T.msExchRecipientDisplayType = S.msExchRecipientDisplayType,
		T.msExchRecipientTypeDetails = S.msExchRecipientTypeDetails,
		T.msExchRemoteRecipientType = S.msExchRemoteRecipientType,
		T.msExchUsageLocation = S.msExchUsageLocation,
		T.msExchUserCulture = S.msExchUserCulture,
		T.msExchVersion = S.msExchVersion,
		T.msExchWhenMailboxCreated = S.msExchWhenMailboxCreated,
		T.notes = S.notes,
		T.physicalDeliveryOfficeName = S.physicalDeliveryOfficeName,
		T.proxyAddresses = S.proxyAddresses,
		T.sAMAccountName = S.sAMAccountName,
		T.SourceOrganization = S.SourceOrganization,
		T.SurName = S.SurName,
		T.targetAddress = S.targetAddress,
		T.userPrincipalName = S.userPrincipalName,
		T.whenchanged = S.whenchanged,
		T.whenCreated = S.whencreated
WHEN NOT MATCHED THEN
	INSERT (
		ObjectGUID
		,ExpectedAzureADImmutableID
		,AccountExpirationDate
		,altRecipient
		,c
		,CanonicalName
		,city
		,company
		,cn
		,co
		,country
		,createTimeStamp
		,deliverandRedirect
		,department
		,displayName
		,DistinguishedName
		,employeeID
		,employeeNumber
		,[enabled]
		,extensionattribute1
		,extensionattribute10
		,extensionattribute11
		,extensionattribute12
		,extensionattribute13
		,extensionattribute14
		,extensionattribute15
		,extensionattribute2
		,extensionattribute3
		,extensionattribute4
		,extensionattribute5
		,extensionattribute6
		,extensionattribute7
		,extensionattribute8
		,extensionattribute9
		,forwardingAddress
		,GivenName
		,homeMDB
		,homeMTA
		,LastLogonDate
		,legacyExchangeDN
		,Mail
		,mailNickname
		,memberof
		,modifyTimeStamp
		,[mS-DS-ConsistencyGuid]
		,msExchArchiveGUID
		,msExchArchiveName
		,msexchextensioncustomattribute1
		,msexchextensioncustomattribute2
		,msexchextensioncustomattribute3
		,msexchextensioncustomattribute4
		,msexchextensioncustomattribute5
		,msExchGenericForwardingAddress
		,msExchHideFromAddressLists
		,msExchHomeServerName
		,msExchMailboxGUID
		,msExchMasterAccountSID
		,msExchPoliciesExcluded
		,msExchRecipientDisplayType
		,msExchRecipientTypeDetails
		,msExchRemoteRecipientType
		,msExchUsageLocation
		,msExchUserCulture
		,msExchVersion
		,msExchWhenMailboxCreated
		,notes
		,physicalDeliveryOfficeName
		,proxyAddresses
		,sAMAccountName
		,SourceOrganization
		,SurName
		,targetAddress
		,userPrincipalName
		,whenchanged
		,whencreated		
	)
	VALUES (
		S.ObjectGUID
		,S.ExpectedAzureADImmutableID
		,S.AccountExpirationDate
		,S.altRecipient
		,S.c
		,S.CanonicalName
		,S.city
		,S.company
		,S.cn
		,S.co
		,S.country
		,S.createTimeStamp
		,S.deliverandRedirect
		,S.department
		,S.displayName
		,S.DistinguishedName
		,S.employeeID
		,S.employeeNumber
		,S.[enabled]
		,S.extensionattribute1
		,S.extensionattribute10
		,S.extensionattribute11
		,S.extensionattribute12
		,S.extensionattribute13
		,S.extensionattribute14
		,S.extensionattribute15
		,S.extensionattribute2
		,S.extensionattribute3
		,S.extensionattribute4
		,S.extensionattribute5
		,S.extensionattribute6
		,S.extensionattribute7
		,S.extensionattribute8
		,S.extensionattribute9
		,S.forwardingAddress
		,S.GivenName
		,S.homeMDB
		,S.homeMTA
		,S.LastLogonDate
		,S.legacyExchangeDN
		,S.Mail
		,S.mailNickname
		,S.memberof
		,S.modifyTimeStamp
		,S.[mS-DS-ConsistencyGuid]
		,S.msExchArchiveGUID
		,S.msExchArchiveName
		,S.msexchextensioncustomattribute1
		,S.msexchextensioncustomattribute2
		,S.msexchextensioncustomattribute3
		,S.msexchextensioncustomattribute4
		,S.msexchextensioncustomattribute5
		,S.msExchGenericForwardingAddress
		,S.msExchHideFromAddressLists
		,S.msExchHomeServerName
		,S.msExchMailboxGUID
		,S.msExchMasterAccountSID
		,S.msExchPoliciesExcluded
		,S.msExchRecipientDisplayType
		,S.msExchRecipientTypeDetails
		,S.msExchRemoteRecipientType
		,S.msExchUsageLocation
		,S.msExchUserCulture
		,S.msExchVersion
		,S.msExchWhenMailboxCreated
		,S.notes
		,S.physicalDeliveryOfficeName
		,S.proxyAddresses
		,S.sAMAccountName
		,S.SourceOrganization
		,S.SurName
		,S.targetAddress
		,S.userPrincipalName
		,S.whenchanged
		,S.whencreated
	)
	OUTPUT deleted.*, $action, inserted.* ; 
	--INTO dbo.ADUsersMergeResults;
END;
--@@ROWCOUNT
